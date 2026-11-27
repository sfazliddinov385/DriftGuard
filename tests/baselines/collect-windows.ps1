# Run only on the disposable hosted Windows runner in windows-baseline.yml.
param([Parameter(Mandatory)][string] $OutputPath, [switch] $ClockDemo)
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This collector changes audit settings on a disposable GitHub-hosted Windows runner.'
}

# Ask Windows to record process creation (4688), including command-line arguments.
& auditpol.exe /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to enable process creation auditing.' }
$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null

$system32 = Join-Path $env:SystemRoot System32
$powershell = Join-Path $system32 'WindowsPowerShell\v1.0\powershell.exe'
$encodedClock = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Date -Format o'))
$tasks = @(
    @{ Name='read-clock'; Program=$powershell; Arguments='-NoProfile -NonInteractive -Command "Get-Date -Format o"' }
    @{ Name='read-clock-encoded'; Program=$powershell; Arguments="-NoProfile -NonInteractive -EncodedCommand $encodedClock" }
    @{ Name='list-running-services'; Program=$powershell; Arguments='-NoProfile -NonInteractive -Command "Get-Service | Select-Object -First 3"' }
    @{ Name='read-windows-version'; Program=(Join-Path $system32 'cmd.exe'); Arguments='/d /c ver' }
    @{ Name='list-scheduled-tasks'; Program=(Join-Path $system32 'schtasks.exe'); Arguments='/query /fo LIST' }
    @{ Name='read-time-zone'; Program=(Join-Path $system32 'tzutil.exe'); Arguments='/g' }
    @{ Name='read-host-name'; Program=(Join-Path $system32 'hostname.exe'); Arguments='' }
    @{ Name='read-current-identity'; Program=(Join-Path $system32 'whoami.exe'); Arguments='' }
)
$start = Get-Date
if ($ClockDemo) {
    $tasks = @($tasks | Where-Object { $_.Name -in 'read-clock','read-clock-encoded' })
}
$startRecord = (Get-WinEvent -LogName Security -MaxEvents 1).RecordId
$launched = @{}
foreach ($task in $tasks) {
    $info = [Diagnostics.ProcessStartInfo]::new($task.Program, $task.Arguments)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $child = [Diagnostics.Process]::Start($info)
    try {
        # Do not log the command output or retain user or machine identifiers.
        $null = $child.StandardOutput.ReadToEnd()
        $child.WaitForExit()
        if ($child.ExitCode -ne 0) { throw "Normal task failed: $($task.Name)" }
        $launched[[string]$child.Id] = $task
    } finally { $child.Dispose() }
}
$observed = @{}
$deadline = (Get-Date).AddSeconds(30)
do {
    $records = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$start.AddSeconds(-1) } -ErrorAction SilentlyContinue
    foreach ($record in $records) {
        if ($record.RecordId -le $startRecord) { continue }
        $fields = @{}
        ([xml]$record.ToXml()).Event.EventData.Data | ForEach-Object { $fields[$_.Name] = $_.'#text' }
        if ([string]::IsNullOrEmpty($fields.NewProcessId) -or [string]::IsNullOrEmpty($fields.ProcessId)) { continue }
        $newPid = [Convert]::ToInt64(($fields.NewProcessId -replace '^0x',''),16)
        $creatorPid = [Convert]::ToInt64(($fields.ProcessId -replace '^0x',''),16)
        $task = $launched[[string]$newPid]
        if ($null -eq $task -or $creatorPid -ne $PID -or $fields.NewProcessName -ine $task.Program) { continue }
        if ([string]::IsNullOrWhiteSpace($fields.CommandLine)) { continue }
        # Export only records whose entire command line equals one of our known commands.
        $expected = ('"' + $task.Program + '" ' + $task.Arguments).Trim()
        $unquoted = ($task.Program + ' ' + $task.Arguments).Trim()
        $line = $fields.CommandLine.Trim()
        if ($line -ine $expected -and $line -ine $unquoted) { continue }
        $observed[$task.Name] = [ordered]@{ case_id=$task.Name; Image=$fields.NewProcessName; CommandLine=$line }
        if ($ClockDemo) {
            $observed[$task.Name]['EventID'] = 4688
            $observed[$task.Name]['EventRecordID'] = [string]$record.RecordId
            $observed[$task.Name]['ObservedAt'] = $record.TimeCreated.ToUniversalTime().ToString('o')
        }
    }
    if ($observed.Count -eq $tasks.Count) { break }
    Start-Sleep -Seconds 1
} while ((Get-Date) -lt $deadline)
if ($observed.Count -ne $tasks.Count) {
    $missing = ($tasks | Where-Object { -not $observed.ContainsKey($_.Name) }).Name
    throw "Incomplete Security 4688 capture. Missing cases: $($missing -join ', ')."
}
$capture = [ordered]@{
    source='GitHub-hosted Windows Server 2022, Windows Security 4688, controlled read-only administration tasks'
    events=@($tasks | ForEach-Object { $observed[$_.Name] })
}
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force
$capture | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding utf8NoBOM
Write-Host "Captured $($observed.Count) task records from the Windows Security event log."
