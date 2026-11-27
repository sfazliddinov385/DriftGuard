# Run from a dedicated clone on the same machine as the persistent Splunk lab.
param([string]$SourceField = 'CommandLine', [switch]$ForceCheck)
$ErrorActionPreference = 'Stop'
if ($SourceField -notin @('CommandLine','OriginalCommandText')) { throw 'Unsupported source field' }
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $origin = (& git remote get-url origin)
    if ($LASTEXITCODE -ne 0 -or $origin -notmatch '^https://github\.com/sfazliddinov385/DriftGuard(\.git)?/?$') {
        throw 'Use a dedicated clone of the DriftGuard repository.'
    }
    $branch = & git branch --show-current
    $dirty = & git status --porcelain --untracked-files=no
    if ($branch -ne 'main' -or $dirty) { throw 'The watcher needs a clean main checkout.' }
    & git fetch origin main
    if ($LASTEXITCODE -ne 0) { throw 'Fetching reviewed main failed.' }
    & git merge --ff-only origin/main
    if ($LASTEXITCODE -ne 0) { throw 'Cannot fast-forward the dedicated clone.' }
    $sha = (& git rev-parse HEAD)
    $remote = (& git rev-parse origin/main)
    if ($sha -ne $remote) { throw 'Local main has unpublished changes.' }
    $date = Get-Date -Format 'yyyy-MM-dd'
    $stateFile = Join-Path $root 'reports/watch-state.json'
    $state = if (Test-Path $stateFile) { Get-Content $stateFile -Raw | ConvertFrom-Json }
    $revision = (& git log -1 --format=%H -- config rules/windows/proc_creation_encoded_powershell.yml scripts/splunk_canary.py scripts/check_splunk_replay.py)
    $due = ((Get-Date).Hour -ge 2 -and $date -ne $state.date)
    if (!$ForceCheck -and !$due -and $state.revision -eq $revision -and $state.field -eq $SourceField) { return }
    $python = Join-Path $root '.venv/Scripts/python.exe'
    & $python scripts/splunk_canary.py --source-field $SourceField
    $rc = $LASTEXITCODE
    if ($rc -eq 1 -and (Test-Path 'reports/splunk-canary.json')) {
        & $python scripts/review_splunk_drift.py
        if ($LASTEXITCODE -ne 0) { throw 'Splunk miss requires human investigation. See reports/splunk-canary.json.' }
        if ($env:DRIFTGUARD_WEBHOOK_URL) { & $python scripts/notify_slack.py drift }
    } elseif ($rc -ne 0) {
        throw 'No completed verification. Check the Splunk connection, role and certificate.'
    } elseif ($state.result -eq 'drift' -and $env:DRIFTGUARD_WEBHOOK_URL) {
        & $python scripts/notify_slack.py recovered
    }
    $result = (Get-Content 'reports/splunk-canary.json' -Raw | ConvertFrom-Json).status
    @{date=$date; revision=$revision; result=$result; field=$SourceField} |
        ConvertTo-Json | Set-Content "$stateFile.tmp"
    Move-Item -Force "$stateFile.tmp" $stateFile
    if ($result -ne 'pass') { exit 1 }
} finally { Pop-Location }
