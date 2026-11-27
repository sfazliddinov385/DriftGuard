# One-time setup under the Windows user who runs the dedicated lab.
param([ValidateSet('CommandLine','OriginalCommandText')][string]$SourceField = 'CommandLine',
      [string]$CAFile, [string]$SplunkUrl = 'https://localhost:8089')
$ErrorActionPreference = 'Stop'
$watcher = Join-Path $PSScriptRoot 'watch_splunk.ps1'
$root = Split-Path -Parent $PSScriptRoot
if (!(Test-Path (Join-Path $root '.venv/Scripts/python.exe'))) { throw 'Install the repository requirements in .venv first.' }
& gh auth status --hostname github.com
if ($LASTEXITCODE -ne 0) { throw 'Sign in to GitHub CLI with permission to open repair PRs.' }
$profileDir = Join-Path $env:LOCALAPPDATA 'DriftGuard'
New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
if ($CAFile) { $CAFile = (Resolve-Path $CAFile).Path }
$secret = Read-Host 'Dedicated Splunk token (input hidden)' -AsSecureString
if (!$secret.Length) { throw 'A token is required.' }
# This DPAPI value can only be decoded by this user on this Windows computer.
@{url=$SplunkUrl; ca=$CAFile; token=(ConvertFrom-SecureString $secret)} | ConvertTo-Json |
    Set-Content (Join-Path $profileDir 'canary-profile.json')
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -NonInteractive -File "' + $watcher + '" -SourceField ' + $SourceField)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName 'DriftGuard Splunk lab' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Write-Host 'Watcher installed. The first check begins in one minute. Results are in reports/splunk-canary.json.'
