# Check the Windows logs arriving in Splunk

Use this on the computer that can reach your Splunk server. It answers two questions about one Sysmon feed. Did process-start events arrive recently, and do the events contain the `Image` and `CommandLine` fields that DriftGuard’s rules use?

Splunk returns one row of counts and timestamps. The check makes a read-only search, saves its result locally, and makes no Cloudflare or GitHub requests. If multiple computers share the same feed, add `--host` with an exact Splunk host name to check one separately. To check whether the PowerShell search finds the right event IDs, use the [recorded Splunk replay](splunk-replay.md).

## Run it once

1. Install the project requirements in the repository’s Python environment. Use a Splunk token whose role can search the intended index. Set `SPLUNK_URL` to the HTTPS management address, normally on port 8089. Use a hostname covered by the server certificate. For a private certificate authority, point `SPLUNK_CA_BUNDLE` at its PEM file.
2. In Splunk, look at a recent Sysmon process-start event and note its index, sourcetype, and source. If other Windows channels share this sourcetype, specify the exact Sysmon source with `--source`. That keeps unrelated Windows Event ID 1 records out of the count.
3. In PowerShell inside the repository, replace the example index, sourcetype, and source with the ones from your event.

```powershell
$env:SPLUNK_URL = 'https://localhost:8089'
$credential = [Net.NetworkCredential]::new('', (Read-Host 'Splunk read-only token' -AsSecureString))
$env:SPLUNK_TOKEN = $credential.Password
try {
    .\.venv\Scripts\python.exe scripts/check_splunk_health.py --index windows --sourcetype XmlWinEventLog --source 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' --json-out "$env:LOCALAPPDATA\DriftGuard\health.json"
} finally {
    Remove-Item Env:\SPLUNK_TOKEN -ErrorAction SilentlyContinue
    Remove-Variable credential
}
```

The default search looks back 60 minutes of event time. It requires a source event and a process event within the last 30 minutes, at least five process events in the full window, and the required fields on every process event. It recognizes event ID 1 using either `EventID` or `EventCode`. Blank or placeholder (`-`) values count as missing. Use `--window-minutes`, `--max-age-minutes` and `--min-process-events` to fit a feed’s normal hours and volume.

| Status | What it means | Exit code |
| --- | --- | --- |
| `healthy` | This time window met the configured checks. | 0 |
| `unhealthy` | No recent source events were visible, events were stale, or at least one required field was missing. Inspect the reason and counts. An empty window can also mean a quiet host, wrong source, or an account without visibility. | 1 |
| `insufficient_data` | The source was active but returned too few process events to establish field health. | 2 |
| `unknown` | The search failed or its response was incomplete. Check the token, server certificate, search permissions, and connection. | 2 |

## Run overnight on Windows

Use the same Windows account to save the token and run the task. In PowerShell, save the token outside the repository with Windows encryption for this account.

```powershell
$state = Join-Path $env:LOCALAPPDATA 'DriftGuard'
New-Item -ItemType Directory -Force $state | Out-Null
Read-Host 'Splunk read-only token' -AsSecureString | ConvertFrom-SecureString | Set-Content (Join-Path $state 'splunk-token.txt')
```

Save the following as `check-health.ps1` inside that directory. Adjust the index, sourcetype, source, project folder, and server address to match the successful manual check. If you used `SPLUNK_CA_BUNDLE`, set it in the script as well.

```powershell
$ErrorActionPreference = 'Stop'
$state = $PSScriptRoot
$project = Join-Path $env:USERPROFILE 'Downloads\DriftGuard'
$env:SPLUNK_URL = 'https://localhost:8089'
$encrypted = Get-Content -Raw (Join-Path $state 'splunk-token.txt')
$secret = ConvertTo-SecureString $encrypted.Trim()
$env:SPLUNK_TOKEN = [Net.NetworkCredential]::new('', $secret).Password
try {
    & "$project\.venv\Scripts\python.exe" "$project\scripts\check_splunk_health.py" --index windows --sourcetype XmlWinEventLog --source 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational' --json-out (Join-Path $state 'health.json')
    exit $LASTEXITCODE
} finally {
    Remove-Item Env:\SPLUNK_TOKEN -ErrorAction SilentlyContinue
}
```

In **Task Scheduler → Create Task**, choose this account and set the desired schedule, for example every 15 minutes. Use `powershell.exe` as the program. Under **Add arguments**, enter `-NoProfile -NonInteractive -File "C:\Users\YOUR_NAME\AppData\Local\DriftGuard\check-health.ps1"` with the actual path. Choose **Run whether user is logged on or not** if you want it to run while signed out. The computer and Splunk must be available at the scheduled time.

Right-click the task and choose **Run**. Confirm that the end time in `health.json` advances and check **Last Run Result**. The report replaces the previous result each time a search completes. An old end time means the task itself may have stopped. Keep the report and encrypted token on the local machine. [Windows credential encryption](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)
