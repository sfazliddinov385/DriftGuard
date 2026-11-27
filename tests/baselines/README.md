# Normal Windows activity

DriftGuard measures how often its rules flag a separate group of normal processes. A match stays in the report so an analyst can see which task would have raised an alert. These small, deliberately selected samples cannot give the alert rate for a company.

## Controlled Windows tasks

The Windows workflow starts eight read-only tasks on a fresh GitHub-hosted Windows Server 2022 runner. The tasks read the clock, list services and scheduled tasks, display the Windows version and time zone, and read the host and account names. One task uses the standard PowerShell encoded-command option to read the clock. An alert for this case is a real example of normal activity that matches the rule. [Read the collector](collect-windows.ps1) · [Open the Windows runs](https://github.com/sfazliddinov385/DriftGuard/actions/workflows/windows-baseline.yml)

The collector checks Windows Security event 4688 for each process it started. It verifies the child and parent process IDs, the executable path, and the full command line against the known task. The saved capture contains the task name, image path and command line. The command output, host and account names, process IDs and other Security log fields stay on the runner. If any expected record or its command line is missing, the collection fails. Windows calls the executable field `NewProcessName`; the collector names it `Image` for the rules. [Windows event 4688 documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

Each successful workflow run publishes the `windows-normal-processes` artifact with the capture and the measured result. Download and extract it, then check the capture against a local copy of the rules:

```sh
python scripts/check_benign_baseline.py --input windows-processes.json --json-out reports/benign-baseline.json
```

The report counts unique normal events flagged across all rules and lists the matched case IDs for each rule. A case can match more than one rule.
