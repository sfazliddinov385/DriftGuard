# Normal Windows activity

DriftGuard measures how often its rules flag a separate group of normal processes. A match stays in the report so an analyst can see which task would have raised an alert. These small, deliberately selected samples cannot give the alert rate for a company.

## Independent Windows recording used in every check

The checked-in file contains **91 normal process starts** from one Windows research host in the DARPA OpTC data release. The recording is from 17 September 2019, during the project's benign collection period. The source is independent of the attack recordings and the rule authors. DARPA released the original records into the public domain. This copy uses a pinned Parquet conversion published by equalNull. [Original data release](https://github.com/FiveDirections/OpTC-data) · [Original benign collection](https://drive.google.com/drive/folders/1DIO8V9zN27nqwQi403YL_b3tLvutVy-p) · [Pinned input file](https://huggingface.co/datasets/equalNull/labelled-optc-sep17/resolve/b28ed9d9440870cff1fdf9011f9328f1192a56cf/data/AIA-101-125.ecar-2019-09-17-sysclient0118.parquet) · [Sanitized capture](windows-processes.json)

Of the 1,646 process starts labeled normal with a recorded command line, 101 used one of four selected administration programs. We kept all 91 with a verifiable executable path. For a bare filename, we used that process's own module-load records when they pointed to a single matching path. The file contains 58 scheduled-task operations, 24 Defender operations, seven Group Policy operations and two PowerShell service checks. Some commands repeat. There are 26 distinct image-and-command pairs. This sample contains no Mshta launches or encoded PowerShell commands. The separate Windows exercise below covers one normal encoded command.

We retained the original command lines and executable paths, replaced a lab account in task names and arguments, and assigned short case IDs. The extraction discards the other source fields. To reproduce it, download the pinned file above as `optc.parquet`. Only this one-time preparation needs DuckDB. The script checks the input's SHA-256 before reading any rows. [Read the extraction code](prepare_optc.py)

```sh
python -m pip install duckdb==2.0.1
python tests/baselines/prepare_optc.py optc.parquet regenerated.json
```

The checked-in output's SHA-256 is `0621d03d482a55a70f4a85882662852440a29917a72db638055fca3bfb484f37`.

## Controlled Windows tasks

The Windows workflow starts eight read-only tasks on a fresh GitHub-hosted Windows Server 2022 runner. The tasks read the clock, list services and scheduled tasks, display the Windows version and time zone, and read the host and account names. One task uses the standard PowerShell encoded-command option to read the clock. An alert for this case is a real example of normal activity that matches the rule. [Read the collector](collect-windows.ps1) · [Open the Windows runs](https://github.com/sfazliddinov385/DriftGuard/actions/workflows/windows-baseline.yml)

The collector checks Windows Security event 4688 for each process it started. It verifies the child and parent process IDs, the executable path, and the full command line against the known task. The saved capture contains the task name, image path and command line. The command output, host and account names, process IDs and other Security log fields stay on the runner. If any expected record or its command line is missing, the collection fails. Windows calls the executable field `NewProcessName`; the collector names it `Image` for the rules. [Windows event 4688 documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

Each successful workflow run publishes the `windows-normal-processes` artifact with the capture and the measured result. Download and extract it, then check the capture against a local copy of the rules:

```sh
python scripts/check_benign_baseline.py --input windows-processes.json --json-out reports/benign-baseline.json
```

The report counts unique normal events flagged across all rules and lists the matched case IDs for each rule. A case can match more than one rule.
