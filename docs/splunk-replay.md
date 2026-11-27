# Check a DriftGuard rule inside Splunk

This test runs the current PowerShell rule through Splunk's search engine. You upload eight small JSON records to a dedicated index on your Splunk Enterprise instance. Four are sanitized copies of the recording used in GitHub. The other four have one change: their command line is stored under `OriginalCommandText`. Both sets have the same event record IDs and a unique label for this upload.

The expected result is a pass for the first set and a missing-field failure for the second. The rule in Git stays the same. The test uses recorded activity and runs no PowerShell commands from the logs.

## 1. Prepare the demo file

From the repository root in PowerShell, after installing the project requirements, run:

```powershell
$demo = .\.venv\Scripts\python.exe scripts/prepare_splunk_replay.py --output-dir $env:TEMP | ConvertFrom-Json
$demo.path
$demo.batch
```

Keep this PowerShell window open. The file contains the original image paths, record IDs and switch names. All command arguments have been replaced with `[removed]`. Each invocation writes a different file so earlier runs cannot supply a match.

## 2. Upload the file to a test index

1. In Splunk Web, create an event index named `driftguard_replay` under **Settings → Indexes → New Index**, or use the existing test index of that name.
2. Go to **Settings → Add Data → Upload** and select the file at `$demo.path`. Choose the `_json` source type. The preview should show **eight separate JSON events**.
3. Under **Input Settings**, choose `driftguard_replay` as the index. Submit the upload once. Repeated uploads of the same batch create duplicate events and the check reports them.

The client searches the indexed events by the batch and case labels in their raw text. The rule uses the fields extracted by Splunk. It does not read a lookup table or extract a missing field on the fly.

## 3. Run both checks from your PC

Use a Splunk user who can run searches and read the test index. Set the management URL and a search token in your PowerShell session. The token stays out of the command history. The usual management port is 8089.

```powershell
$env:SPLUNK_URL = 'https://localhost:8089'
$env:SPLUNK_TOKEN = [Net.NetworkCredential]::new('', (Read-Host 'Splunk search token' -AsSecureString)).Password

.\.venv\Scripts\python.exe scripts/check_splunk_replay.py --batch $demo.batch --scenario healthy
.\.venv\Scripts\python.exe scripts/check_splunk_replay.py --batch $demo.batch --scenario renamed
```

Use the hostname on your server's TLS certificate. If your server uses a private certificate authority, set `SPLUNK_CA_BUNDLE` to its trusted PEM certificate file. Splunk Enterprise must have token authentication enabled to accept a bearer token. If you already have a short-lived Splunk session key, set `SPLUNK_SESSION_KEY` instead of `SPLUNK_TOKEN`. The client accepts exactly one credential. [Splunk REST search documentation](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions)

| Scenario | What to look for |
| --- | --- |
| `healthy` | `status: pass`. Splunk sees four recent events with the required fields. It returns IDs `5585441` and `5613964` exactly once each. |
| `renamed` | `status: missing_required_fields`. Splunk sees the same four recent events, but zero have `CommandLine`. Both expected IDs appear under `missed_ids`. An exit code of 1 is expected here. |

The script first checks all four inputs and their index times. It then compiles the Sigma rule to Splunk's search language, executes it against the same batch, and compares the actual IDs with the labels in the repository. The default freshness limit is 60 minutes from indexing. To repeat the demo another day, prepare and upload a fresh batch.

## Understand a different result

| Result | What it means |
| --- | --- |
| `no_events_visible` | Splunk returned zero events for this batch and scenario. Check the index, upload, indexing delay, and index permissions. |
| `incomplete_or_duplicate_input` | Some source IDs are missing, unexpected or duplicated. Compare the batch and upload count before changing the rule. |
| `missing_required_fields` | The expected records arrived, but some lack an image or command line, or do not have process-creation event ID 1. Check the field counts. |
| `stale_input` | One or more records were indexed outside the allowed window. |
| `rule_mismatch` | The input records and fields were present and recent. The actual search missed or added one or more event IDs. |
| `unverified` | The client could not evaluate the search. Check the API connection, TLS, token and search permissions. |

The exit code is 0 for a match, 1 for a measured failure and 2 when the check could not complete. You can redirect the JSON output to a file for evidence. This demonstrates the search against an indexed test batch. Testing a scheduled alert firing and reaching the analyst would require checking the alert itself.
