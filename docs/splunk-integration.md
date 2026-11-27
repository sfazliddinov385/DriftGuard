# Run the Windows-to-Splunk alert demo

One GitHub runner captures two real Windows Security events. Another starts a temporary Splunk Enterprise instance. Both PowerShell commands read the clock. Only one uses an encoded command. DriftGuard checks that Splunk indexed both Windows record IDs and compares completed scheduled searches with Splunk’s list of fired alerts. The test also replays a public Sysmon recording in the same instance.

## Run it

1. Open [Splunk integration test](https://github.com/sfazliddinov385/DriftGuard/actions/workflows/splunk-integration.yml) under Actions.
2. Choose **Run workflow** on `main`. Review the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html) and select the acceptance checkbox if you agree.
3. Open the finished job summary. Look for **Scheduled PowerShell alert on fresh Windows events**. Each row identifies a completed search and whether it triggered. The `windows-clock` artifact contains the two Windows records. The `splunk-replay-results` artifact contains the search results and field checks.

Maintainers of the original DriftGuard repository can also opt in by including `[splunk-test]` in the head commit message when pushing a change to the integration workflow, runner scripts, or PowerShell rule on `main`. The image version and digest are pinned in the [test script](../scripts/test_splunk_container.sh).

## What to show an analyst

Open the [published demo](https://sfazliddinov385.github.io/DriftGuard/#scheduled-alert-demo) or the [completed workflow](https://github.com/sfazliddinov385/DriftGuard/actions/runs/45944956740). Follow the encoded clock check’s Windows record ID across the three searches. In each one the same two events are present and the same PowerShell rule runs.

1. **Original fields.** Splunk records a fired alert. Its result contains the encoded clock check’s ID.
2. **Renamed field.** The command line arrives as `OriginalCommandText`. DriftGuard confirms the search ran, both events were indexed, zero had the expected `CommandLine` field, and no alert fired.
3. **Repaired field mapping.** Splunk reads that same renamed data with a field alias. The scheduled alert fires again on the original encoded event ID. The rule stays the same throughout the test.

The [saved result](../dashboard/windows-alert-demo.json) includes both Windows record IDs, the GitHub run, and the Splunk scheduled job ID for each case. The demo configures the field alias explicitly. The separate rule-repair workflow in the README shows a proposed rule edit reviewed by a person.

## What the public recording checks

In the verified run, both sets arrived in the same index with the same four original record IDs. [Open the completed test](https://github.com/sfazliddinov385/DriftGuard/actions/runs/45941550323/job/140316779935#step:5:1) · [Read the four results](evidence/splunk-replay.json)

| Recording in the test index | Observed Splunk matches | Observed source health |
| --- | --- | --- |
| Original fields | Two rows, with record IDs `5585441` and `5613964`. | All four process records contain a command line. |
| Renamed command-line field | Zero matches and both expected IDs reported missing. | All four process records are visible and zero have the expected command-line field. |

The job must observe **both** outcomes to pass. A connection failure or an empty index fails the job. The replay and field checks use a dedicated search-only account. The scheduled-alert demo uses a temporary admin account inside this instance to register the three searches and read their alert history. Both clients verify the instance’s test certificate. The only published evidence comes from this test index. To check your own Windows logs, use the [local source health check](splunk-health.md).
