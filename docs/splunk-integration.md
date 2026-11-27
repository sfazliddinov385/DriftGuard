# Test both recordings in an isolated Splunk instance

This GitHub Actions job starts the official Splunk Enterprise container on a temporary Linux runner. It uses eight sanitized records prepared from the public PowerShell recording. Four have a command-line field. The other four contain the same information under a different field name. The job reads both through Splunk's search API and removes the instance when it finishes.

## Run it

1. Open [Splunk integration test](https://github.com/sfazliddinov385/DriftGuard/actions/workflows/splunk-integration.yml) under Actions.
2. Choose **Run workflow** on `main`. Review the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html) and select the acceptance checkbox if you agree.
3. Open the finished job summary. The downloadable `splunk-replay-results` artifact contains counts, field checks, and the returned public record IDs.

Maintainers of the original DriftGuard repository can also opt in by including `[splunk-test]` in the head commit message when pushing a change to the integration workflow, runner scripts, or PowerShell rule on `main`. The image version and digest are pinned in the [test script](../scripts/test_splunk_container.sh).

## What counts as a pass

| Recording in the test index | Expected Splunk matches | Expected source health |
| --- | --- | --- |
| Original fields | Two rows, with record IDs `5585441` and `5613964`. | All four process records contain a command line. |
| Renamed command-line field | Zero matches and both expected IDs reported missing. | All four process records are visible and zero have the expected command-line field. |

The job must observe **both** outcomes to pass. A connection failure or an empty index fails the job. It uses a dedicated search-only account and checks the server certificate against an authority generated for that run. The only published evidence comes from this test index. To check your own Windows logs, use the [local source health check](splunk-health.md).
