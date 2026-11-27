# Run DriftGuard overnight

## What runs on GitHub

At **08:17 UTC each day** (2:17 a.m. Central Standard Time, 3:17 a.m. Central Daylight Time), GitHub captures two harmless clock checks on Windows and starts a fresh Splunk Enterprise test instance. A merge that changes the managed mapping or PowerShell rule runs the check again. GitHub schedules are best effort.

The managed alert reads only the dedicated `driftguard_replay` test index and its clock-test source. Each check tags two events with a new batch ID, verifies both Windows record IDs arrived, and waits for a later completed scheduled job. The job must return the encoded event only, with a matching entry in Splunk’s fired-alert history. Losing a field, receiving no inputs, or failing to reach Splunk produce different evidence.

The hosted source intentionally sends its command line under `OriginalCommandText`. When the reviewed mapping only reads `CommandLine`, the check stays red. DriftGuard tries the fallback in a **separate saved search** and verifies that the scheduler fires on the expected event and leaves the ordinary clock check alone. Only then does it propose a mapping-only draft PR. An existing open review is reused. When available, Cloudflare supplies an explanation from the test counts. A person reviews the change. Merging the mapping runs the original managed alert again. An unexplained miss stays red for investigation.

In the [first automated repair run](https://github.com/sfazliddinov385/DriftGuard/actions/runs/45948322930), the original scheduled job missed Windows record `1566191`. The preview job fired on that exact record and left the ordinary clock check quiet. GitHub opened [draft repair #5](https://github.com/sfazliddinov385/DriftGuard/pull/5) with the measured result and Cloudflare’s explanation.

[Splunk workflow and run history](https://github.com/sfazliddinov385/DriftGuard/actions/workflows/splunk-integration.yml) · [Current mapping](../config/splunk-command-fields.json)

## Keep the alert on your Windows Splunk

Use a **dedicated lab** installation of Splunk Enterprise with scheduled alerts enabled. In Splunk create an events index named `driftguard_replay`. The token for the dedicated lab user must be able to search that index, create and schedule its own alerts in the Search app, read its fired alerts, and submit the two test events through the management API (`edit_tcp` is required for `receivers/simple`). Use the trusted CA for Splunk’s HTTPS certificate. Its name or IP must match the loopback address you use. The watcher connects locally; GitHub needs no route to your computer.

In PowerShell, use a dedicated checkout so the watcher can fast-forward reviewed changes. Install GitHub CLI and sign in with a repository account able to open a PR.

```powershell
git clone https://github.com/sfazliddinov385/DriftGuard.git "$env:USERPROFILE/DriftGuard-watch"
Set-Location "$env:USERPROFILE/DriftGuard-watch"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
gh auth login
.\scripts\install_splunk_watch.ps1 -SourceField OriginalCommandText -CAFile C:\path\to\splunk-ca.pem
```

Replace the CA path with your actual PEM file. Omit `-CAFile` if the Python HTTPS client already trusts the server. Type the Splunk token at the hidden prompt. The installer stores it protected with Windows DPAPI under your local user profile, outside the repo. On a PC, the input is the [public pair of recorded Windows clock events](../tests/baselines/clock-pair.json); the hosted nightly job collects a new pair. Choosing `OriginalCommandText` reproduces the changed source format. Choosing `CommandLine` checks the original format.

The Windows task checks for a newly merged rule or mapping every 15 minutes. It runs the full test after a change and once each night after 2 a.m. local time. Keep the machine awake, Splunk running and the task user signed in for the default interactive task. The saved alert remains in **Settings → Searches, reports, and alerts → DriftGuard_Managed_PowerShell_Canary**. Open `reports/splunk-canary.json` for the batch and scheduled-job evidence. If you also want direct Slack delivery from the PC, supply its own `DRIFTGUARD_WEBHOOK_URL` through the task user’s secret store. GitHub cannot export a repository secret to the PC.

## Slack and ATT&CK coverage

Create an incoming webhook for the channel you choose. Add its URL under repository **Settings → Secrets and variables → Actions → New repository secret**, named `DRIFTGUARD_WEBHOOK_URL`. Open the **Slack delivery test** workflow and choose **Run workflow**. Success requires Slack to acknowledge the request. Check the channel for “Test message from DriftGuard.” Hosted replay misses and Splunk review or deployment results link back to the GitHub run.

The dashboard publishes an ATT&CK Navigator layer after every replay. The colors describe the techniques exercised by the repository’s log samples. Several rules sharing one technique must all pass for it to be green. Untested techniques remain blank. [Open the heatmap](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fsfazliddinov385.github.io%2FDriftGuard%2Fattack-layer.json) · [Download the measured layer](https://sfazliddinov385.github.io/DriftGuard/attack-layer.json)

## Verify Cloudflare controls

The **Cloudflare gateway controls** workflow sends fixed, synthetic prompts using the existing GitHub Actions secrets. It checks an explicit per-request cache key for a miss followed by a hit. It submits a public test-card number and expects a request-side DLP block. It sends a bounded burst against the lab’s 10 requests per minute limit and verifies recovery after a minute. The uploaded `gateway-proof.json` includes status codes and cache outcomes. The workflow stays red if any control lacks proof.

In Cloudflare, open your gateway settings, select DLP and enable a blocking rule on incoming requests for the Financial Information profile with Visa matching enabled. Verify the gateway rate limit is 10 per 60 seconds. The cache test applies a short TTL only to its synthetic prompt. DriftGuard’s repair requests bypass caching so a later DLP policy change applies to new requests. After saving settings, rerun **Cloudflare gateway controls**. The probe token can run inference without permission to change account policy. [Gateway controls workflow](https://github.com/sfazliddinov385/DriftGuard/actions/workflows/gateway-proof.yml) · [Cloudflare DLP setup](https://developers.cloudflare.com/ai-gateway/features/dlp/set-up-dlp/)

Before the Visa detection entry was enabled, [the gateway accepted the test card](https://github.com/sfazliddinov385/DriftGuard/actions/runs/45948010834/job/140337070721). After setup, the gateway accepted a comparison number with an invalid checksum (HTTP 200) and explicitly reported blocking the request containing the synthetic Visa number (HTTP 424, code 2030). The test checks the block direction because the numeric code alone is ambiguous on this endpoint. In the same run the repeat request hit the cache, the burst reached the rate limit, and a later request succeeded. [View the passing gateway checks](https://github.com/sfazliddinov385/DriftGuard/actions/runs/45956452431/job/140363936198)
