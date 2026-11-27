"""Post a run link and a fixed status to the configured Slack incoming webhook."""
import argparse
import os
from urllib.parse import urlsplit

import requests

MESSAGES = {"drift": "A Splunk or replay check missed expected activity. Review the run for the cause and any draft repair.",
            "recovered": "The reviewed alert passed its scheduled Splunk check.",
            "error": "A validation job could not finish. Check the run before trusting coverage.",
            "test": "Test message from DriftGuard. Delivery to this channel is working."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("status", choices=MESSAGES)
    args = parser.parse_args()
    hook = os.getenv("DRIFTGUARD_WEBHOOK_URL", "").strip()
    if not hook:
        print("Slack delivery unavailable: configure DRIFTGUARD_WEBHOOK_URL.")
        return 2
    url = urlsplit(hook)
    if url.scheme != "https" or url.netloc not in {"hooks.slack.com", "hooks.slack-gov.com"} or not url.path.startswith("/services/"):
        print("The configured secret is not a Slack incoming webhook.")
        return 2
    run = os.getenv("GITHUB_RUN_ID", "")
    repo = os.getenv("GITHUB_REPOSITORY", "sfazliddinov385/DriftGuard")
    link = f"https://github.com/{repo}/actions/runs/{run}" if run.isdecimal() else f"https://github.com/{repo}/pulls"
    try:
        r = requests.post(hook, json={"text": f"DriftGuard · {MESSAGES[args.status]} {link}"},
                          timeout=10, allow_redirects=False)
        ok = r.status_code == 200 and r.text.strip() == "ok"
    except requests.RequestException:
        ok = False
    print("Slack accepted the message." if ok else "Slack delivery was not confirmed.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
