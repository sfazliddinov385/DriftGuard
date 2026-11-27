"""Measure three controls on the named gateway with fixed, synthetic requests."""
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests


def evidence(response):
    try:
        body = response.json()
    except ValueError:
        body = {}
    errors = body.get("errors") or [body.get("error", {})]
    if isinstance(errors, dict):
        errors = [errors]
    codes = [str(e.get("code", "")) for e in errors if isinstance(e, dict)]
    messages = " ".join(str(e.get("message", "")) for e in errors if isinstance(e, dict)).lower()
    try:
        policy = json.loads(response.headers.get("cf-aig-dlp", "{}"))
    except ValueError:
        policy = {}
    return {
        "http": response.status_code, "codes": codes,
        "gateway_rate_message": ("gateway" in messages and "rate limit" in messages and
                                 "billing" not in messages and "provider" not in messages),
        "cache": response.headers.get("cf-aig-cache-status", "").upper(),
        "request_block": policy.get("action") == "BLOCK" and
        any(f.get("check") == "REQUEST" for f in policy.get("findings", [])),
    }


def verify():
    account, gateway, token = [os.environ[k].strip() for k in
                               ("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_GATEWAY_ID", "CLOUDFLARE_API_TOKEN")]
    if not re.fullmatch("[0-9a-fA-F]{32}", account) or not re.fullmatch(r"[\w-]+", gateway):
        raise ValueError("Invalid gateway configuration.")
    url = f"https://api.cloudflare.com/client/v4/accounts/{account}/ai/v1/chat/completions"
    run = uuid.uuid4().hex
    headers = {"Authorization": "Bearer " + token, "cf-aig-gateway-id": gateway}
    session = requests.Session()
    settings = session.get(f"https://api.cloudflare.com/client/v4/accounts/{account}/ai-gateway/gateways/{gateway}",
                           headers=headers, timeout=15, allow_redirects=False)
    info = settings.json().get("result") or {} if settings.ok else {}
    policy = {"settings_read_http": settings.status_code, "cache_ttl": info.get("cache_ttl"),
              "rate_limit": info.get("rate_limiting_limit"), "interval": info.get("rate_limiting_interval"),
              "dlp_enabled": (info.get("dlp") or {}).get("enabled")}
    def send(text, extra):
        response = session.post(url, headers=headers | extra, timeout=(5, 30), allow_redirects=False,
                                 json={"model": "@cf/meta/llama-3.3-70b-instruct-fp8-fast", "max_tokens": 4,
                                       "messages": [{"role": "user", "content": text}]})
        return evidence(response)

    cache_headers = {"cf-aig-cache-key": "driftguard-proof-" + run, "cf-aig-cache-ttl": "120"}
    no_cache = {"cf-aig-skip-cache": "true"}
    prompt = "DriftGuard synthetic check " + run + ". Reply OK."
    first = send(prompt, cache_headers)
    time.sleep(3)
    second = send(prompt, cache_headers)
    dlp = send("DriftGuard synthetic DLP test card: 4111 1111 1111 1111. Reply OK.", no_cache)
    burst = []
    recovery = None
    if first["http"] == 200:
        for i in range(11):
            reply = send(f"{prompt} Sample {i}.", no_cache)
            burst.append(reply)
            if reply["http"] != 200:
                break
        if burst[-1]["http"] == 429:
            time.sleep(65)
            recovery = send(prompt + " Recovery.", no_cache)
    rate = any(r["http"] == 429 and ("2003" in r["codes"] or r["gateway_rate_message"]) and "2018" not in r["codes"] for r in burst)
    session.close()
    return {
        "configuration": policy, "verified_utc": datetime.now(timezone.utc).isoformat(), "run_id": os.getenv("GITHUB_RUN_ID"),
        "cache": {"pass": first["http"] == second["http"] == 200 and
                  first["cache"] == "MISS" and second["cache"] == "HIT", "responses": [first, second]},
        "dlp": {"pass": dlp["http"] == 400 and ("2029" in dlp["codes"] or dlp["request_block"]), "response": dlp},
        "rate_limit": {"pass": bool(rate and recovery and recovery["http"] == 200),
                       "burst": burst, "recovery": recovery},
    }


if __name__ == "__main__":
    report = verify()
    path = Path("reports/gateway-proof.json")
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    if dest := os.getenv("GITHUB_STEP_SUMMARY"):
        with open(dest, "a") as summary:
            for name in ("cache", "dlp", "rate_limit"):
                print(f"- {name}: {'verified' if report[name]['pass'] else 'unverified'}", file=summary)
    raise SystemExit(0 if all(report[n]["pass"] for n in ("cache", "dlp", "rate_limit")) else 1)
