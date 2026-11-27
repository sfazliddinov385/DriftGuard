"""Run a completed, read-only search through the Splunk management API."""

import json
import os
from urllib.parse import urlsplit

import requests


class SplunkSearchError(Exception):
    """The search did not provide usable evidence."""


def splunk_results(query: str, earliest: str = "0", latest: str = "now") -> list[dict]:
    base_url = os.environ.get("SPLUNK_URL", "https://localhost:8089").rstrip("/")
    url = urlsplit(base_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        raise SplunkSearchError("SPLUNK_URL must be an HTTPS origin, such as https://localhost:8089.")
    token = os.environ.get("SPLUNK_TOKEN", "").strip()
    session_key = os.environ.get("SPLUNK_SESSION_KEY", "").strip()
    if bool(token) == bool(session_key):
        raise SplunkSearchError("Set exactly one of SPLUNK_TOKEN or SPLUNK_SESSION_KEY for a user with search access.")
    authorization = f"Bearer {token}" if token else f"Splunk {session_key}"
    try:
        with requests.post(
            f"{base_url}/services/search/jobs",
            headers={"Authorization": authorization},
            data={
                "search": query,
                "earliest_time": earliest,
                "latest_time": latest,
                "exec_mode": "oneshot",
                "output_mode": "json",
            },
            verify=os.environ.get("SPLUNK_CA_BUNDLE") or True,
            timeout=(5, 90),
            allow_redirects=False,
        ) as response:
            if not 200 <= response.status_code < 300:
                raise SplunkSearchError(f"Splunk returned HTTP {response.status_code}. Check the URL, token and role.")
            body = response.text.strip()
    except (requests.RequestException, OSError) as exc:
        raise SplunkSearchError("Could not complete the Splunk request. Check connectivity and the trusted TLS certificate.") from exc

    try:
        # Splunk can return a results envelope or a stream of JSON result records.
        try:
            records = [json.loads(body)]
        except json.JSONDecodeError:
            records = [json.loads(line) for line in body.splitlines() if line.strip()]
        rows = []
        has_results = False
        for record in records:
            if not isinstance(record, dict) or record.get("preview") not in (False, None):
                raise ValueError("invalid or unfinished results")
            for message in record.get("messages", []):
                if message.get("type", "").upper() not in {"INFO", "DEBUG"}:
                    raise SplunkSearchError("Splunk reported a search warning or error. Inspect the search in Splunk.")
            if "results" in record:
                if not isinstance(record["results"], list):
                    raise ValueError("invalid results")
                has_results = True
                rows.extend(record["results"])
            if "result" in record:
                has_results = True
                rows.append(record["result"])
        if not has_results or not all(isinstance(row, dict) for row in rows):
            raise ValueError("missing results")
        return rows
    except (ValueError, TypeError, AttributeError) as exc:
        raise SplunkSearchError("Splunk returned an incomplete or unreadable search result.") from exc
