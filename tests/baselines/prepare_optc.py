"""Rebuild the reviewed OpTC snapshot from the pinned public Parquet download."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import duckdb

SOURCE_SHA256 = "8fe2b389acd1490d19a3d138640c23a481389f53b47e4fc3b4a82cfabdba2a6e"
SOURCE_TITLE = "DARPA OpTC, 17 September 2019, benign Windows process records"

# Resolve a bare image name only when that process's own module events agree on one path.
PROCESS_QUERY = """
WITH actions AS (
    SELECT *, lower(split_part(image_path, chr(92), -1)) AS executable
    FROM records
    WHERE is_malicious = 0 AND object = 'PROCESS' AND action = 'CREATE'
      AND command_line IS NOT NULL
), images AS (
    SELECT actorID, lower(split_part(module_path, chr(92), -1)) AS executable,
           min(module_path) AS full_path
    FROM records
    WHERE object = 'MODULE' AND action = 'LOAD' AND strpos(module_path, chr(92)) > 0
    GROUP BY actorID, executable
    HAVING count(DISTINCT lower(module_path)) = 1
)
SELECT a.executable,
       coalesce(CASE WHEN starts_with(a.image_path, chr(92)) THEN a.image_path END, i.full_path),
       a.command_line
FROM actions a LEFT JOIN images i ON a.objectID = i.actorID AND a.executable = i.executable
WHERE a.executable IN ('schtasks.exe', 'powershell.exe', 'gpupdate.exe', 'mpcmdrun.exe')
ORDER BY a.timestamp, a.id
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parquet", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with args.parquet.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != SOURCE_SHA256:
            raise SystemExit("Downloaded file differs from the reviewed source.")
    with duckdb.connect() as database:
        database.read_parquet(str(args.parquet)).create_view("records")
        rows = database.sql(PROCESS_QUERY).fetchall()

    events = []
    for executable, image, command in rows:
        if not image:
            continue
        command = re.sub(r"\bMantra_[A-Za-z0-9]+_[A-Za-z0-9]+_[A-Za-z0-9]+\b",
                         "Mantra_REDACTED_ACCOUNT", command)
        command = re.sub(r'(?i)(/ru ")([^"\\]+)[\\][^"]+(")', r'\1REDACTED_ACCOUNT\3', command)
        case = f"optc-{len(events) + 1:03d}-{executable.removesuffix('.exe')}"
        events.append({"case_id": case, "Image": image, "CommandLine": command})
    result = {"source": SOURCE_TITLE, "events": events}
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
