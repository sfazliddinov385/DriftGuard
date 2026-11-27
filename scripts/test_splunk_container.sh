#!/usr/bin/env bash
# Run only on a disposable runner after accepting the Splunk General Terms.
set -euo pipefail

work=$(mktemp -d)
container="driftguard-test-$RANDOM-$$"
cleanup() {
  docker rm -fv "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

image='splunk/splunk:10.2.10@sha256:5220fc37a7cbf2f801d7eeebd7fbff858f5281dc48386990e07fe9b19c562ac0'
export SPLUNK_URL=https://127.0.0.1:18089
export SPLUNK_CA_BUNDLE="$work/ca.pem"
SPLUNK_PASSWORD="Dg1-$(openssl rand -hex 24)"
reader_password="Dg1-$(openssl rand -hex 24)"
export SPLUNK_PASSWORD
echo "::add-mask::$SPLUNK_PASSWORD"
echo "::add-mask::$reader_password"

# Give only this instance a private key. The HTTPS client trusts only its one-day CA.
mkdir -p "$work/server" "$work/defaults" "$work/fixtures" "$work/app/default" "$work/app/metadata"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=DriftGuard CI CA' \
  -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$work/server.key" -out "$work/server.csr" 2>/dev/null
printf '%s\n' 'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:driftguard-ci' \
  'extendedKeyUsage=serverAuth,clientAuth' 'basicConstraints=CA:FALSE' > "$work/extensions"
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 1 -extfile "$work/extensions" -out "$work/tls.crt" 2>/dev/null
cat "$work/tls.crt" "$work/server.key" "$work/ca.pem" > "$work/server/server.pem"
cp "$work/ca.pem" "$work/server/ca.pem"
cat > "$work/defaults/default.yml" <<'CONFIG'
splunk:
  ssl:
    enable: true
    cert: /tmp/driftguard-tls/server.pem
    ca: /tmp/driftguard-tls/ca.pem
CONFIG

cat > "$work/app/default/app.conf" <<'CONFIG'
[install]
state = enabled
[ui]
is_visible = false
[launcher]
version = 1.0.0
CONFIG
cat > "$work/app/metadata/default.meta" <<'CONFIG'
[]
export = system
CONFIG
cat > "$work/app/default/indexes.conf" <<'CONFIG'
[driftguard_replay]
homePath = $SPLUNK_DB/driftguard_replay/db
coldPath = $SPLUNK_DB/driftguard_replay/colddb
thawedPath = $SPLUNK_DB/driftguard_replay/thaweddb
CONFIG
cat > "$work/app/default/authorize.conf" <<'CONFIG'
[role_driftguard_reader]
search = enabled
srchIndexesAllowed = driftguard_replay
srchIndexesDefault = driftguard_replay
srchJobsQuota = 3
CONFIG
cat > "$work/app/default/props.conf" <<'CONFIG'
[driftguard:json]
SHOULD_LINEMERGE = false
DATETIME_CONFIG = CURRENT
KV_MODE = json
CONFIG
for scenario in healthy renamed; do
  cat >> "$work/app/default/inputs.conf" <<CONFIG
[monitor:///tmp/driftguard-fixtures/$scenario.json]
disabled = false
index = driftguard_replay
sourcetype = driftguard:json
source = driftguard_$scenario
crcSalt = <SOURCE>
CONFIG
done

batch_info=$(python scripts/prepare_splunk_replay.py --output-dir "$work")
batch=$(jq -er .batch <<<"$batch_info")
fixture=$(jq -er .path <<<"$batch_info")
for scenario in healthy renamed; do
  jq -c --arg marker "driftguard$scenario" 'select(.driftguard_case == $marker)' "$fixture" > "$work/fixtures/$scenario.json"
done

docker pull "$image"
docker create --name "$container" --hostname driftguard-ci --publish 127.0.0.1:18089:8089 \
  -e SPLUNK_START_ARGS=--accept-license -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD -e SPLUNK_DEFAULTS_URL=/tmp/defaults/default.yml \
  -v "$work/defaults:/tmp/defaults:ro" -v "$work/server:/tmp/driftguard-tls:ro" \
  -v "$work/fixtures:/tmp/driftguard-fixtures:ro" "$image" >/dev/null
docker cp "$work/app" "$container:/opt/splunk/etc/apps/driftguard_ci"
docker start "$container" >/dev/null

api=(curl --silent --show-error --fail --max-time 15 --cacert "$SPLUNK_CA_BUNDLE")
ready=false
for ((attempt=0; attempt<100; attempt++)); do
  if "${api[@]}" --user "admin:$SPLUNK_PASSWORD" "$SPLUNK_URL/services/server/info" >/dev/null 2>&1; then
    ready=true
    break
  fi
  if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then break; fi
  sleep 4
done
if [[ $ready != true ]]; then
  echo "Splunk's management API was not ready over verified HTTPS." >&2
  docker inspect --format 'Container state: {{.State.Status}} ({{.State.ExitCode}})' "$container" >&2
  exit 1
fi

# Use admin only for creating the short-lived reader. Both checks run as that reader.
"${api[@]}" --user "admin:$SPLUNK_PASSWORD" "$SPLUNK_URL/services/authentication/users" \
  --data-urlencode name=dg_reader --data-urlencode "password=$reader_password" \
  --data-urlencode roles=driftguard_reader >/dev/null
session_xml=$("${api[@]}" "$SPLUNK_URL/services/auth/login" \
  --data-urlencode username=dg_reader --data-urlencode "password=$reader_password")
SPLUNK_SESSION_KEY=$(python -c 'import sys,xml.etree.ElementTree as ET; print(ET.fromstring(sys.stdin.read()).findtext("sessionKey") or "")' <<<"$session_xml")
test -n "$SPLUNK_SESSION_KEY"
echo "::add-mask::$SPLUNK_SESSION_KEY"
export SPLUNK_SESSION_KEY
unset session_xml SPLUNK_PASSWORD reader_password

out=reports/splunk-integration
mkdir -p "$out"
for scenario in healthy renamed; do
  # Indexing and search availability can lag server startup. Only retry empty, partial or unavailable searches.
  for ((attempt=0; attempt<20; attempt++)); do
    rc=0
    python scripts/check_splunk_replay.py --batch "$batch" --scenario "$scenario" > "$out/replay-$scenario.json" || rc=$?
    state=$(jq -er .status "$out/replay-$scenario.json")
    case "$state" in
      no_events_visible|incomplete_or_duplicate_input|unverified) sleep 4 ;;
      *) break ;;
    esac
  done
  cat "$out/replay-$scenario.json"
  # These are fixed, reviewed expectations for the four public events.
  if [[ $scenario == healthy ]]; then
    test "$rc" -eq 0
    jq -e '.status == "pass" and .source_events == 4 and .returned_record_ids == ["5585441","5613964"] and .field_counts.CommandLine == 4' "$out/replay-$scenario.json" >/dev/null
  else
    test "$rc" -eq 1
    jq -e '.status == "missing_required_fields" and .source_events == 4 and .field_counts.CommandLine == 0 and .missed_ids == ["5585441","5613964"] and .returned_record_ids == []' "$out/replay-$scenario.json" >/dev/null
  fi

  rc=0
  python scripts/check_splunk_health.py --index driftguard_replay --sourcetype driftguard:json \
    --source "driftguard_$scenario" --min-process-events 1 --json-out "$out/source-$scenario.json" || rc=$?
  if [[ $scenario == healthy ]]; then
    test "$rc" -eq 0
    jq -e '.status == "healthy" and .process_events == 4 and .processes_with_command_line == 4' "$out/source-$scenario.json" >/dev/null
  else
    test "$rc" -eq 1
    jq -e '.status == "unhealthy" and .process_events == 4 and .processes_with_command_line == 0 and .reasons == ["missing_command_line"]' "$out/source-$scenario.json" >/dev/null
  fi
done

if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
  {
    echo '### Isolated Splunk replay'
    echo
    echo '| Recording | Process events | Command lines present | Matching event IDs |'
    echo '| --- | ---: | ---: | --- |'
    for scenario in healthy renamed; do
      jq -r '"| \(.scenario) | \(.source_events) | \(.field_counts.CommandLine) | \(.returned_record_ids | if length > 0 then join(", ") else "None" end) |"' "$out/replay-$scenario.json"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi
