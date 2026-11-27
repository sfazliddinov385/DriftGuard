"use strict";

const REPO = "https://github.com/sfazliddinov385/DriftGuard";
const $ = (id) => document.getElementById(id);
const LABELS = {
  pass: ["Passed", "good"], success: ["Passed", "good"], fail: ["Failed", "bad"],
  failure: ["Failed", "bad"], error: ["Error", "bad"], cancelled: ["Cancelled", "neutral"],
  skipped: ["Skipped", "neutral"], unknown: ["Unknown", "neutral"]
};
const STAGES = [
  ["sigma", "Sigma validation"], ["splunk", "Splunk SPL compilation"],
  ["pytest", "Automated tests"], ["replay", "Detection replay"],
  ["healer", "Cloudflare AI healer"], ["draft_pr", "Open repair proposal"],
  ["baseline", "Measure alerts on normal activity"]
];

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function link(text, href, className) {
  const a = element("a", text, className);
  a.href = href;
  return a;
}
function statusLabel(status) {
  return LABELS[status] || LABELS.unknown;
}
function tag(status) {
  const [label, style] = statusLabel(status);
  return element("span", label, "tag " + style);
}
function validCount(n) {
  return Number.isSafeInteger(n) && n >= 0;
}
function fraction(hits, total) {
  return validCount(hits) && validCount(total) ? hits + " / " + total : "—";
}
function aggregate(rules, category) {
  if (!rules.length) return "—";
  let hits = 0, total = 0;
  for (const rule of rules) {
    const count = rule[category];
    if (!count) return "—";
    if (category === "recorded") {
      if (!validCount(count.expected) || !Array.isArray(count.missed_ids) ||
          !validCount(count.hits) || count.missed_ids.length > count.expected) return "—";
      hits += count.expected - count.missed_ids.length;
      total += count.expected;
    } else {
      if (!validCount(count.hits) || !validCount(count.total)) return "—";
      hits += count.hits;
      total += count.total;
    }
  }
  return fraction(hits, total);
}
function chartRow(rule) {
  const row = element("div", null, "chart-row" + (rule.status === "fail" ? " alert" : ""));
  const {hits, total} = rule.recorded || {};
  const track = element("span", null, "chart-track");
  track.setAttribute("aria-hidden", "true");
  if (validCount(hits) && validCount(total) && total > 0) {
    const fill = element("span", null, "chart-fill");
    fill.style.width = Math.min(100, 100 * hits / total) + "%";
    track.append(fill);
  }
  row.append(element("span", rule.technique || rule.title || rule.id, "chart-label"),
    track, element("span", fraction(hits, total), "chart-count"));
  return row;
}
function sourceLink(label, path, ref) {
  if (typeof path !== "string" || !path || path.startsWith("/") || path.includes("..")) return null;
  return link(label, REPO + "/blob/" + ref + "/" + path.split("/").map(encodeURIComponent).join("/"));
}
function ruleDetail(rule, ref) {
  const detail = element("details", null, "rule");
  const heading = element("summary", null, "rule-head");
  const name = element("span", null, "rule-name");
  name.append(element("strong", rule.title || rule.id), element("span", rule.technique || "Technique unavailable", "mono"));
  const recorded = rule.recorded || {}, withheld = rule.withheld || {}, benign = rule.benign || {};
  const end = element("span", null, "rule-end");
  end.append(tag(rule.status), element("span", null, "caret"));
  heading.append(name, element("span", fraction(recorded.hits, recorded.total), "metric"), end);
  const body = element("div", null, "rule-body");
  if (rule.status !== "pass" && rule.summary) body.append(element("p", rule.summary));
  body.append(element("p", "Withheld positives: " + fraction(withheld.hits, withheld.total) +
    " · Benign alerts: " + fraction(benign.hits, benign.total)));
  for (const [key, label] of [["matched_ids","Matched record IDs"],["missed_ids","Missed record IDs"],["unexpected_ids","Unexpected record IDs"]]) {
    const ids = recorded[key];
    if (Array.isArray(ids) && (ids.length || key === "matched_ids")) {
      const line = element("p", label + ": ");
      line.append(element("span", ids.length ? ids.join(", ") : "None", "mono"));
      body.append(line);
    }
  }
  const links = element("p", null, "detail-links");
  for (const a of [sourceLink("Sigma rule ↗", rule.rule_path, ref), sourceLink("Log fixture ↗", rule.fixture_path, ref)]) {
    if (a) links.append(a);
  }
  body.append(links);
  detail.append(heading, body);
  return detail;
}
function renderReport(data) {
  if (data.schema_version !== 1 || !data.checks ||
      (data.replay != null && !Array.isArray(data.replay.rules))) throw Error("Unsupported report");
  const replay = data.replay, rules = replay?.rules || [];
  const hasRules = rules.length > 0;
  const checkedCommit = /^[a-f0-9]{40}$/i.test(data.commit) ? data.commit : null;
  const date = new Date(data.generated_at || NaN);
  if (Number.isFinite(date.getTime())) {
    $("updated").dateTime = date.toISOString();
    $("updated").textContent = new Intl.DateTimeFormat("en-US", {
      month:"short", day:"numeric", year:"numeric", hour:"numeric", minute:"2-digit",
      timeZone:"UTC", timeZoneName:"short"
    }).format(date);
  }
  const passed = rules.filter((r) => r.status === "pass").length;
  $("score").textContent = hasRules ? passed : "—";
  if (hasRules) $("score").append(element("span", "/ " + rules.length, "den"));
  $("score-caption").textContent = hasRules ? "rules passed replay" : "No replay measurements for this run";
  const totals = rules.map((r) => r.recorded?.total);
  if (hasRules && totals.every(validCount)) $("event-total").textContent = totals.reduce((a,b) => a+b, 0) + " events";
  $("chart").replaceChildren(...rules.map(chartRow));
  $("expected").textContent = aggregate(rules, "recorded");
  $("withheld").textContent = aggregate(rules, "withheld");
  $("benign").textContent = aggregate(rules, "benign");
  const baseline = data.benign_baseline;
  if (baseline && validCount(baseline.any_rule_matches) && validCount(baseline.event_count)) {
    $("baseline-count").textContent = baseline.any_rule_matches + " of " + baseline.event_count +
      " normal processes in this sample matched at least one rule.";
    const titles = new Map(rules.map((r) => [r.id, r.title || r.id]));
    $("baseline-rules").replaceChildren(...baseline.rules.map((r) =>
      element("li", (titles.get(r.id) || r.id) + " · " + r.matched_count + " matched")));
  } else {
    $("baseline-count").textContent = "No normal-activity measurement for this run.";
    $("baseline-rules").replaceChildren();
  }
  $("rule-count").textContent = hasRules ? String(rules.length) : "—";
  $("rules").replaceChildren(...rules.map((r) => ruleDetail(r, checkedCommit || "main")));
  if (!hasRules) {
    $("chart").append(element("p", "No event counts available.", "missing"));
    $("rules").append(element("p", replay?.error || "This run did not produce per-rule replay data.", "missing"));
  }
  $("pipeline-state").replaceChildren(tag(data.pipeline_status));
  for (const [key, name] of STAGES) {
    const [state, css] = statusLabel(data.checks[key]);
    const stage = element("li");
    stage.append(element("span", name), element("span", state, "stage-state " +
      (css === "good" ? "ok" : css === "bad" ? "problem" : "quiet")));
    $("checks").append(stage);
  }
  const runId = String(data.run_id || "");
  if (/^\d+$/.test(runId)) {
    const attempt = String(data.run_attempt || "");
    const runUrl = REPO + "/actions/runs/" + runId + (/^\d+$/.test(attempt) ? "/attempts/" + attempt : "");
    $("run-meta").append(link("Workflow run " + (data.run_number ? "#" + data.run_number : "") + " ↗", runUrl));
  }
  if (checkedCommit) $("run-meta").append(link("main @ " + checkedCommit.slice(0,7), REPO + "/commit/" + checkedCommit, "mono"));
  $("notice").replaceChildren();
  $("notice").hidden = true;
  if (replay?.error && hasRules) {
    $("notice").textContent = replay.error;
    $("notice").hidden = false;
  }
  $("report").hidden = false;
}
// A failed deployment can leave the preceding snapshot online. Link to a newer
// main run when GitHub reports one; keep the dated evidence when the API is offline.
async function checkFreshness(snapshot) {
  if (!/^\d+$/.test(String(snapshot.run_id || ""))) return;
  const endpoint = "https://api.github.com/repos/sfazliddinov385/DriftGuard/actions/workflows/" +
    "replay-validation.yml/runs?branch=main&per_page=10";
  try {
    const response = await fetch(endpoint, {signal: AbortSignal.timeout(4000)});
    if (!response.ok) return;
    const runs = (await response.json()).workflow_runs;
    if (!Array.isArray(runs)) return;
    const newer = runs.find((run) => run.head_branch === "main" &&
      (run.event === "push" || run.event === "workflow_dispatch") && (
        run.run_number > Number(snapshot.run_number) ||
        (String(run.id) === String(snapshot.run_id) && run.run_attempt > Number(snapshot.run_attempt))
      ));
    if (!newer || !/^\d+$/.test(String(newer.id))) return;
    const notice = $("notice");
    notice.hidden = false;
    notice.append(document.createTextNode(notice.hasChildNodes() ? " " : ""),
      link("View newer main run #" + newer.run_number + " ↗", REPO + "/actions/runs/" + newer.id));
  } catch {
    // Freshness is optional. The run number and UTC timestamp identify the snapshot.
  }
}
async function load() {
  try {
    const response = await fetch("./data.json", {cache:"no-store"});
    if (!response.ok) throw Error("No published report");
    const snapshot = await response.json();
    renderReport(snapshot);
    void checkFreshness(snapshot);
  } catch {
    const notice = $("notice");
    notice.hidden = false;
    notice.replaceChildren(document.createTextNode("The validation report could not be loaded. "),
      link("Check the workflow runs", REPO + "/actions/workflows/replay-validation.yml"), document.createTextNode(" or reload the page."));
  }
}
load();

async function loadScheduledDemo() {
  const target = $("demo-results");
  try {
    const response = await fetch("./windows-alert-demo.json");
    if (!response.ok) throw Error("Missing demo evidence");
    const data = await response.json();
    const table = element("table");
    const header = table.createTHead().insertRow();
    for (const name of ["Field mapping", "Command lines visible", "Scheduled alert"]) {
      const th = element("th", name);
      th.scope = "col";
      header.append(th);
    }
    const body = table.createTBody();
    for (const [key, label] of [["original", "Original"], ["renamed", "Renamed"], ["restored", "Mapping restored"]]) {
      const outcome = data.outcomes[key];
      if (!validCount(outcome.command_lines_visible) || !validCount(outcome.events_indexed) ||
          !outcome.scheduled_job || typeof outcome.tracked_alert !== "boolean") throw Error("Incomplete outcome");
      const row = body.insertRow();
      const name = element("th", label);
      name.scope = "row";
      row.append(name, element("td", fraction(outcome.command_lines_visible, outcome.events_indexed)),
        element("td", outcome.tracked_alert ? "Fired" : "Silent"));
    }
    const rid = data.captured_record_ids["read-clock-encoded"];
    const plain = data.captured_record_ids["read-clock"];
    const summary = element("p", "Follow Windows event record " + rid +
      " through the run. Renaming CommandLine removed its match. Restoring the field mapping brought the alert back. " +
      "The ordinary clock check (record " + plain + ") stayed quiet in all three searches.");
    const verified = element("p", "Captured test run · ");
    const timestamp = element("time", new Intl.DateTimeFormat("en-US", {
      dateStyle: "medium", timeStyle: "short", timeZone: "UTC"
    }).format(new Date(data.verified_utc)) + " UTC");
    timestamp.dateTime = data.verified_utc;
    verified.append(timestamp);
    target.replaceChildren(table, summary, verified);
    if (/^[0-9]+$/.test(String(data.github_run_id))) {
      $("demo-links").prepend(link("Open this Splunk test ↗", REPO + "/actions/runs/" + data.github_run_id));
    }
  } catch {
    target.textContent = "The scheduled-alert results could not be loaded.";
  }
}
loadScheduledDemo();

async function loadManagedRun() {
  const output = $("managed-status");
  try {
    const api = "https://api.github.com/repos/sfazliddinov385/DriftGuard/actions";
    const opts = {signal: AbortSignal.timeout(8000)};
    const response = await fetch(api + "/workflows/splunk-integration.yml/runs?branch=main&per_page=1", opts);
    if (!response.ok) throw Error("Run unavailable");
    const run = (await response.json()).workflow_runs[0];
    if (!run || !/^\d+$/.test(String(run.id))) throw Error("Invalid run");
    $("managed-link").href = REPO + "/actions/runs/" + run.id;
    $("managed-link").textContent = "Open run #" + run.run_number + " ↗";
    const jobs = await fetch(api + "/runs/" + run.id + "/jobs", opts);
    if (!jobs.ok) throw Error("Jobs unavailable");
    const check = (await jobs.json()).jobs.find(j => j.name === "check");
    const label = check?.conclusion === "success" ? "Passed" :
      check?.conclusion === "failure" ? "Needs investigation" :
      run.status !== "completed" ? "In progress" : "Unverified";
    output.textContent = label + " · " + run.created_at.replace("T", " ").replace("Z", " UTC");
  } catch {
    output.textContent = "Current Splunk status unavailable. Open the run history for the latest evidence.";
  }
}
loadManagedRun();
