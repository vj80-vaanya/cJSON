#!/usr/bin/env python3
"""Upload built binaries to a BinXray server, wait for the result, and fail the build on severe findings.

Usage:  python binxray_scan.py FILE [FILE ...]

Configuration (environment):
  BINXRAY_API_URL         Base URL of the BinXray server, e.g. https://binxray.example.com (no trailing path). If unset, the scan is
                          SKIPPED and the script exits 0, so a fork or a pull request without secrets still gets a green build.
  BINXRAY_API_KEY         A BinXray API key. Sent in the X-API-Key header (the only place the server reads it). Without a key the server
                          treats the caller as an anonymous guest: details are masked and only 3 scans per hour per IP are allowed.
  BINXRAY_EULA_ACCEPTED   Must be "true". The server refuses every upload without it (it asks you to accept the BinXray Dual-Use
                          Technology EULA). This script never accepts a legal agreement on your behalf: set it deliberately.
  FAIL_ON                 critical (default) | high | none. Which findings fail the build.
  ANALYSIS_MODE           fast (default). "deep" is enterprise-only on the server.
  TIMEOUT_SECONDS         Per-file wait for the scan to finish (default 600).
  OUT_DIR                 Where result JSON files are written (default binxray-results).

Exit codes:  0 = passed or skipped,  1 = findings at or above the FAIL_ON level,  2 = the scan could not be completed
(bad URL or key, EULA not accepted, upload refused, scan failed on the server, timeout).

API contract (checked against the server code, backend/app/presentation/api/routes_scan.py and deps.py):
  POST /api/scan            multipart: file, analysis_mode, eula_accepted   ->  {"task_id": ..., "status": "PENDING"}
  GET  /api/scan/status/ID  ->  status PENDING | PROCESSING | FAILED | SUCCESS; on SUCCESS "results.vulnerabilities" is
                            {library: [ {severity, base_score, ...} ]} (id/description are masked for guests and free accounts).
"""
import json
import os
import sys
import time
from pathlib import Path

import requests

POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "5"))


def log(msg):
    print(msg, flush=True)


def annotate(kind, msg):
    """GitHub Actions annotation (shows on the run page); plain text elsewhere."""
    print(f"::{kind}::{msg}", flush=True)


def count(vulns):
    """Return (critical, high, total) from the flattened vulnerability list, using severity, else the CVSS score."""
    crit = high = 0
    for v in vulns:
        sev = str(v.get("severity") or "").upper()
        try:
            score = float(v.get("base_score") or 0)
        except (TypeError, ValueError):
            score = 0.0
        if sev == "CRITICAL" or (not sev and score >= 9.0):
            crit += 1
        elif sev == "HIGH" or (not sev and score >= 7.0):
            high += 1
    return crit, high, len(vulns)


def scan_one(base, headers, path, mode, timeout_s):
    with open(path, "rb") as fh:
        r = requests.post(f"{base}/api/scan", headers=headers, files={"file": (path.name, fh)},
                          data={"analysis_mode": mode, "eula_accepted": "true"}, timeout=120)
    if r.status_code != 200:
        raise RuntimeError(f"upload refused for {path.name}: HTTP {r.status_code} {r.text[:300]}")
    task_id = r.json().get("task_id")
    if not task_id:
        raise RuntimeError(f"upload for {path.name} returned no task_id: {r.text[:300]}")
    log(f"[*] {path.name}: scan queued (task {task_id})")
    deadline = time.time() + timeout_s
    while True:
        if time.time() > deadline:
            raise RuntimeError(f"{path.name}: scan did not finish within {timeout_s}s")
        s = requests.get(f"{base}/api/scan/status/{task_id}", headers=headers, timeout=60)
        if s.status_code == 200:
            body = s.json()
            status = body.get("status")
            if status == "SUCCESS":
                return body["results"]
            if status == "FAILED":
                raise RuntimeError(f"{path.name}: scan failed on the server: {body.get('error')}")
        elif s.status_code in (401, 403, 404):
            raise RuntimeError(f"{path.name}: status check refused: HTTP {s.status_code} {s.text[:200]}")
        else:
            log(f"[!] status check returned HTTP {s.status_code}; retrying")
        time.sleep(POLL_SECONDS)


def main(argv):
    files = [Path(a) for a in argv[1:]]
    if not files:
        print(__doc__)
        return 2
    base = os.environ.get("BINXRAY_API_URL", "").strip().rstrip("/")
    fail_on = os.environ.get("FAIL_ON", "critical").strip().lower()
    out = Path(os.environ.get("OUT_DIR", "binxray-results"))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")

    def write_summary(text):
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(text + "\n")

    if not base:
        annotate("notice", "BinXray scan skipped: BINXRAY_API_URL is not set (add it as a repository secret to enable scanning).")
        write_summary("### BinXray scan\nSkipped: `BINXRAY_API_URL` secret is not set.")
        return 0
    if fail_on not in ("critical", "high", "none"):
        annotate("error", f"FAIL_ON must be critical, high or none, not {fail_on!r}")
        return 2
    if os.environ.get("BINXRAY_EULA_ACCEPTED", "").strip().lower() != "true":
        annotate("error", "BinXray requires you to accept its EULA before scanning. Read it, then set the repository variable "
                          "BINXRAY_EULA_ACCEPTED to 'true'. (This script will not accept a legal agreement for you.)")
        return 2
    headers = {}
    key = os.environ.get("BINXRAY_API_KEY", "").strip()
    if key:
        headers["X-API-Key"] = key
    else:
        annotate("warning", "No BINXRAY_API_KEY: the server will treat this run as an anonymous guest (masked details, 3 scans per hour per IP).")
    missing = [str(p) for p in files if not p.is_file()]
    if missing:
        annotate("error", f"file(s) not found: {', '.join(missing)}")
        return 2

    out.mkdir(parents=True, exist_ok=True)
    mode = os.environ.get("ANALYSIS_MODE", "fast")
    timeout_s = int(os.environ.get("TIMEOUT_SECONDS", "600"))
    rows, total_crit, total_high = [], 0, 0
    for path in files:
        try:
            results = scan_one(base, headers, path, mode, timeout_s)
        except (RuntimeError, requests.RequestException) as e:
            annotate("error", f"BinXray scan could not be completed: {e}")
            write_summary(f"### BinXray scan\nCould not complete: `{e}`")
            return 2
        (out / f"{path.name}.binxray.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        vulns = [v for lst in (results.get("vulnerabilities") or {}).values() for v in (lst or [])]
        crit, high, total = count(vulns)
        libs = results.get("libraries") or {}
        rows.append((path.name, results.get("format", "?"), len(libs), total, crit, high))
        total_crit += crit
        total_high += high
        log(f"[+] {path.name}: format={results.get('format')} libraries={len(libs)} findings={total} critical={crit} high={high}")

    table = ["| File | Format | Libraries | Findings | Critical | High |", "|---|---|---|---|---|---|"]
    table += [f"| {n} | {f} | {l} | {t} | {c} | {h} |" for n, f, l, t, c, h in rows]
    gate = {"critical": "fails on any CRITICAL", "high": "fails on any CRITICAL or HIGH", "none": "report only"}[fail_on]
    write_summary("### BinXray scan\n" + "\n".join(table) + f"\n\nGate: {gate}.")
    log("\n".join(table))

    failed = (fail_on == "critical" and total_crit > 0) or (fail_on == "high" and (total_crit + total_high) > 0)
    if failed:
        annotate("error", f"BinXray gate failed ({gate}): {total_crit} critical, {total_high} high across {len(rows)} file(s).")
        return 1
    log(f"[+] BinXray gate passed ({gate}).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
