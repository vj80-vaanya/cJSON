"""Self-test for binxray_scan.py against the mock API. Run:  python .github/scripts/test_binxray_scan.py [FILE_TO_SCAN]

Every case checks the exit code (0 pass/skip, 1 findings, 2 could not scan) and, where it matters, what the server actually received.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from mock_binxray_api import make_server  # noqa: E402

SCAN = HERE / "binxray_scan.py"
target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkstemp(suffix=".bin")[1])
if not sys.argv[1:]:
    target.write_bytes(b"\x7fELF" + bytes(range(64)))
failures = []


def run(env_extra, label, expect, want_out=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BINXRAY_", "FAIL_ON", "ANALYSIS_MODE", "GITHUB_STEP_SUMMARY"))}
    env.update({"POLL_SECONDS": "0.05", "OUT_DIR": tempfile.mkdtemp()})
    env.update(env_extra)
    p = subprocess.run([sys.executable, str(SCAN), str(target)], env=env, capture_output=True, text=True, timeout=120)
    ok = p.returncode == expect and (want_out is None or want_out in p.stdout + p.stderr)
    print(("PASS " if ok else "FAIL ") + f"{label}: exit {p.returncode} (expected {expect})")
    if not ok:
        failures.append(label)
        print("   output:", (p.stdout + p.stderr)[-500:].replace("\n", "\n   "))
    return p, env["OUT_DIR"]


def server(scenario):
    srv, port, state = make_server(scenario)
    return srv, f"http://127.0.0.1:{port}", state


ok_env = {"BINXRAY_EULA_ACCEPTED": "true", "BINXRAY_API_KEY": "test-key"}

run({}, "no URL configured -> skipped, green", 0, "skipped")

srv, url, st = server("clean")
run({"BINXRAY_API_URL": url, "BINXRAY_API_KEY": "test-key"}, "EULA not accepted -> refuses to scan", 2, "EULA")
p, out = run({"BINXRAY_API_URL": url, **ok_env}, "clean binary passes", 0)
assert any(Path(out).glob("*.binxray.json")), "results file missing"
h = requests.get(url + "/__debug").json()["headers"]
if h.get("x-api-key") != "test-key" or "authorization" in h:
    failures.append("api key must be sent as X-API-Key, not Authorization")
    print("FAIL API key header:", h)
else:
    print("PASS API key sent as X-API-Key only (not as a Bearer token)")
run({"BINXRAY_API_URL": url, "BINXRAY_EULA_ACCEPTED": "true", "BINXRAY_API_KEY": "wrong"}, "wrong key still scans (as guest), like the real server", 0)
r = requests.post(url + "/api/scan", files={"file": ("a.bin", b"x")}, data={"analysis_mode": "fast"})
print(("PASS " if r.status_code == 403 else "FAIL ") + f"mock server enforces the EULA field (HTTP {r.status_code})")
if r.status_code != 403:
    failures.append("mock does not enforce EULA")
srv.shutdown()

srv, url, st = server("high")
run({"BINXRAY_API_URL": url, **ok_env}, "HIGH finding, gate=critical -> passes", 0)
run({"BINXRAY_API_URL": url, **ok_env, "FAIL_ON": "high"}, "HIGH finding, gate=high -> fails", 1)
srv.shutdown()

srv, url, st = server("critical")
run({"BINXRAY_API_URL": url, **ok_env}, "CRITICAL finding, gate=critical -> fails", 1, "gate failed")
run({"BINXRAY_API_URL": url, **ok_env, "BINXRAY_API_KEY": "wrong"}, "CRITICAL still counted when details are masked (guest)", 1)
run({"BINXRAY_API_URL": url, **ok_env, "FAIL_ON": "none"}, "CRITICAL finding, gate=none -> report only", 0)
srv.shutdown()

srv, url, st = server("failed")
run({"BINXRAY_API_URL": url, **ok_env}, "scan fails on the server -> exit 2", 2, "failed on the server")
srv.shutdown()

run({"BINXRAY_API_URL": "http://127.0.0.1:1", **ok_env}, "server unreachable -> exit 2", 2)
run({"BINXRAY_API_URL": url, **ok_env, "FAIL_ON": "bogus"}, "invalid FAIL_ON -> exit 2", 2)

print("\nALL PASSED" if not failures else f"\nFAILED: {failures}")
sys.exit(1 if failures else 0)
