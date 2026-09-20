"""A tiny stand-in for the BinXray scan API, used only to test the CI scan script without a real server.

It follows the same rules as the real server (backend/app/presentation/api/routes_scan.py, deps.py):
  * POST /api/scan is refused with 403 unless the form field eula_accepted is "true".
  * An API key is honored only in the X-API-Key header. Anything else (for example a Bearer token) makes the caller an anonymous guest,
    silently, and guests get masked CVE ids (severity and score are kept).
  * GET /api/scan/status/ID answers PENDING, then PROCESSING, then SUCCESS (or FAILED for the "failed" scenario).
It is a test double, not a copy of BinXray: it contains no BinXray code and returns canned findings.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FINDINGS = {
    "clean": [],
    "high": [{"id": "CVE-2000-0001", "severity": "HIGH", "base_score": 7.5}],
    "critical": [{"id": "CVE-2000-0002", "severity": "CRITICAL", "base_score": 9.8}, {"id": "CVE-2000-0003", "severity": "MEDIUM", "base_score": 5.0}],
}


def make_server(scenario, valid_key="test-key"):
    state = {"polls": {}, "last_headers": {}, "uploads": 0}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _is_member(self):
            return self.headers.get("X-API-Key") == valid_key          # the Authorization header is deliberately ignored

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(n)
            state["last_headers"] = {k.lower(): v for k, v in self.headers.items()}
            if self.path != "/api/scan":
                return self._send(404, {"detail": "not found"})
            if b'name="eula_accepted"\r\n\r\ntrue' not in body:
                return self._send(403, {"detail": "You must accept the Dual-Use Technology EULA to use BinXray."})
            state["uploads"] += 1
            return self._send(200, {"task_id": f"task-{state['uploads']}", "status": "PENDING", "is_guest": not self._is_member()})

        def do_GET(self):
            if self.path != "/__debug":            # the debug request must not overwrite the headers it reports
                state["last_headers"] = {k.lower(): v for k, v in self.headers.items()}
            if self.path == "/__debug":
                return self._send(200, {"headers": state["last_headers"], "uploads": state["uploads"]})
            if not self.path.startswith("/api/scan/status/"):
                return self._send(404, {"detail": "not found"})
            tid = self.path.rsplit("/", 1)[1]
            state["polls"][tid] = state["polls"].get(tid, 0) + 1
            n = state["polls"][tid]
            if n == 1:
                return self._send(200, {"task_id": tid, "status": "PENDING"})
            if n == 2:
                return self._send(200, {"task_id": tid, "status": "PROCESSING"})
            if scenario == "failed":
                return self._send(200, {"task_id": tid, "status": "FAILED", "error": "Worker error"})
            vulns = [dict(v) for v in FINDINGS[scenario]]
            if not self._is_member():
                for v in vulns:
                    v.update({"id": "CVE-XXXX-XXXX", "description": "Register to view detailed risk analysis."})
            return self._send(200, {"task_id": tid, "status": "SUCCESS", "results": {
                "filename": "x", "format": "ELF", "libraries": {"cjson": {"version": "1.7.19"}},
                "vulnerabilities": {"cjson": vulns} if vulns else {}}})

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], state
