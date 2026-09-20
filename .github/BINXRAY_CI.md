# Scanning cJSON builds with BinXray in CI

The workflow `.github/workflows/binxray-scan.yml` builds cJSON on GitHub's free Linux runners, then sends the built binaries to a BinXray server and fails the build if BinXray reports severe findings.

## What runs

| Job | What it does | Needs a BinXray server? |
|---|---|---|
| `build` | Builds cJSON (release, shared library) and keeps the ELF files as an artifact | No |
| `scanner-selftest` | Runs `test_binxray_scan.py`: 14 checks of the scan script against a mock server (upload contract, gate levels, exit codes) on a real built binary | No |
| `binxray-scan` | Uploads the binaries to your BinXray server, waits, prints a table, fails on findings at or above the gate | Yes (skipped and green if not configured) |

## Turning the real scan on

Repository Settings > Secrets and variables > Actions:

| Name | Kind | Value |
|---|---|---|
| `BINXRAY_API_URL` | secret | Base URL of your BinXray server. A secret, because this repository is public and workflow files are public. |
| `BINXRAY_API_KEY` | secret | An API key from that server. Optional, but without it the server treats the run as an anonymous guest: masked CVE ids, 3 scans per hour per IP. |
| `BINXRAY_EULA_ACCEPTED` | variable | `true`, only after you have read the BinXray EULA. The server rejects every upload without it, and the script will not accept a legal agreement for you. |
| `BINXRAY_FAIL_ON` | variable | `critical` (default), `high` or `none` (report only). |

Then run the workflow from the Actions tab, or push a commit.

Runs from forks and pull requests from other people do not receive secrets, so they skip the scan and stay green. That is deliberate: it stops an outside pull request from using your server or your key.

## Exit codes of the scan script

`0` passed or skipped, `1` findings at or above the gate, `2` the scan could not be completed (wrong URL or key, EULA not accepted, upload refused, scan failed on the server, timeout). A `2` fails the build; treating "could not scan" as a pass would hide a broken pipeline.

## Why this does not use BinXray's published GitHub Action

Checked against the BinXray server code, the published client (`cli/binxray_cli.py`, which `binxray/scan-action` downloads and runs) cannot scan successfully:

1. It never sends the form field `eula_accepted`, and the server answers every upload without it with HTTP 403. Run against a mock that follows the server's rules, the published client stops at "Upload failed: You must accept the Dual-Use Technology EULA".
2. It sends the API key as `Authorization: Bearer <key>`. The server reads an API key only from the `X-API-Key` header; a Bearer value is tried as a login token, fails, and silently turns the caller into an anonymous guest.

`.github/scripts/binxray_scan.py` follows the real contract instead. These two defects are worth fixing in BinXray's own client.

## Files

- `.github/scripts/binxray_scan.py`: the scan client (Python and `requests`; runs the same locally and in CI).
- `.github/scripts/mock_binxray_api.py`, `test_binxray_scan.py`: the mock server and the self-test.
