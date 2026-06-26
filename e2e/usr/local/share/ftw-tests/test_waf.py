"""
FTW test runner for PHP WAF.

FTW's pytest plugin parses the YAML files in this directory and parametrizes
this function with one parsed Test object per stage. The plugin only performs
parametrization, it does NOT execute the stages. The test body must drive
execution by calling TestRunner.run_stage, which sends the HTTP request to
dest_addr:port (taken from each stage's YAML input) and asserts the expected
output (status, response_contains). Without this the YAML suite is collected
and reported green without a single request leaving the container.

On failure the runner:
  1. re-sends the exact request via curl (the test image ships curl) and prints
     the status + first 600 bytes of the body. This is the decisive evidence:
     a WAF block page ("Request blocked by ModSecurity") vs a PHP error vs a
     bridge error vs an empty 403.
  2. greps the ModSecurity audit + debug logs for the request URI (part B of
     an audit transaction holds the raw request line). NOTE: SecDebugLogLevel=3
     logs ONLY warnings/errors, so a clean transaction produces no debug lines
     a missing debug entry does NOT mean the WAF skipped the request. The audit
     log is the authoritative signal: no audit entry == no rule matched == the
     403 did NOT come from a WAF rule block (every block calls process_logging).
  3. appends a RAW tail of both logs as a last resort.

The test container mounts the php-fpm modsec_logs volume read-only at /var/log.
"""
import re
import subprocess

import pytest

from ftw import errors, testrunner

_AUDIT_LOG = "/var/log/modsec_audit.log"
_DEBUG_LOG = "/var/log/modsec_debug.log"


def _read(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except Exception as exc:  # noqa: BLE001 - best effort diagnostics
        return f"(unavailable: {exc})"


def _curl(stage):
    """Re-send the stage's request via curl and return (status, body_snippet).

    Replicates method, uri, headers (incl. Host), and body. Uses --http1.1 and a
    benign UA so the probe itself is not blocked by rule 1025. Best effort: if
    curl is unavailable or errors, returns a placeholder."""
    try:
        inp = stage.input
        host = inp.headers.get("Host", "bridge")
        url = f"http://{inp.dest_addr}:{inp.port}{inp.uri}"
        cmd = [
            "curl", "-sS", "-i", "--http1.1", "-X", inp.method,
            "-H", f"Host: {host}",
            "-H", "User-Agent: FTW-diagnostic",
            "--max-time", "5",
        ]
        # Forward all non-Host headers from the stage.
        for name, val in (inp.headers or {}).items():
            if name.lower() == "host":
                continue
            cmd += ["-H", f"{name}: {val}"]
        data = getattr(inp, "data", "") or ""
        if data:
            cmd += ["--data-binary", data]
        cmd += [url]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        # First line is the status line. Body is after the blank line.
        status = "?"
        m = re.search(r"HTTP/\S+\s+(\d+)", out)
        if m:
            status = m.group(1)
        body = out
        if "\r\n\r\n" in out:
            body = out.split("\r\n\r\n", 1)[1]
        elif "\n\n" in out:
            body = out.split("\n\n", 1)[1]
        snippet = body[:600]
        return status, snippet
    except Exception as exc:  # noqa: BLE001 - best effort diagnostics
        return "?", f"(curl failed: {exc})"


def _grep_audit(uri):
    text = _read(_AUDIT_LOG)
    blocks = re.split(r"(?m)^(?=--[a-f0-9]+-A--)", text)
    needles = [uri]
    if "?" in uri:
        needles.append(uri.split("?", 1)[0])
    for block in blocks:
        for needle in needles:
            if re.search(re.escape(needle), block):
                return block if len(block) < 4000 else block[:4000] + "\n...[truncated]"
    return "(no audit transaction matched request URI %r)" % uri


def _grep_debug(uri):
    text = _read(_DEBUG_LOG)
    candidates = [uri]
    if "?" in uri:
        path = uri.split("?", 1)[0]
        candidates.append(path)
        candidates.append(path.rsplit("/", 1)[-1])
    lines = []
    for needle in candidates:
        lines = [ln for ln in text.splitlines() if needle in ln]
        if lines:
            break
    if not lines:
        return "(no debug log lines matched any form of %r)\nNOTE: level 3 logs only errors/matches" % uri
    out = "\n".join(lines[-60:])
    return out if len(out) < 6000 else out[:6000] + "\n...[truncated]"


def _tail_raw(path, n=80):
    try:
        with open(path, "r", errors="replace") as fh:
            return "".join(fh.readlines()[-n:])
    except Exception as exc:  # noqa: BLE001 - best effort diagnostics
        return f"(unavailable: {exc})"


def _diagnostics(test, uri):
    stage = None
    for s in reversed(test.stages):
        try:
            if s.input.uri == uri:
                stage = s
                break
        except Exception:  # noqa: BLE001
            continue
    curl_status, curl_body = ("?", "") if stage is None else _curl(stage)
    return (
        f"--- request URI: {uri} ---\n"
        f"--- curl re-send: status={curl_status} ---\n{curl_body}\n\n"
        f"--- modsec_audit.log (matching transaction; part H/K = matched rules) ---\n"
        f"{_grep_audit(uri)}\n\n"
        f"--- modsec_debug.log (lines matching URI) ---\n{_grep_debug(uri)}\n\n"
        f"--- modsec_debug.log (RAW tail, last 80 lines) ---\n{_tail_raw(_DEBUG_LOG)}\n\n"
        f"--- modsec_audit.log (RAW tail, last 40 lines) ---\n{_tail_raw(_AUDIT_LOG, 40)}"
    )


def test_waf(test):
    """Execute every stage of an FTW YAML test against the bridge -> php-fpm stack."""
    runner = testrunner.TestRunner()
    try:
        for stage in test.stages:
            runner.run_stage(stage, None)
    except errors.TestError as exc:
        ctx = exc.args[1] if len(exc.args) > 1 else {}
        uri = _first_uri(test)
        pytest.fail(f"{exc.args[0]} :: {ctx}\n{_diagnostics(test, uri)}", pytrace=False)
    except AssertionError as exc:
        uri = _first_uri(test)
        pytest.fail(f"{exc}\n{_diagnostics(test, uri)}", pytrace=False)


def _first_uri(test):
    """Best effort: the URI of the (last) stage that ran, for log grep."""
    for stage in reversed(test.stages):
        try:
            return stage.input.uri
        except Exception:  # noqa: BLE001
            continue
    return "/"
