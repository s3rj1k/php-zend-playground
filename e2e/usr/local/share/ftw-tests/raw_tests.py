"""
Raw HTTP test harness for the PHP WAF.

FTW's YAML schema cannot express duplicate headers, so these tests use a raw
socket for hand crafted HTTP and assert on the response status. They run in
the same pytest invocation as the FTW YAML tests and target the HAProxy >
php-fpm stack via FTW_HOST / FTW_PORT (default host `bridge`, the HAProxy
service).

The extension rebuilds REQUEST_HEADERS from $_SERVER, collapsing duplicate
headers to one scalar, so duplicate headers are tested for graceful handling
(no crash / no false block), not for a block.

Why raw sockets here (not FTW YAML): a few cases need an empty header value,
an explicit HTTP/1.0 request line, or a hand-built body that FTW's autocomplete
would alter. Raw control bytes (bare CR/LF) are NOT tested here anymore: no
real HTTP front-end (HAProxy included) forwards a raw CR/LF inside a header
value (RFC 9112 defines CRLF as the header delimiter; HAProxy normalizes
mid-header line breaks to LWS). Those rules are covered via their percent
-encoded alternates in the YAML suite (%0d/%0a, which the WAF regex matches
literally). See AGENTS.md.
"""
import os
import socket

HOST = os.environ.get("FTW_HOST", "bridge")
PORT = int(os.environ.get("FTW_PORT", "80"))
TIMEOUT = 10


def _send_raw(request_bytes: bytes) -> tuple[int, str, str]:
    """Send raw HTTP request bytes return (status_code, headers, body)."""
    sock = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    try:
        sock.sendall(request_bytes)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()

    text = b"".join(chunks).decode("latin-1", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    status_line, _, header_block = head.partition("\r\n")
    try:
        status_code = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        status_code = 0
    return status_code, header_block, body


def _request(method: str, path: str, headers: list[tuple[str, str]],
             body: str = "") -> bytes:
    """Build a raw HTTP/1.1 request from explicit header tuples.

    `headers` is a list of (name, value) tuples so duplicate names are
    preserved. Host and User Agent are added if not provided.
    """
    has_host = any(name.lower() == "host" for name, _ in headers)
    has_ua = any(name.lower() == "user-agent" for name, _ in headers)

    lines = [f"{method} {path} HTTP/1.1"]
    if not has_host:
        lines.append(f"Host: {HOST}")
    if not has_ua:
        lines.append("User-Agent: raw-harness")
    for name, value in headers:
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body.encode('latin-1'))}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    return ("\r\n".join(lines) + body).encode("latin-1")


#
# Sanity the harness itself is wired correctly.
#

def test_clean_raw_request_allowed():
    """A well formed raw GET must return 200."""
    req = _request("GET", "/index.php", [])
    status, _, _ = _send_raw(req)
    assert status == 200, f"expected 200 for clean request, got {status}"


#
# Duplicate Content Type (rule 1075 was removed). The extension reconstructs
# REQUEST_HEADERS from $_SERVER, which collapses duplicate headers, so a
# duplicate Content Type must be handled gracefully — not blocked, not crashed.
#

def test_duplicate_content_type_handled_gracefully():
    """Duplicate Content Type must not trigger a WAF block or an error."""
    req = _request("POST", "/post.php", [
        ("Content-Type", "application/json"),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ], body="{}")
    status, _, _ = _send_raw(req)
    assert status < 400, (
        f"duplicate Content-Type should be handled gracefully, got {status}"
    )


def test_duplicate_content_type_matching_values_handled_gracefully():
    """Even matching duplicate Content Type values must not block."""
    req = _request("POST", "/post.php", [
        ("Content-Type", "application/json"),
        ("Content-Type", "application/json"),
    ], body="{}")
    status, _, _ = _send_raw(req)
    assert status < 400, (
        f"duplicate Content-Type should be handled gracefully, got {status}"
    )


#
# Header/request line smuggling. A real front-end (HAProxy) parses on CRLF, so
# a bare CR/LF inside a header value never reaches the WAF as a raw byte — it
# is normalized to LWS (RFC 9112). These vectors are therefore tested via their
# percent-encoded alternates in the YAML suite (rule 1028 via %0d in Host,
# rule 1047 via %0a in ARGS), which the WAF regex matches literally. The one
# framing vector that DOES survive a real front-end is CL+TE both present:
# HAProxy forwards both headers (not stripping either), so rule 1105 fires.
#

def test_request_smuggling_cl_te_rejected():
    """Rule 1105 (CRS 920181) CL + Transfer Encoding both present.

    A request carrying both Content-Length and Transfer-Encoding is a request
    smuggling vector. HAProxy forwards both headers to php-fpm (it does not
    resolve the ambiguity itself); rule 1105 blocks at phase 1 -> 403.
    """
    raw = (
        "POST /index.php HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: raw-harness\r\n"
        "Accept: */*\r\n"
        "Content-Length: 5\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "x=123"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status == 403, (
        f"CL+TE smuggling should be blocked by rule 1105, got {status}"
    )


#
# CRLF injection in an argument. Sent percent-encoded (%0a) so it passes
# HAProxy's request-line parser; the WAF URL-decodes ARGS, so the literal LF
# is present in the arg value and rule 1047 (CRLF in ARGS) matches -> 403.
#

def test_lf_injection_in_arg_rejected():
    """Rule 1047 a percent-encoded LF (%0a) in an arg is blocked.

    HAProxy forwards /index.php?q=line%0ainjection untouched; the WAF decodes
    ARGS['q'] = "line\\ninjection" and rule 1047 matches -> 403.
    """
    raw = (
        "GET /index.php?q=line%0ainjection HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: raw-harness\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status == 403, (
        f"%0a in arg should be blocked by rule 1047, got {status}"
    )


#
# Raw body with a NUL byte that FTW's YAML cannot carry cleanly. Sent
# percent-encoded (%00) so it traverses HAProxy as normal form data; PHP/WAF
# URL-decode it to a real NUL in the arg. Ensures the pipeline does not crash
# on control bytes in the body.
#

def test_nul_byte_in_body_does_not_crash():
    """A percent-encoded NUL (%00) in the POST body must not crash the pipeline."""
    body = "data=hello%00world"
    req = _request("POST", "/post.php", [
        ("Content-Type", "application/x-www-form-urlencoded"),
    ], body=body)
    status, _, _ = _send_raw(req)
    # Only assert no 5xx (server crash) and no hang either 200 or 403 is fine.
    assert status < 500, (
        f"%00 in body caused server error {status}"
    )


#
# Rules ported from OWASP CRS 4.27.0 that require raw HTTP (FTW's YAML schema
# cannot express an empty header value or a non 1.1 request line version).
#

def test_empty_accept_header_blocked():
    """Rule 1104 (CRS 920310) an empty Accept header must be blocked (403)."""
    req = _request("GET", "/index.php", [("Accept", "")])
    status, _, _ = _send_raw(req)
    assert status == 403, (
        f"empty Accept header should be blocked by rule 1104, got {status}"
    )


def test_nonempty_accept_header_allowed():
    """Rule 1104 (CRS 920310) a real Accept value must not be blocked."""
    req = _request("GET", "/index.php", [("Accept", "*/*")])
    status, _, _ = _send_raw(req)
    assert status == 200, (
        f"Accept: */* should be allowed, got {status}"
    )


def test_http_1_0_protocol_blocked():
    """Rule 1109 (CRS 920430) an HTTP/1.0 request must be blocked (403).

    The bridge forwards the client protocol version to FPM as SERVER_PROTOCOL, so
    the extension derives REQUEST_PROTOCOL='HTTP/1.0' and rule 1109 fires.
    """
    raw = (
        "GET /index.php HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "User-Agent: raw-harness\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status == 403, (
        f"HTTP/1.0 request should be blocked by rule 1109, got {status}"
    )


def test_http_1_1_protocol_allowed():
    """Rule 1109 (CRS 920430) an HTTP/1.1 request must be allowed (200)."""
    raw = (
        "GET /index.php HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: raw-harness\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status == 200, (
        f"HTTP/1.1 request should be allowed, got {status}"
    )


#
# Oversized response body inspection. The bench/rule scenario configs set
# waf.modsec_response_body_limit = 1MB. Only the first limit bytes are
# inspected (the rest stream through once the buffer is full). These guard the
# overflow handling in waf_ub_write: the inspected prefix must still be matched,
# and a marker that lands entirely in the overflow tail must not be matched.
#

def test_oversized_response_marker_in_prefix_blocked():
    """Rule 1008 marker inside the inspected prefix (small body) is blocked."""
    req = _request("GET", "/big.php?pad=0&mark=1", [("Accept", "*/*")])
    status, _, _ = _send_raw(req)
    assert status == 403, (
        f"blocked_response_content in inspected prefix should be blocked, got {status}"
    )


def test_oversized_response_benign_padding_allowed():
    """A >1MB benign response (no marker) streams through and is allowed (200)."""
    req = _request("GET", "/big.php?pad=2000000", [("Accept", "*/*")])
    status, _, _ = _send_raw(req)
    assert status == 200, (
        f"benign oversized response should be allowed, got {status}"
    )


def test_oversized_response_marker_in_tail_not_blocked():
    """Rule 1008 marker placed AFTER the 1MB limit is in the uninspected tail.

    Only the first modsec_response_body_limit bytes are inspected (by design,
    to bound memory), so a marker landing in the overflow tail must not trigger
    a block. This also verifies the overflow path does not crash on a >1MB body.
    """
    req = _request("GET", "/big.php?pad=2000000&mark=1", [("Accept", "*/*")])
    status, _, _ = _send_raw(req)
    assert status == 200, (
        f"marker in overflow tail should not be blocked (inspect prefix only), "
        f"got {status}"
    )
