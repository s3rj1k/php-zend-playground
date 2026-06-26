"""
Raw HTTP test harness for the PHP WAF.

FTW's YAML schema cannot express duplicate headers or arbitrary raw bytes in
the request line/headers, so these tests use a raw socket for hand crafted
HTTP and assert on the response status. They run in the same pytest invocation
as the FTW YAML tests and target the nginx > php fpm stack via FTW_HOST /
FTW_PORT (default nginx 80).

The extension rebuilds REQUEST_HEADERS from $_SERVER, collapsing duplicate
headers to one scalar, so duplicate headers are tested for graceful handling
(no crash / no false block), not for a block. Malformed HTTP tests assert the
request is rejected rather than reaching the app.
"""
import os
import socket

HOST = os.environ.get("FTW_HOST", "nginx")
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
# Header/request line smuggling via raw CRLF bytes. FTW percent encodes or
# rejects control chars in header values raw sockets can inject actual
# CR/LF. Such malformed requests must be rejected (400/403), never reach the
# application as 200.
#

def test_host_header_crlf_injection_rejected():
    """A literal CRLF inside the Host header value must be rejected."""
    raw = (
        "GET /index.php HTTP/1.1\r\n"
        "Host: localhost\r\nX-Injected: yes\r\n"
        "User-Agent: raw-harness\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status in (400, 403), (
        f"Host CRLF injection should be rejected (400/403), got {status}"
    )


def test_literal_newline_in_request_line_rejected():
    """A literal LF in the request target must be rejected."""
    raw = (
        "GET /index.php?q=line\ninjection HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: raw-harness\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status in (400, 403), (
        f"newline in request line should be rejected (400/403), got {status}"
    )


def test_header_smuggling_via_tab_in_value_rejected():
    """A smuggled header via CRLF in an arbitrary header value is rejected."""
    raw = (
        "GET /index.php HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "User-Agent: raw-harness\r\n"
        "X-Custom: value\r\nX-Smuggled: yes\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    status, _, _ = _send_raw(raw)
    assert status in (400, 403), (
        f"header smuggling should be rejected (400/403), got {status}"
    )


#
# Raw body with a NUL byte that FTW's YAML cannot carry cleanly. Ensures the
# WAF/nginx pipeline does not crash on control bytes in the body.
#

def test_nul_byte_in_body_does_not_crash():
    """A NUL byte in the POST body must not crash the pipeline."""
    body = "data=hello\x00world"
    req = _request("POST", "/post.php", [
        ("Content-Type", "application/x-www-form-urlencoded"),
    ], body=body)
    status, _, _ = _send_raw(req)
    # Only assert no 5xx (server crash) and no hang either 200 or 403 is fine.
    assert status < 500, (
        f"NUL in body caused server error {status}"
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

    nginx forwards the client protocol version to FPM as SERVER_PROTOCOL, so
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


def test_request_smuggling_cl_te_rejected():
    """Rule 1105 (CRS 920181) CL + Transfer Encoding both present.

    A request carrying both Content Length and Transfer Encoding is a request
    smuggling vector. nginx's handling of the (non chunked) body is version
    dependent, so the request may be rejected by nginx (400) or blocked by the
    WAF rule 1105 (403). Either is correct only a 200 (reaching the app) is a
    failure.
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
    assert status in (400, 403), (
        f"CL+TE smuggling should be rejected (400/403), got {status}"
    )
