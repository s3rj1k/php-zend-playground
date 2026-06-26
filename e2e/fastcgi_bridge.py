#!/usr/bin/env python3
"""
Lenient HTTP -> FastCGI bridge for testing php-fpm + the WAF extension.

WHY THIS EXISTS
  FTW (and raw_tests.py) speak HTTP, but php-fpm:9000 speaks the FastCGI binary
  protocol, so they cannot talk directly. A real HTTP front-end / web server was
  used previously, but it performed its own security checks (validates Host
  syntax, URL-decodes the request target and rejects the resulting NUL,
  hardcodes TRACE->405 and CONNECT->400, rejects non-numeric Content-Length,
  emits interim 100-continue, denies /.ht paths, 404s missing .php without
  entering userland). Those checks masked whether the WAF actually fired, so
  the suite could not honestly verify the WAF.

  This bridge is intentionally DUMB and PERMISSIVE: it parses just enough HTTP to
  read the method, the raw request target, headers and body, then forwards them
  to php-fpm as FastCGI params WITHOUT validating, decoding, or rejecting
  anything. The request target is passed through verbatim as REQUEST_URI, every
  method token is accepted (TRACE/CONNECT/DELETE/...), weird Host values are
  forwarded as HTTP_HOST, %00 stays as literal "%00", etc. The WAF (which reads
  $_SERVER, populated from these params) is therefore the verifier for every
  rule. Missing .php files fall back to the index.php front controller so PHP
  userland always runs and the execute_ex hook always fires (preserving the
  original REQUEST_URI so path rules like 1006/1038 still match).

  This is a TEST HARNESS, not a production server: it does Connection: close per
  request, single-threaded-per-connection (threaded), and minimal framing. It
  must never be exposed publicly.
"""

import os
import socket
import struct
import threading
import sys

DOC_ROOT = os.environ.get("DOC_ROOT", "/var/www/html")
FPM_HOST = os.environ.get("FPM_HOST", "php-fpm")
FPM_PORT = int(os.environ.get("FPM_PORT", "9000"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))
INDEX_FILE = "index.php"

# FastCGI 1.0 record types
FCGI_VERSION = 1
FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1

MAX_RECORD = 65535  # max content length per FastCGI record
RECV_BUF = 65536
READ_TIMEOUT = 60


# ---------------------------------------------------------------------------
# FastCGI client
# ---------------------------------------------------------------------------

def _record(rec_type: int, request_id: int, content: bytes) -> bytes:
    """Build one FastCGI record (header is exactly 8 bytes)."""
    content_len = len(content)
    padding = (8 - (content_len % 8)) % 8
    # version(1) type(1) requestId(2) contentLength(2) paddingLength(1) reserved(1)
    # NB: NO trailing 'x' pad — FastCGI headers are 8 bytes, not 9. The extra
    # pad byte corrupts the stream and php-fpm resets the connection.
    header = struct.pack(
        "!BBHHBB",
        FCGI_VERSION,
        rec_type,
        request_id,
        content_len,
        padding,
        0,
    )
    return header + content + (b"\x00" * padding)


def _encode_params(params: dict) -> bytes:
    """Encode name/value pairs into FastCGI PARAMS content bytes."""
    out = bytearray()
    for name, value in params.items():
        nb = name.encode("latin-1", "replace")
        vb = str(value).encode("latin-1", "replace")
        out += _encode_len(len(nb))
        out += _encode_len(len(vb))
        out += nb
        out += vb
    return bytes(out)


def _encode_len(n: int) -> bytes:
    if n < 128:
        return struct.pack("!B", n)
    return struct.pack("!I", n | 0x80000000)


def fcgi_request(params: dict, body: bytes) -> tuple[bytes, bytes]:
    """Send a request to php-fpm and return (stdout_bytes, stderr_bytes)."""
    request_id = 1
    sock = socket.create_connection((FPM_HOST, FPM_PORT), timeout=READ_TIMEOUT)
    sock.settimeout(READ_TIMEOUT)
    try:
        # BEGIN_REQUEST: role RESPONDER, no keep-alive (flags=0)
        begin = struct.pack("!HB5x", FCGI_RESPONDER, 0)
        sock.sendall(_record(FCGI_BEGIN_REQUEST, request_id, begin))

        # PARAMS (may span multiple records), terminated by an empty PARAMS record
        encoded = _encode_params(params)
        for i in range(0, len(encoded), MAX_RECORD):
            sock.sendall(_record(FCGI_PARAMS, request_id, encoded[i:i + MAX_RECORD]))
        sock.sendall(_record(FCGI_PARAMS, request_id, b""))

        # STDIN body (may span multiple records), terminated by an empty record
        for i in range(0, len(body), MAX_RECORD):
            sock.sendall(_record(FCGI_STDIN, request_id, body[i:i + MAX_RECORD]))
        sock.sendall(_record(FCGI_STDIN, request_id, b""))

        # Read response records until END_REQUEST
        stdout = bytearray()
        stderr = bytearray()
        while True:
            header = _recv_exact(sock, 8)
            if header is None or len(header) < 8:
                break
            # NB: FastCGI header is 8 bytes (!BBHHBB), NOT 9 — no trailing 'x'.
            # (The same bug on the send side was already fixed in _record.)
            _, rec_type, req_id, content_len, padding_len, _ = struct.unpack(
                "!BBHHBB", header)
            content = _recv_exact(sock, content_len) if content_len else b""
            if padding_len:
                _recv_exact(sock, padding_len)
            if rec_type == FCGI_STDOUT:
                stdout += content
            elif rec_type == FCGI_STDERR:
                stderr += content
            elif rec_type == FCGI_END_REQUEST:
                break
        return bytes(stdout), bytes(stderr)
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), RECV_BUF))
        if not chunk:
            break
        data += chunk
    return bytes(data)


# ---------------------------------------------------------------------------
# Lenient HTTP request parsing
# ---------------------------------------------------------------------------

def read_request(sock: socket.socket) -> tuple[str, str, str, list, bytes]:
    """Read one HTTP request. Returns (method, target, version, headers, body).

    Lenient: accepts any method token, does not URL-decode the target, does not
    validate Host. Returns ("", "", "", [], b"") on unrecoverable framing error.
    """
    sock.settimeout(READ_TIMEOUT)
    buf = bytearray()

    # Read until end of headers (\r\n\r\n).
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(RECV_BUF)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > 1024 * 1024:  # header bomb guard
            break

    head_end = buf.find(b"\r\n\r\n")
    if head_end < 0:
        return "", "", "", [], b""
    header_blob = bytes(buf[:head_end])
    rest = bytes(buf[head_end + 4:])

    lines = header_blob.split(b"\r\n")
    if not lines or not lines[0]:
        return "", "", "", [], b""

    request_line = lines[0].decode("latin-1", "replace")
    parts = request_line.split(" ")
    if len(parts) < 2:
        return "", "", "", [], b""
    method = parts[0]
    target = parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers = []  # list of (name, value), duplicates preserved
    for line in lines[1:]:
        if not line:
            continue
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers.append(
            (name.decode("latin-1", "replace").strip(),
             value.decode("latin-1", "replace").strip(" \t"))
        )

    # Determine body length.
    cl = header_value(headers, "content-length")
    te = header_value(headers, "transfer-encoding")
    body = bytearray(rest)

    # NOTE: do NOT send "100 Continue" here. FTW sends the entire request
    # (headers + body) in one shot and then reads the response, taking the
    # FIRST status line as the result. An interim 100 would be recorded as
    # the status and mask the WAF's 403. The WAF rule for Expect fires at
    # phase 1 on the header alone, so the body is irrelevant to the block.

    if te and "chunked" in te.lower():
        body += read_chunked(sock, body)
    elif cl and cl.isdigit():
        need = int(cl)
        while len(body) < need:
            try:
                chunk = sock.recv(RECV_BUF)
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
        body = body[:need]
    # else: no body (or read until close — not needed for FTW which sends CL)

    return method, target, version, headers, bytes(body)


def header_value(headers: list, name: str) -> str:
    """First value for a case-insensitive header name."""
    lname = name.lower()
    for n, v in headers:
        if n.lower() == lname:
            return v
    return ""


def read_chunked(sock: socket.socket, initial: bytes) -> bytes:
    """Dechunk a Transfer-Encoding: chunked body already partially in `initial`."""
    data = bytearray(initial)
    out = bytearray()
    pos = 0
    while True:
        # ensure we have a size line
        nl = data.find(b"\r\n", pos)
        while nl < 0:
            chunk = sock.recv(RECV_BUF)
            if not chunk:
                return bytes(out)
            data += chunk
            nl = data.find(b"\r\n", pos)
        size_line = data[pos:nl].split(b";")[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            return bytes(out)
        pos = nl + 2
        if size == 0:
            return bytes(out)
        # ensure we have `size` bytes + trailing CRLF
        while len(data) < pos + size + 2:
            chunk = sock.recv(RECV_BUF)
            if not chunk:
                break
            data += chunk
        out += data[pos:pos + size]
        pos += size + 2


# ---------------------------------------------------------------------------
# Routing + FastCGI param construction
# ---------------------------------------------------------------------------

def resolve_script(target: str) -> tuple[str, str]:
    """Return (script_filename, script_name) for a request target.

    Front-controller fallback: if the path doesn't map to an existing file,
    serve index.php so PHP userland always runs (and the WAF hook fires on the
    ORIGINAL REQUEST_URI). REQUEST_URI is set to the raw target regardless.
    """
    path = target.split("?", 1)[0]
    # Normalize a trailing path segment; never allow escaping DOC_ROOT.
    rel = path.lstrip("/")
    candidate = os.path.normpath(os.path.join(DOC_ROOT, rel))
    if (candidate == DOC_ROOT or candidate.startswith(DOC_ROOT + os.sep)) \
            and os.path.isfile(candidate):
        return candidate, path
    # Front controller fallback.
    return os.path.join(DOC_ROOT, INDEX_FILE), path


def build_params(method, target, version, headers, body, client_addr,
                 client_port):
    script_filename, script_name = resolve_script(target)
    if "?" in target:
        path_only, _, query = target.partition("?")
    else:
        path_only, query = target, ""

    server_name = header_value(headers, "host") or "localhost"

    params = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_PROTOCOL": version,
        "SERVER_SOFTWARE": "fastcgi-bridge/1.0",
        "REQUEST_METHOD": method,
        "REQUEST_URI": target,            # raw, undecoded, incl. query string
        "QUERY_STRING": query,
        "DOCUMENT_ROOT": DOC_ROOT,
        "DOCUMENT_URI": path_only,
        "SCRIPT_NAME": script_name,
        "SCRIPT_FILENAME": script_filename,
        "REMOTE_ADDR": client_addr,
        "REMOTE_PORT": str(client_port),
        "SERVER_ADDR": "127.0.0.1",
        "SERVER_PORT": str(LISTEN_PORT),
        "SERVER_NAME": server_name,
        "REDIRECT_STATUS": "200",         # required by php-fpm security model
    }

    # CONTENT_TYPE / CONTENT_LENGTH use the CGI (no HTTP_) prefix.
    ct = header_value(headers, "content-type")
    if ct:
        params["CONTENT_TYPE"] = ct
    cl = header_value(headers, "content-length")
    if cl:
        params["CONTENT_LENGTH"] = cl
    elif body:
        params["CONTENT_LENGTH"] = str(len(body))

    # All other headers -> HTTP_<NAME> (dashes -> underscores, uppercased).
    # Duplicates are joined with ", " (CGI/1.1 convention).
    grouped = {}
    for name, value in headers:
        if name.lower() in ("content-type", "content-length"):
            continue
        key = "HTTP_" + name.upper().replace("-", "_")
        grouped.setdefault(key, []).append(value)
    for key, values in grouped.items():
        params[key] = ", ".join(values)

    return params


# ---------------------------------------------------------------------------
# CGI/1.1 response -> HTTP response
# ---------------------------------------------------------------------------

def build_http_response(stdout: bytes) -> bytes:
    """Convert php-fpm CGI/1.1 output (headers + blank line + body) to HTTP."""
    sep = stdout.find(b"\r\n\r\n")
    if sep < 0:
        sep = stdout.find(b"\n\n")
        if sep < 0:
            # No header terminator: emit as 200 with the raw bytes.
            return (b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: " + str(len(stdout)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n") + stdout
        head = stdout[:sep]
        body = stdout[sep + 2:]
        sep_lines = b"\n"
    else:
        head = stdout[:sep]
        body = stdout[sep + 4:]
        sep_lines = b"\r\n"

    status_code = 200
    status_text = "OK"
    out_headers = []
    for line in head.split(sep_lines):
        if not line:
            continue
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        name_s = name.decode("latin-1", "replace").strip()
        value_s = value.decode("latin-1", "replace").strip()
        if name_s.lower() == "status":
            # e.g. "403 Forbidden" or "404 Not Found"
            bits = value_s.split(" ", 1)
            try:
                status_code = int(bits[0])
            except (ValueError, IndexError):
                status_code = 200
            status_text = bits[1] if len(bits) > 1 else ""
            # Don't re-emit Status: as a response header.
            continue
        out_headers.append((name_s, value_s))

    # Ensure Content-Length reflects the actual body.
    have_cl = any(n.lower() == "content-length" for n, _ in out_headers)
    resp = bytearray()
    if status_text:
        resp += f"HTTP/1.1 {status_code} {status_text}\r\n".encode("latin-1")
    else:
        resp += f"HTTP/1.1 {status_code}\r\n".encode("latin-1")
    for name_s, value_s in out_headers:
        resp += f"{name_s}: {value_s}\r\n".encode("latin-1")
    if not have_cl:
        resp += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    resp += b"Connection: close\r\n\r\n"
    resp += body
    return bytes(resp)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def handle(conn, addr):
    try:
        method, target, version, headers, body = read_request(conn)
        if not method:
            conn.sendall(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n")
            return
        client_addr = addr[0]
        client_port = addr[1]
        params = build_params(method, target, version, headers, body,
                              client_addr, client_port)
        stdout, stderr = fcgi_request(params, body)
        if stderr:
            sys.stderr.write(
                "[bridge] php-fpm stderr: " + stderr.decode("latin-1", "replace")
                + "\n")
        if not stdout:
            conn.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n")
            return
        conn.sendall(build_http_response(stdout))
    except (socket.timeout, ConnectionError, OSError) as exc:
        # Log connection errors so we can diagnose bridge -> php-fpm issues.
        # Previously silently swallowed, hiding the root cause.
        sys.stderr.write(f"[bridge] connection error: {exc!r}\n")
    except Exception as exc:  # never crash the server thread
        try:
            sys.stderr.write(f"[bridge] error: {exc!r}\n")
            conn.sendall(
                b"HTTP/1.1 500 Internal Server Error\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n")
        except OSError:
            pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(128)
    sys.stderr.write(
        f"[bridge] listening on {LISTEN_HOST}:{LISTEN_PORT}, "
        f"fastcgi {FPM_HOST}:{FPM_PORT}, docroot {DOC_ROOT}\n")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
