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

PERFORMANCE
  The original bridge opened a fresh FastCGI TCP connection per request and
  spawned a thread per connection — both are real per-request costs that nginx
  avoids. This version:
    - keeps a pool of persistent FPM connections (FCGI_KEEP_CONN) and reuses
      them across requests (one request at a time per socket; php-fpm does not
      multiplex, so the pool is bounded by worker count);
    - serves HTTP keep-alive on the client side so oha/FTW reuse one TCP
      connection for many requests (no handshake per request);
    - dispatches connections to a bounded thread pool (no per-request thread
      creation).
  Leniency is UNCHANGED: read_request/resolve_script/build_params are the same
  raw-byte forwarding code. Do not "tidy" the parser into a strict HTTP parser —
  that is exactly what made nginx mask the WAF.

  This is a TEST HARNESS, not production: no TLS, bounded concurrency, runs as
  root to bind :80. Never expose it publicly.
"""

import os
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import deque

DOC_ROOT = os.environ.get("DOC_ROOT", "/var/www/html")
FPM_HOST = os.environ.get("FPM_HOST", "php-fpm")
FPM_PORT = int(os.environ.get("FPM_PORT", "9000"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))
INDEX_FILE = "index.php"

# Concurrency knobs. BRIDGE_WORKERS caps the thread pool (one worker per
# in-flight client connection); FPM_POOL_MAX caps persistent FPM connections.
# FPM_POOL_MAX should be <= php-fpm pm.max_children (see etc/php-fpm.d/zz-pool.conf)
# or extra connections just queue inside FPM.
BRIDGE_WORKERS = int(os.environ.get("BRIDGE_WORKERS", "128"))
FPM_POOL_MAX = int(os.environ.get("FPM_POOL_MAX", "64"))

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
FCGI_KEEP_CONN = 1  # BEGIN_REQUEST flag: keep socket open after END_REQUEST

MAX_RECORD = 65535  # max content length per FastCGI record
RECV_BUF = 65536
READ_TIMEOUT = 60
LISTEN_BACKLOG = 1024


# ---------------------------------------------------------------------------
# FastCGI framing
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


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), RECV_BUF))
        if not chunk:
            break
        data += chunk
    return bytes(data)


# ---------------------------------------------------------------------------
# FPM connection pool (persistent, KEEP_CONN)
# ---------------------------------------------------------------------------

class FpmPool:
    """A bounded pool of persistent FastCGI connections to php-fpm.

    One request uses one socket at a time (php-fpm does not multiplex, so we
    cannot run two BEGIN_REQUEST in parallel on one socket). acquire() returns
    a healthy socket (reused if available, else newly opened up to the cap, else
    it blocks for a free one). release() returns it to the pool; discard()
    closes it (used on any error — a pooled socket may have been closed by FPM).

    If FPM does not honour FCGI_KEEP_CONN in some build, connections still work
    per-request: the stale reuse simply fails, the caller retries once with a
    fresh socket, and the bad socket is discarded. No regression vs the old
    per-request-connect behaviour.
    """

    def __init__(self, max_conns: int):
        self.max = max_conns
        self._idle: deque[socket.socket] = deque()
        self._open = 0
        self._cond = threading.Condition()

    def _open_socket(self) -> socket.socket:
        sock = socket.create_connection((FPM_HOST, FPM_PORT), timeout=READ_TIMEOUT)
        sock.settimeout(READ_TIMEOUT)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def acquire(self) -> socket.socket:
        """Get a socket to talk to FPM on. May be reused (pooled) or fresh.

        Invariant: _open counts IN-FLIGHT sockets (checked out, not idle).
        acquire always +1; release/discard always -1. The cap is _open < max.
        The caller validates by use: a stale pooled socket may raise on the first
        send/recv; the caller retries once via fcgi_request.
        """
        # Fast path: grab an idle socket if one is pooled.
        with self._cond:
            if self._idle:
                sock = self._idle.pop()
                self._open += 1
                return sock
            if self._open < self.max:
                self._open += 1
                need_open = True
            else:
                need_open = False
        if need_open:
            # Open outside the lock (connect can block).
            try:
                return self._open_socket()
            except OSError:
                with self._cond:
                    self._open -= 1
                    self._cond.notify()
                raise
        # At capacity: wait for a release to hand back an idle socket.
        with self._cond:
            while not self._idle:
                self._cond.wait()
            sock = self._idle.pop()
            self._open += 1
            return sock

    def release(self, sock: socket.socket):
        """Return a healthy socket to the pool for reuse, else close it."""
        with self._cond:
            self._open -= 1
            if len(self._idle) < self.max:
                self._idle.append(sock)
                self._cond.notify()
                return
        try:
            sock.close()
        except OSError:
            pass

    def discard(self, sock: socket.socket):
        """Drop a bad socket and free its capacity slot."""
        try:
            sock.close()
        except OSError:
            pass
        with self._cond:
            self._open -= 1
            self._cond.notify_all()


# A single shared pool for the whole process.
_fpm_pool = FpmPool(FPM_POOL_MAX)


def fcgi_request(pool: FpmPool, params: dict, body: bytes) -> tuple[bytes, bytes]:
    """Send a request to php-fpm via the pool. Returns (stdout, stderr).

    Retries once on a stale pooled connection (FPM may have closed it).
    """
    request_id = 1
    # BEGIN_REQUEST: role RESPONDER, FCGI_KEEP_CONN so the socket is reusable.
    begin = struct.pack("!HB5x", FCGI_RESPONDER, FCGI_KEEP_CONN)
    encoded = _encode_params(params)
    # Pre-build the whole upstream write in one buffer: fewer sendall syscalls.
    out = bytearray()
    out += _record(FCGI_BEGIN_REQUEST, request_id, begin)
    for i in range(0, len(encoded), MAX_RECORD):
        out += _record(FCGI_PARAMS, request_id, encoded[i:i + MAX_RECORD])
    out += _record(FCGI_PARAMS, request_id, b"")
    for i in range(0, len(body), MAX_RECORD):
        out += _record(FCGI_STDIN, request_id, body[i:i + MAX_RECORD])
    out += _record(FCGI_STDIN, request_id, b"")
    request_bytes = bytes(out)

    last_err: Exception | None = None
    for attempt in (0, 1):
        sock = pool.acquire()
        reused = attempt == 0  # first attempt may use a pooled socket
        try:
            sock.sendall(request_bytes)
            stdout, stderr = _read_response(sock, request_id)
            pool.release(sock)
            return stdout, stderr
        except (socket.timeout, ConnectionError, OSError) as exc:
            last_err = exc
            pool.discard(sock)
            if reused:
                # Stale pooled connection: retry once with a fresh socket.
                continue
            raise
    raise ConnectionError(f"FastCGI request failed after retry: {last_err!r}")


def _read_response(sock: socket.socket, request_id: int) -> tuple[bytes, bytes]:
    """Read FastCGI response records until END_REQUEST."""
    stdout = bytearray()
    stderr = bytearray()
    while True:
        header = _recv_exact(sock, 8)
        if header is None or len(header) < 8:
            raise ConnectionError("FastCGI connection closed before END_REQUEST")
        # NB: FastCGI header is 8 bytes (!BBHHBB), NOT 9 — no trailing 'x'.
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


# ---------------------------------------------------------------------------
# Lenient HTTP request parsing  (DO NOT MAKE STRICT — see module docstring)
# ---------------------------------------------------------------------------

def read_request(sock: socket.socket) -> tuple[str, str, str, list, bytes]:
    """Read one HTTP request. Returns (method, target, version, headers, body).

    Lenient: accepts any method token, does not URL-decode the target, does not
    validate Host. Returns ("", "", "", [], b"") on unrecoverable framing error
    OR when the connection is cleanly closed (no more requests) — the caller
    distinguishes by also checking recv for EOF.
    """
    sock.settimeout(READ_TIMEOUT)
    buf = bytearray()

    # Read until end of headers (\r\n\r\n). The first recv may return b"" if
    # the client closed after the previous keep-alive response — that is a clean
    # EOF, not an error.
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(RECV_BUF)
        except socket.timeout:
            break
        if not chunk:
            return "", "", "", [], b""
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


def _wants_close(version: str, headers: list) -> bool:
    """Whether the client asked to close after this request (HTTP/1.1 keep-alive
    is the default; HTTP/1.0 close is the default)."""
    conn = header_value(headers, "connection").lower()
    if "close" in conn:
        return True
    if version.upper() == "HTTP/1.0":
        return "keep-alive" not in conn
    return False


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

def build_http_response(stdout: bytes, keep_alive: bool) -> bytes:
    """Convert php-fpm CGI/1.1 output (headers + blank line + body) to HTTP.

    keep_alive controls the Connection header and whether a Content-Length is
    forced (required to frame keep-alive responses).
    """
    sep = stdout.find(b"\r\n\r\n")
    if sep < 0:
        sep = stdout.find(b"\n\n")
        if sep < 0:
            # No header terminator: emit as 200 with the raw bytes.
            return (b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: " + str(len(stdout)).encode() + b"\r\n"
                    b"Connection: " + (b"keep-alive" if keep_alive else b"close") +
                    b"\r\n\r\n") + stdout
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
    have_cl = False
    for line in head.split(sep_lines):
        if not line:
            continue
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        name_s = name.decode("latin-1", "replace").strip()
        value_s = value.decode("latin-1", "replace").strip()
        lname = name_s.lower()
        if lname == "status":
            # e.g. "403 Forbidden" or "404 Not Found"
            bits = value_s.split(" ", 1)
            try:
                status_code = int(bits[0])
            except (ValueError, IndexError):
                status_code = 200
            status_text = bits[1] if len(bits) > 1 else ""
            # Don't re-emit Status: as a response header.
            continue
        if lname == "content-length":
            have_cl = True
        if lname == "connection":
            # We set Connection ourselves below; drop the CGI/app one.
            continue
        out_headers.append((name_s, value_s))

    # For keep-alive we MUST send a correct Content-Length so the client can
    # frame the next request; the bridge buffers the full body so this is exact.
    body_len = len(body)
    resp = bytearray()
    if status_text:
        resp += f"HTTP/1.1 {status_code} {status_text}\r\n".encode("latin-1")
    else:
        resp += f"HTTP/1.1 {status_code}\r\n".encode("latin-1")
    for name_s, value_s in out_headers:
        resp += f"{name_s}: {value_s}\r\n".encode("latin-1")
    if not have_cl:
        resp += b"Content-Length: " + str(body_len).encode() + b"\r\n"
    resp += b"Connection: keep-alive\r\n\r\n" if keep_alive \
        else b"Connection: close\r\n\r\n"
    resp += body
    return bytes(resp)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

_BAD_REQUEST = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)
_BAD_GATEWAY = (
    b"HTTP/1.1 502 Bad Gateway\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)
_INTERNAL_ERROR = (
    b"HTTP/1.1 500 Internal Server Error\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


def handle(conn, addr):
    """Serve one client connection, looping over keep-alive requests."""
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        while True:
            method, target, version, headers, body = read_request(conn)
            if not method:
                # Clean EOF (client closed) or framing error: in either case
                # there is nothing more to read on this connection.
                return
            close_after = _wants_close(version, headers)
            try:
                params = build_params(method, target, version, headers, body,
                                      addr[0], addr[1])
                stdout, stderr = fcgi_request(_fpm_pool, params, body)
            except Exception as exc:
                # Upstream failure (FPM down / stale conn / timeout). Close the
                # client connection — keeping it alive would just fail again.
                sys.stderr.write(f"[bridge] upstream error: {exc!r}\n")
                conn.sendall(_BAD_GATEWAY)
                return
            if stderr:
                sys.stderr.write(
                    "[bridge] php-fpm stderr: "
                    + stderr.decode("latin-1", "replace") + "\n")
            if not stdout:
                conn.sendall(_BAD_GATEWAY)
                return
            conn.sendall(build_http_response(stdout, keep_alive=not close_after))
            if close_after:
                return
    except (socket.timeout, ConnectionError, OSError) as exc:
        # Client side went away. Log only unexpected resets, not clean EOF.
        sys.stderr.write(f"[bridge] client error: {exc!r}\n")
    except Exception as exc:  # never crash the worker thread
        try:
            sys.stderr.write(f"[bridge] error: {exc!r}\n")
            conn.sendall(_INTERNAL_ERROR)
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
    srv.listen(LISTEN_BACKLOG)
    sys.stderr.write(
        f"[bridge] listening on {LISTEN_HOST}:{LISTEN_PORT}, "
        f"fastcgi {FPM_HOST}:{FPM_PORT}, docroot {DOC_ROOT}, "
        f"workers={BRIDGE_WORKERS}, fpm_pool={FPM_POOL_MAX}\n")
    executor = ThreadPoolExecutor(max_workers=BRIDGE_WORKERS,
                                  thread_name_prefix="bridge")
    while True:
        conn, addr = srv.accept()
        # submit returns immediately; if the pool is saturated the task queues
        # (the TCP connection is already accepted, the client just waits).
        executor.submit(handle, conn, addr)


if __name__ == "__main__":
    main()
