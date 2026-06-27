// Command waf-bridge is a dumb, lenient, performant HTTP -> FastCGI proxy that
// fronts php-fpm for the WAF test/bench stack.
//
// WHY (not net/http.Server): a real HTTP front-end / net/http.Server PARSES the
// request strictly (validates Host, URL-decodes the target and rejects the
// resulting NUL, rejects TRACE/CONNECT/non-numeric Content-Length, emits interim
// 100-continue, 404s missing .php). Those checks MASK whether the WAF actually
// fired, so the suite could not honestly verify the WAF. This bridge parses just
// enough HTTP to read method / raw request target / headers / body, then forwards
// them to php-fpm as FastCGI params WITHOUT validating/decoding/rejecting
// anything. REQUEST_URI is the raw target verbatim (%00 stays "%00", .. stays ..,
// :// stays ://), any method token is accepted, weird Host is forwarded as
// HTTP_HOST. The WAF (inside php-fpm, reading $_SERVER) is the verifier for
// every rule. Missing .php falls back to index.php so userland always runs and
// the execute_ex hook always fires (preserving the original REQUEST_URI so path
// rules like 1006/1038 still match).
//
// PERFORMANCE: compiled Go — no GIL, goroutines use all cores natively
// (GOMAXPROCS=NumCPU), so a single process reaches nginx-class throughput with no
// prefork. FastCGI framing is delegated to github.com/tomasen/fcgi_client
// (well-tested); BEGIN_REQUEST uses flags=0 (no KEEP_CONN) because php-fpm's
// default config closes the socket per request, and a reuse pool caused spurious
// 502s (RST mid-request). HTTP keep-alive is served on the client side so
// oha/FTW reuse one TCP connection for many requests.
//
// This is a TEST HARNESS, not production: no TLS, runs as root to bind :80.
// Never expose it publicly.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	fcgiclient "github.com/tomasen/fcgi_client"
)

var (
	docRoot    = getenv("DOC_ROOT", "/var/www/html")
	fpmHost    = getenv("FPM_HOST", "php-fpm")
	fpmPort    = getenv("FPM_PORT", "9000")
	listenHost = getenv("LISTEN_HOST", "0.0.0.0")
	listenPort = getenv("LISTEN_PORT", "80")
	indexFile  = getenv("INDEX_FILE", "index.php")
	// Cap in-flight FPM dials so we don't exceed pm.max_children. Default 64
	// (see etc/php-fpm.d/zz-pool.conf). Set FPM_TOTAL to match max_children.
	fpmTotal = atoiDefault(getenv("FPM_TOTAL", "64"), 64)

	// Pre-computed once at startup (were recomputed per request):
	//   fpmAddr     — net.JoinHostPort(fpmHost, fpmPort)
	//   absRoot     — filepath.Abs(docRoot) (+ trailing separator for prefix test)
	//   indexScript — filepath.Join(docRoot, indexFile) (the front-controller)
	fpmAddr     = net.JoinHostPort(fpmHost, fpmPort)
	absRoot     = absRootForDocRoot()
	indexScript = filepath.Join(docRoot, indexFile)
)

// absRootForDocRoot returns the absolute docroot with a trailing separator so
// the escape check in resolveScript is a single strings.HasPrefix (no per-request
// allocation of separator concatenation).
func absRootForDocRoot() string {
	a, err := filepath.Abs(docRoot)
	if err != nil {
		a = docRoot
	}
	return a + string(filepath.Separator)
}

const (
	readTimeoutSec = 60
	recvBuf        = 65536
)

// fpmGate caps in-flight FastCGI connections (a semaphore, NOT a pool — see the
// module doc: php-fpm closes per request, so reuse pools cause RST/502).
var fpmGate = make(chan struct{}, fpmTotal)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func atoiDefault(s string, d int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return d
	}
	return n
}

// ---------------------------------------------------------------------------
// Lenient HTTP request parsing (DO NOT MAKE STRICT — see module doc)
// ---------------------------------------------------------------------------

// headerVal returns the first value for a case-insensitive header name.
func headerVal(headers [][2]string, name string) string {
	lname := strings.ToLower(name)
	for _, h := range headers {
		if strings.ToLower(h[0]) == lname {
			return h[1]
		}
	}
	return ""
}

// wantsClose reports whether the client asked to close after this request
// (HTTP/1.1 keep-alive is default; HTTP/1.0 close is default).
func wantsClose(version string, headers [][2]string) bool {
	conn := strings.ToLower(headerVal(headers, "connection"))
	if strings.Contains(conn, "close") {
		return true
	}
	if strings.EqualFold(version, "HTTP/1.0") {
		return !strings.Contains(conn, "keep-alive")
	}
	return false
}

// readRequest reads one HTTP request leniently. Returns method/target/version/
// headers/body, or ok=false on a clean EOF or unrecoverable framing error.
// Accepts any method token, does not URL-decode the target, does not validate
// Host, does not emit 100-continue (FTW takes the first status line).
func readRequest(br *bufio.Reader) (method, target, version string, headers [][2]string, body []byte, ok bool) {
	// Read until end of headers (\r\n\r\n). The first Read may return EOF if the
	// client closed after the previous keep-alive response — that is a clean EOF.
	var buf bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", "", nil, nil, false
		}
		buf.WriteString(line)
		if buf.Len() > 1<<20 { // header bomb guard
			return "", "", "", nil, nil, false
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	lines := strings.Split(buf.String(), "\r\n")
	if len(lines) == 0 {
		return "", "", "", nil, nil, false
	}
	// The last element is "" (the trailing \r\n\r\n left an empty split tail);
	// drop a trailing "" so the header loop below doesn't see a phantom line.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return "", "", "", nil, nil, false
	}
	method = parts[0]
	target = parts[1]
	if len(parts) > 2 {
		version = parts[2]
	} else {
		version = "HTTP/1.1"
	}

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		ci := strings.IndexByte(line, ':')
		if ci < 0 {
			continue
		}
		name := strings.TrimSpace(line[:ci])
		value := strings.TrimLeft(line[ci+1:], " \t")
		headers = append(headers, [2]string{name, value})
	}

	// Determine body length.
	cl := headerVal(headers, "content-length")
	te := strings.ToLower(headerVal(headers, "transfer-encoding"))
	if strings.Contains(te, "chunked") {
		body = readChunked(br)
	} else if cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n > 0 {
			body = make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				// Short read: keep what we got.
				body = body[:len(body):len(body)]
			}
		}
	}
	// else: no body (FTW/oha always send Content-Length on POSTs).

	return method, target, version, headers, body, true
}

// readChunked dechunks a Transfer-Encoding: chunked body from the reader.
func readChunked(br *bufio.Reader) []byte {
	var out bytes.Buffer
	for {
		sizeLine, err := br.ReadString('\n')
		if err != nil {
			return out.Bytes()
		}
		sizeLine = strings.TrimRight(sizeLine, "\r\n")
		if i := strings.IndexByte(sizeLine, ';'); i >= 0 {
			sizeLine = sizeLine[:i]
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil {
			return out.Bytes()
		}
		if n == 0 {
			// trailing CRLF after the 0-size chunk
			_, _ = br.ReadString('\n')
			return out.Bytes()
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return out.Bytes()
		}
		out.Write(chunk)
		_, _ = br.ReadString('\n') // trailing CRLF
	}
}

// ---------------------------------------------------------------------------
// Routing + FastCGI param construction
// ---------------------------------------------------------------------------

// resolveScript maps a request target to (scriptFilename, scriptName) with a
// front-controller fallback: a non-existent file routes to index.php so PHP
// userland always runs (and the WAF hook fires) while REQUEST_URI keeps the
// original path so path rules still match.
//
// Path safety: never serve a file outside docRoot (rejects ../../etc/passwd
// style targets by falling through to the front controller, where the WAF
// path/args rules then inspect the original REQUEST_URI).
func resolveScript(target string) (string, string) {
	path := target
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	rel := strings.TrimLeft(path, "/")
	candidate := filepath.Join(docRoot, filepath.Clean("/"+rel))
	// Ensure the candidate did not escape docRoot. absRoot already has a
	// trailing separator, so HasPrefix(candidate, absRoot) is the escape test.
	if !strings.HasPrefix(candidate+string(filepath.Separator), absRoot) {
		return indexScript, path
	}
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate, path
	}
	return indexScript, path
}

// buildParams constructs the FastCGI (CGI/1.1) params map from the raw request.
// REQUEST_URI is the raw target verbatim; HTTP_* headers preserve duplicates by
// joining with ", " (CGI convention); CONTENT_TYPE/CONTENT_LENGTH use no prefix.
func buildParams(method, target, version string, headers [][2]string, body []byte, clientAddr string, clientPort string) map[string]string {
	scriptFilename, scriptName := resolveScript(target)
	pathOnly, query := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		pathOnly, query = target[:i], target[i+1:]
	}
	serverName := "localhost"
	// Single pass over headers: collect HTTP_* params, and capture the special
	// CGI headers (Host/Content-Type/Content-Length) without re-scanning.
	// Pre-size to the worst case (static keys + 1 per header) to avoid rehash.
	p := make(map[string]string, 16+len(headers))
	p["GATEWAY_INTERFACE"] = "CGI/1.1"
	p["SERVER_PROTOCOL"] = version
	p["SERVER_SOFTWARE"] = "waf-bridge/2.0"
	p["REQUEST_METHOD"] = method
	p["REQUEST_URI"] = target // raw, undecoded, incl. query string
	p["QUERY_STRING"] = query
	p["DOCUMENT_ROOT"] = docRoot
	p["DOCUMENT_URI"] = pathOnly
	p["SCRIPT_NAME"] = scriptName
	p["SCRIPT_FILENAME"] = scriptFilename
	p["REMOTE_ADDR"] = clientAddr
	p["REMOTE_PORT"] = clientPort
	p["SERVER_ADDR"] = "127.0.0.1"
	p["SERVER_PORT"] = listenPort
	p["REDIRECT_STATUS"] = "200" // required by php-fpm security model

	var clHeader string
	// group order for duplicate HTTP_* headers (CGI/1.1 joins with ", ").
	grouped := make(map[string][]string, len(headers))
	order := make([]string, 0, len(headers))
	for _, h := range headers {
		name := strings.ToLower(h[0])
		switch name {
		case "content-type":
			p["CONTENT_TYPE"] = h[1]
			continue
		case "content-length":
			clHeader = h[1]
			continue
		case "host":
			serverName = h[1]
		}
		key := "HTTP_" + strings.ToUpper(strings.ReplaceAll(h[0], "-", "_"))
		if _, seen := grouped[key]; !seen {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], h[1])
	}
	p["SERVER_NAME"] = serverName

	if clHeader != "" {
		p["CONTENT_LENGTH"] = clHeader
	} else if len(body) > 0 {
		p["CONTENT_LENGTH"] = strconv.Itoa(len(body))
	}
	for _, key := range order {
		p[key] = strings.Join(grouped[key], ", ")
	}

	return p
}

// ---------------------------------------------------------------------------
// FastCGI request (per-request dial; flags=0)
// ---------------------------------------------------------------------------

// fpmRequest dials php-fpm, sends the request, and returns the raw CGI/1.1
// STDOUT bytes (headers + blank line + body) plus any STDERR. A fresh
// connection is used per call (php-fpm's default config closes after each
// request; a reuse pool caused spurious 502s). Concurrency is capped by fpmGate
// so pm.max_children isn't exceeded.
//
// NB: we use fcgi_client.Do (raw STDOUT reader), NOT Request — Request assumes
// the CGI output begins with an HTTP status line ("HTTP/1.1 200 OK"), but
// php-fpm CGI output uses a "Status:" HEADER instead. Reading raw STDOUT and
// parsing the CGI headers ourselves (see writeHTTPResponse) is correct.
//
// LIMITATION: fcgi_client.Do's reader does not separate FCGI_STDERR from
// FCGI_STDOUT (both stream into the returned reader). The test endpoints don't
// emit FPM STDERR in practice (PHP notices/deprecations go to FPM's error log,
// not the FastCGI STDERR stream), so this is low-risk. If a request ever
// triggers FPM-level STDERR, its bytes would be prepended to the CGI output and
// the status-line parse in writeHTTPResponse would fall back to raw 200 output.
func fpmRequest(params map[string]string, body []byte) ([]byte, []byte, error) {
	fpmGate <- struct{}{}
	defer func() { <-fpmGate }()

	fcgi, err := fcgiclient.DialTimeout("tcp", fpmAddr, time.Duration(readTimeoutSec)*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("fcgi dial: %w", err)
	}
	defer fcgi.Close()

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	r, err := fcgi.Do(params, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("fcgi do: %w", err)
	}
	stdout, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("fcgi read: %w", err)
	}
	return stdout, nil, nil
}

// ---------------------------------------------------------------------------
// CGI/1.1 response -> HTTP response bytes
// ---------------------------------------------------------------------------

var (
	badGateway = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
)

// writeHTTPResponse translates php-fpm's raw CGI/1.1 STDOUT (headers + blank
// line + body) into an HTTP response on w. keepAlive controls the Connection
// header and forces a correct Content-Length so the client can frame the next
// request. The CGI "Status:" header (e.g. "403 Forbidden") becomes the HTTP
// status line; it is not re-emitted as a response header.
//
// PERF: avoids fmt.Fprintf (reflection + format parse) by building the status
// line and Content-Length with strconv.AppendInt / direct WriteString.
func writeHTTPResponse(w io.Writer, stdout []byte, keepAlive bool) error {
	sep := bytes.Index(stdout, []byte("\r\n\r\n"))
	var head, body []byte
	if sep < 0 {
		if sep = bytes.Index(stdout, []byte("\n\n")); sep < 0 {
			// No header terminator: emit as 200 with the raw bytes.
			return writeRaw(w, stdout, keepAlive)
		}
		head = stdout[:sep]
		body = stdout[sep+2:]
	} else {
		head = stdout[:sep]
		body = stdout[sep+4:]
	}

	statusCode := 200
	statusText := "OK"
	var outHeaders [][2]string
	haveCL := false
	for _, line := range splitCRLF(head) {
		if len(line) == 0 {
			continue
		}
		ci := bytes.IndexByte(line, ':')
		if ci < 0 {
			continue
		}
		name := strings.TrimSpace(string(line[:ci]))
		value := strings.TrimSpace(string(line[ci+1:]))
		lname := strings.ToLower(name)
		if lname == "status" {
			// e.g. "403 Forbidden"
			bits := strings.SplitN(value, " ", 2)
			if n, err := strconv.Atoi(bits[0]); err == nil {
				statusCode = n
			}
			if len(bits) > 1 {
				statusText = bits[1]
			}
			continue // don't re-emit Status: as a response header
		}
		if lname == "content-length" {
			haveCL = true
		}
		if lname == "connection" {
			continue // we set Connection ourselves
		}
		outHeaders = append(outHeaders, [2]string{name, value})
	}

	var buf bytes.Buffer

	// Status line: "HTTP/1.1 <code> <text>\r\n" — built without fmt.
	buf.WriteString("HTTP/1.1 ")
	buf.Write(strconv.AppendInt(buf.AvailableBuffer(), int64(statusCode), 10))
	buf.WriteByte(' ')
	buf.WriteString(statusText)
	buf.WriteString("\r\n")
	for _, h := range outHeaders {
		buf.WriteString(h[0])
		buf.WriteString(": ")
		buf.WriteString(h[1])
		buf.WriteString("\r\n")
	}
	if !haveCL {
		buf.WriteString("Content-Length: ")
		buf.Write(strconv.AppendInt(buf.AvailableBuffer(), int64(len(body)), 10))
		buf.WriteString("\r\n")
	}
	if keepAlive {
		buf.WriteString("Connection: keep-alive\r\n\r\n")
	} else {
		buf.WriteString("Connection: close\r\n\r\n")
	}
	buf.Write(body)
	_, err := w.Write(buf.Bytes())
	return err
}

// writeRaw emits stdout as a 200 with the bytes as the body (used when CGI
// output has no header terminator).
func writeRaw(w io.Writer, stdout []byte, keepAlive bool) error {
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: ")
	buf.Write(strconv.AppendInt(buf.AvailableBuffer(), int64(len(stdout)), 10))
	buf.WriteString("\r\n")
	if keepAlive {
		buf.WriteString("Connection: keep-alive\r\n\r\n")
	} else {
		buf.WriteString("Connection: close\r\n\r\n")
	}
	buf.Write(stdout)
	_, err := w.Write(buf.Bytes())
	return err
}

// splitCRLF splits head (which may use \r\n or \n) into header lines.
func splitCRLF(head []byte) [][]byte {
	var lines [][]byte
	if bytes.Contains(head, []byte("\r\n")) {
		for _, l := range bytes.Split(head, []byte("\r\n")) {
			lines = append(lines, l)
		}
	} else {
		for _, l := range bytes.Split(head, []byte("\n")) {
			lines = append(lines, l)
		}
	}
	return lines
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

func handle(conn net.Conn) {
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(false)
	}
	br := bufio.NewReaderSize(conn, recvBuf)

	// Client addr/port are constant for the connection; compute once, not per
	// keep-alive request. Avoids RemoteAddr().String() + SplitHostPort (string
	// parse + alloc) per request.
	clientAddr, clientPort := connAddr(conn.RemoteAddr())

	for {
		method, target, version, headers, body, ok := readRequest(br)
		if !ok {
			return // clean EOF or framing error
		}
		closeAfter := wantsClose(version, headers)

		params := buildParams(method, target, version, headers, body, clientAddr, clientPort)

		stdout, _, err := fpmRequest(params, body)
		if err != nil {
			log.Printf("[bridge] upstream error: %v", err)
			_, _ = conn.Write(badGateway)
			return
		}
		if err := writeHTTPResponse(conn, stdout, !closeAfter); err != nil {
			log.Printf("[bridge] response write error: %v", err)
			return
		}
		if closeAfter {
			return
		}
	}
}

// connAddr returns (ip, port) from a net.Addr without stringifying+parsing.
// Falls back to the raw address string if the concrete type is unknown.
func connAddr(a net.Addr) (string, string) {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.String(), strconv.Itoa(ta.Port)
	}
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), "0"
	}
	return host, port
}

func main() {
	// GOMAXPROCS defaults to NumCPU; Go uses all cores natively (no GIL).
	addr := net.JoinHostPort(listenHost, listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[bridge] listen %s: %v", addr, err)
	}
	log.Printf("[bridge] listening on %s, fastcgi %s:%s, docroot %s, fpm_gate=%d",
		addr, fpmHost, fpmPort, docRoot, fpmTotal)

	// One goroutine per connection; the Go scheduler multiplexes them across
	// all CPU cores. No prefork / SO_REUSEPORT needed (no GIL).
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[bridge] accept error: %v", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle(conn)
		}()
	}
}
