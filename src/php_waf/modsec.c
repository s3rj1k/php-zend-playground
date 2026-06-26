#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "SAPI.h"
#include "ext/standard/head.h"
#include "zend_compile.h"
#include "modsec.h"
#include "php_waf.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* C++ headers for ModSecurity */
#ifdef __cplusplus
extern "C" {
#endif

/* msc_set_request_hostname needs libmodsecurity >= 3.0.13. Older builds
 * (Debian bookworm 3.0.9) lack the symbol, so never reference it or waf.so
 * fails to dlopen. SERVER_NAME is derived from Host by libmodsecurity. */

/* ============================================================================
 * Per Process ModSecurity State
 * ============================================================================ */

static ModSecurity *g_modsec = NULL;
static RulesSet *g_rules = NULL;
static zend_bool g_modsec_initialized = 0;
static unsigned long g_transaction_counter = 0;

/* ============================================================================
 * Log Callback
 * ============================================================================ */

static void modsec_log_callback(void *data, const void *rule_message) {
    (void)data;
    if (rule_message != NULL) {
        const char *msg = (const char *)rule_message;
        php_error(E_WARNING, "waf: ModSecurity: %s", msg);
    }
}

/* ============================================================================
 * HTTP Error Response
 * ============================================================================ */

void waf_send_block_response(int status_code) {
    const char *status_text = "Forbidden";

    switch (status_code) {
        case WAF_HTTP_STATUS_BAD_REQUEST: status_text = "Bad Request"; break;
        case WAF_HTTP_STATUS_FORBIDDEN: status_text = "Forbidden"; break;
        case WAF_HTTP_STATUS_NOT_FOUND: status_text = "Not Found"; break;
        case WAF_HTTP_STATUS_SERVER_ERROR: status_text = "Internal Server Error"; break;
        case 301: status_text = "Moved Permanently"; break;
        case 302: status_text = "Found"; break;
        case 307: status_text = "Temporary Redirect"; break;
        case 308: status_text = "Permanent Redirect"; break;
    }

    /* Emit the full HTTP response via original ub_write, bypassing the PHP
     * output layer and our hook. While a transaction is active waf_ub_write
     * buffers into response_body, so headers would be swallowed and the HTTP
     * front-end would see only the HTML body as a header and return 502.
     * Writing everything through original_ub_write keeps the Status, headers
     * and body ordered for both the request phase block and the RSHUTDOWN
     * block. */
    size_t (*orig_write)(const char *, size_t) = waf_original_ub_write();
    if (orig_write == NULL) {
        orig_write = sapi_module.ub_write;
    }

    char hdr[640];
    int hlen;

    /* Handle redirect if intervention URL is set. */
    if (WAF_G(intervention).url != NULL) {
        hlen = snprintf(hdr, sizeof(hdr),
                        "Status: %d %s\r\n"
                        "Location: %s\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        "\r\n",
                        status_code, status_text, WAF_G(intervention).url);
        if (hlen > 0 && (size_t)hlen < sizeof(hdr)) {
            orig_write(hdr, (size_t)hlen);
        }
        SG(sapi_headers).http_response_code = status_code;
        SG(headers_sent) = 1;
        return;
    }

    /* Build response body. */
    char *body = NULL;
    int blen = spprintf(&body, 0,
             "<!DOCTYPE html>\n<html>\n<head><title>%d %s</title></head>\n"
             "<body>\n<h1>%d %s</h1>\n"
             "<p>Request blocked by ModSecurity Web Application Firewall.</p>\n"
             "<p>Transaction ID: %s</p>\n</body>\n</html>\n",
             status_code, status_text, status_code, status_text,
             WAF_G(transaction_id) ? WAF_G(transaction_id) : "unknown");

    /* Status line and Content Type. */
    hlen = snprintf(hdr, sizeof(hdr),
                    "Status: %d %s\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n",
                    status_code, status_text);
    if (hlen > 0 && (size_t)hlen < sizeof(hdr)) {
        orig_write(hdr, (size_t)hlen);
    }

    /* Optional Transaction ID header. */
    if (WAF_G(transaction_id) != NULL) {
        char txh[256];
        int txl = snprintf(txh, sizeof(txh), "X-Transaction-Id: %s\r\n",
                           WAF_G(transaction_id));
        if (txl > 0 && (size_t)txl < sizeof(txh)) {
            orig_write(txh, (size_t)txl);
        }
    }

    /* Blank line terminates the header section, then the body. */
    orig_write("\r\n", 2);
    if (blen > 0 && body != NULL) {
        orig_write(body, (size_t)blen);
    }
    if (body != NULL) {
        efree(body);
    }

    /* Mark headers sent so shutdown does not emit a second default 200 frame. */
    SG(sapi_headers).http_response_code = status_code;
    SG(headers_sent) = 1;
}

/* ============================================================================
 * Module Lifecycle Functions
 * ============================================================================ */

int waf_modsec_init(void) {
    const char *error = NULL;
    int ret = 0;
    char *seclang_config = NULL;

    if (g_modsec_initialized) return 0;
    if (!WAF_G(enabled)) return 0;

    g_modsec = msc_init();
    if (g_modsec == NULL) {
        php_error(E_WARNING, "waf: Failed to initialize ModSecurity");
        return -1;
    }

    msc_set_connector_info(g_modsec, "PHP waf extension v" PHP_WAF_VERSION);
    msc_set_log_cb(g_modsec, modsec_log_callback);

    g_rules = msc_create_rules_set();
    if (g_rules == NULL) {
        php_error(E_WARNING, "waf: Failed to create ModSecurity rules set");
        msc_cleanup(g_modsec);
        g_modsec = NULL;
        return -1;
    }

    /* Debug and audit logging are SecLang directives with no C API, so inject
     * them as an inline snippet before the user rules. */
    seclang_config = estrdup("");
    if (WAF_G(modsec_debug_log) != NULL && WAF_G(modsec_debug_log)[0] != '\0') {
        char *tmp = NULL;
        spprintf(&tmp, 0, "%sSecDebugLog %s\nSecDebugLogLevel %ld\n", seclang_config,
                 WAF_G(modsec_debug_log), (long)WAF_G(modsec_debug_level));
        efree(seclang_config);
        seclang_config = tmp;
    }
    if (WAF_G(modsec_audit_log) != NULL && WAF_G(modsec_audit_log)[0] != '\0') {
        char *tmp = NULL;
        spprintf(&tmp, 0, "%sSecAuditEngine On\nSecAuditLog %s\n", seclang_config,
                 WAF_G(modsec_audit_log));
        efree(seclang_config);
        seclang_config = tmp;
        if (WAF_G(modsec_audit_log_parts) != NULL &&
            WAF_G(modsec_audit_log_parts)[0] != '\0') {
            char *tmp2 = NULL;
            spprintf(&tmp2, 0, "%sSecAuditLogParts %s\n", seclang_config,
                     WAF_G(modsec_audit_log_parts));
            efree(seclang_config);
            seclang_config = tmp2;
        }
    }

    if (seclang_config != NULL && seclang_config[0] != '\0') {
        ret = msc_rules_add(g_rules, seclang_config, &error);
        if (ret < 0) {
            php_error(E_WARNING, "waf: Failed to configure ModSecurity logging: %s",
                      error ? error : "unknown error");
            efree(seclang_config);
            msc_rules_cleanup(g_rules);
            msc_cleanup(g_modsec);
            g_rules = NULL;
            g_modsec = NULL;
            return -1;
        }
    }
    efree(seclang_config);

    if (WAF_G(modsec_rules_file) != NULL && strlen(WAF_G(modsec_rules_file)) > 0) {
        ret = msc_rules_add_file(g_rules, WAF_G(modsec_rules_file), &error);
        if (ret < 0) {
            php_error(E_WARNING, "waf: Failed to load rules from file: %s",
                      error ? error : "unknown error");
            msc_rules_cleanup(g_rules);
            msc_cleanup(g_modsec);
            g_rules = NULL;
            g_modsec = NULL;
            return -1;
        }
    }

    if (WAF_G(modsec_rules_inline) != NULL && strlen(WAF_G(modsec_rules_inline)) > 0) {
        ret = msc_rules_add(g_rules, WAF_G(modsec_rules_inline), &error);
        if (ret < 0) {
            php_error(E_WARNING, "waf: Failed to load inline rules: %s",
                      error ? error : "unknown error");
            msc_rules_cleanup(g_rules);
            msc_cleanup(g_modsec);
            g_rules = NULL;
            g_modsec = NULL;
            return -1;
        }
    }

    g_modsec_initialized = 1;
    php_error(E_NOTICE, "waf: ModSecurity initialized successfully");
    return 0;
}

void waf_modsec_shutdown(void) {
    if (!g_modsec_initialized) return;

    if (g_rules != NULL) {
        msc_rules_cleanup(g_rules);
        g_rules = NULL;
    }
    if (g_modsec != NULL) {
        msc_cleanup(g_modsec);
        g_modsec = NULL;
    }
    g_modsec_initialized = 0;
}

zend_bool waf_modsec_is_enabled(void) {
    return g_modsec_initialized && g_modsec != NULL && g_rules != NULL;
}

/* ============================================================================
 * Transaction Lifecycle Functions
 * ============================================================================ */

static void generate_transaction_id(char *buf, size_t buf_len) {
    struct timeval tv;
    unsigned long seq;
    gettimeofday(&tv, NULL);
#if defined(ZTS)
    /* Under a threaded SAPI use an atomic counter so IDs never collide. */
    seq = __atomic_add_fetch(&g_transaction_counter, 1, __ATOMIC_SEQ_CST);
#else
    seq = ++g_transaction_counter;
#endif
    snprintf(buf, buf_len, "%08lx%08lx%08lx",
             (unsigned long)tv.tv_sec,
             (unsigned long)tv.tv_usec,
             seq);
}

Transaction *waf_modsec_transaction_begin(void) {
    Transaction *transaction = NULL;
    char tx_id[WAF_TRANSACTION_ID_LEN + 1] = {0};

    if (!waf_modsec_is_enabled()) return NULL;

    /* Initialize intervention structure */
    WAF_G(intervention).status = WAF_HTTP_STATUS_OK;
    WAF_G(intervention).pause = 0;
    WAF_G(intervention).url = NULL;
    WAF_G(intervention).log = NULL;
    WAF_G(intervention).disruptive = 0;

    /* Generate or use provided transaction ID */
    if (WAF_G(modsec_transaction_id) != NULL && strlen(WAF_G(modsec_transaction_id)) > 0) {
        snprintf(tx_id, sizeof(tx_id), "%s", WAF_G(modsec_transaction_id));
    } else {
        generate_transaction_id(tx_id, sizeof(tx_id));
    }

    /* Store transaction ID */
    if (WAF_G(transaction_id) != NULL) efree(WAF_G(transaction_id));
    WAF_G(transaction_id) = estrndup(tx_id, strlen(tx_id));

    transaction = msc_new_transaction_with_id(g_modsec, g_rules, tx_id, NULL);
    if (transaction == NULL) {
        php_error(E_WARNING, "waf: Failed to create ModSecurity transaction");
        return NULL;
    }

    WAF_G(modsec_transaction) = transaction;
    return transaction;
}

void waf_modsec_transaction_end(void) {
    Transaction *transaction = WAF_G(modsec_transaction);

    if (transaction != NULL) {
        msc_transaction_cleanup(transaction);
        WAF_G(modsec_transaction) = NULL;
    }

    waf_modsec_intervention_cleanup();

    if (WAF_G(transaction_id) != NULL) {
        efree(WAF_G(transaction_id));
        WAF_G(transaction_id) = NULL;
    }
}

const char *waf_modsec_get_transaction_id(void) {
    return WAF_G(transaction_id);
}

/* ============================================================================
 * Connection Phase (Phase 1)
 * ============================================================================ */

int waf_modsec_process_connection(const char *client_ip, int client_port,
                                  const char *server_ip, int server_port) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_connection(transaction, client_ip, client_port, server_ip, server_port);
}

/* ============================================================================
 * URI Phase (Phase 2)
 * ============================================================================ */

int waf_modsec_process_uri(const char *uri, const char *method,
                           const char *http_version) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_uri(transaction, uri, method, http_version);
}

int waf_modsec_set_hostname(const char *hostname) {
#ifdef HAVE_MSC_SET_REQUEST_HOSTNAME
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL || hostname == NULL) return 0;
    return msc_set_request_hostname(transaction, (const unsigned char *)hostname);
#else
    /* Symbol unavailable (libmodsecurity < 3.0.13) SERVER_NAME comes from Host. */
    (void)hostname;
    return 0;
#endif
}

/* ============================================================================
 * Request Headers Phase (Phase 3)
 * ============================================================================ */

int waf_modsec_add_request_header(const char *name, size_t name_len,
                                  const char *value, size_t value_len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_add_n_request_header(transaction, (const unsigned char *)name,
                                    name_len, (const unsigned char *)value, value_len);
}

int waf_modsec_process_request_headers(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_request_headers(transaction);
}

/* ============================================================================
 * Request Body Phase (Phase 4)
 * ============================================================================ */

int waf_modsec_append_request_body(const unsigned char *body, size_t len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_append_request_body(transaction, body, len);
}

int waf_modsec_process_request_body(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_request_body(transaction);
}

/* ============================================================================
 * Response Headers Phase (Phase 5)
 * ============================================================================ */

int waf_modsec_add_response_header(const char *name, size_t name_len,
                                   const char *value, size_t value_len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_add_n_response_header(transaction, (const unsigned char *)name,
                                     name_len, (const unsigned char *)value, value_len);
}

int waf_modsec_process_response_headers(int status_code, const char *protocol) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_response_headers(transaction, status_code, protocol);
}

int waf_modsec_update_status_code(int status) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_update_status_code(transaction, status);
}

/* ============================================================================
 * Response Body Phase (Phase 4)
 * ============================================================================ */

int waf_modsec_append_response_body(const unsigned char *body, size_t len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_append_response_body(transaction, body, len);
}

int waf_modsec_process_response_body(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_response_body(transaction);
}

const char *waf_modsec_get_response_body(size_t *len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL || len == NULL) return NULL;
    *len = msc_get_response_body_length(transaction);
    return msc_get_response_body(transaction);
}

/* ============================================================================
 * Logging Phase (Phase 7)
 * ============================================================================ */

int waf_modsec_process_logging(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_logging(transaction);
}

/* ============================================================================
 * Intervention Handling
 * ============================================================================ */

int waf_modsec_check_intervention(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;

    /* Free previous intervention resources before resetting */
    waf_modsec_intervention_cleanup();

    /* Reset intervention structure */
    WAF_G(intervention).status = WAF_HTTP_STATUS_OK;
    WAF_G(intervention).pause = 0;
    WAF_G(intervention).disruptive = 0;
    WAF_G(intervention).url = NULL;
    WAF_G(intervention).log = NULL;

    if (msc_intervention(transaction, &WAF_G(intervention))) {
        if (WAF_G(intervention).disruptive) {
            return WAF_G(intervention).status > 0
                       ? (int)WAF_G(intervention).status
                       : (int)WAF_G(modsec_block_status);
        }
    }
    return 0;
}

const char *waf_modsec_get_intervention_log(void) {
    return WAF_G(intervention).log;
}

const char *waf_modsec_get_intervention_url(void) {
    return WAF_G(intervention).url;
}

int waf_modsec_get_intervention_status(void) {
    return WAF_G(intervention).status > 0
               ? (int)WAF_G(intervention).status
               : (int)WAF_G(modsec_block_status);
}

void waf_modsec_intervention_cleanup(void) {
    if (WAF_G(intervention).url != NULL) {
        free(WAF_G(intervention).url);
        WAF_G(intervention).url = NULL;
    }
    if (WAF_G(intervention).log != NULL) {
        free(WAF_G(intervention).log);
        WAF_G(intervention).log = NULL;
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *waf_get_client_ip(void) {
    zval *server_vars = NULL;
    zval *forwarded_for = NULL;
    zval *remote_addr = NULL;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return "127.0.0.1";
    }

    /* Use X Forwarded For only when trusted, taking the leftmost (original
     * client) entry since the header is fully client controlled. */
    if (WAF_G(trust_proxy_headers)) {
        forwarded_for = zend_hash_str_find(Z_ARRVAL_P(server_vars), "HTTP_X_FORWARDED_FOR",
                                           sizeof("HTTP_X_FORWARDED_FOR") - 1);
        if (forwarded_for != NULL && Z_TYPE_P(forwarded_for) == IS_STRING &&
            Z_STRLEN_P(forwarded_for) > 0) {
            /* XFF may be "client, proxy1, proxy2" take the first token. */
            const char *xff = Z_STRVAL_P(forwarded_for);
            const char *comma = strchr(xff, ',');
            size_t ip_len = comma != NULL ? (size_t)(comma - xff) : Z_STRLEN_P(forwarded_for);
            /* Trim trailing whitespace. */
            while (ip_len > 0 && (xff[ip_len - 1] == ' ' || xff[ip_len - 1] == '\t')) {
                ip_len--;
            }
            if (ip_len > 0) {
                static char client_ip[64];
                size_t copy_len = ip_len < sizeof(client_ip) - 1 ? ip_len : sizeof(client_ip) - 1;
                /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
                memcpy(client_ip, xff, copy_len);
                client_ip[copy_len] = '\0';
                return client_ip;
            }
        }
    }

    /* Fall back to REMOTE_ADDR */
    remote_addr = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REMOTE_ADDR",
                                     sizeof("REMOTE_ADDR") - 1);
    if (remote_addr != NULL && Z_TYPE_P(remote_addr) == IS_STRING) {
        return Z_STRVAL_P(remote_addr);
    }

    return "127.0.0.1";
}

int waf_get_client_port(void) {
    zval *server_vars = NULL;
    zval *remote_port = NULL;
    long port = 0;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return 0;
    }

    remote_port = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REMOTE_PORT",
                                     sizeof("REMOTE_PORT") - 1);
    if (remote_port != NULL && Z_TYPE_P(remote_port) == IS_STRING) {
        port = strtol(Z_STRVAL_P(remote_port), NULL, 10);
        return (port > 0 && port <= WAF_MAX_PORT_NUMBER) ? (int)port : 0;
    }

    return 0;
}

const char *waf_get_server_ip(void) {
    zval *server_vars = NULL;
    zval *server_addr = NULL;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return "127.0.0.1";
    }

    server_addr = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_ADDR",
                                     sizeof("SERVER_ADDR") - 1);
    if (server_addr != NULL && Z_TYPE_P(server_addr) == IS_STRING) {
        return Z_STRVAL_P(server_addr);
    }

    return "127.0.0.1";
}

int waf_get_server_port(void) {
    zval *server_vars = NULL;
    zval *server_port = NULL;
    long port = 0;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return WAF_DEFAULT_HTTP_PORT;
    }

    server_port = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_PORT",
                                     sizeof("SERVER_PORT") - 1);
    if (server_port != NULL && Z_TYPE_P(server_port) == IS_STRING) {
        port = strtol(Z_STRVAL_P(server_port), NULL, 10);
        return (port > 0 && port <= WAF_MAX_PORT_NUMBER) ? (int)port : WAF_DEFAULT_HTTP_PORT;
    }

    return WAF_DEFAULT_HTTP_PORT;
}

const char *waf_get_http_version(void) {
    zval *server_vars = NULL;
    zval *protocol = NULL;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return "1.1";
    }

    protocol = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_PROTOCOL",
                                  sizeof("SERVER_PROTOCOL") - 1);
    if (protocol != NULL && Z_TYPE_P(protocol) == IS_STRING) {
        const char *proto = Z_STRVAL_P(protocol);
        if (strncmp(proto, "HTTP/", WAF_HTTP_PREFIX_LEN) == 0) {
            return proto + WAF_HTTP_PREFIX_LEN;
        }
        return proto;
    }

    return "1.1";
}

/* ============================================================================
 * High Level Request Processing
 * ============================================================================ */

int waf_modsec_process_request(void) {
    Transaction *transaction = NULL;
    zval *server_vars = NULL;
    zend_string *key = NULL;
    zval *val = NULL;
    int intervention_status = 0;
    const char *client_ip = NULL;
    int client_port = 0;
    const char *server_ip = NULL;
    const char *request_uri = NULL;
    const char *request_method = NULL;
    const char *http_version = NULL;
    const char *server_name = NULL;
    int server_port = 0;

    if (!waf_modsec_is_enabled()) return 0;

    /* Force the $_SERVER auto global to be populated NOW. Under
     * auto_globals_jit=On (the PHP default) $_SERVER is realized lazily on the
     * script's first reference to it, but waf_execute_ex fires on the first
     * userland opcode, BEFORE that reference runs. Reading $_SERVER here
     * otherwise yields a stale/empty symbol table, so every request looks like
     * "GET /" from 127.0.0.1 with no User-Agent -> rule 1027 false-positives on
     * benign endpoints that never touch $_SERVER directly. zend_is_auto_global_str
     * runs the JIT callback to populate EG(symbol_table) regardless of jit. */
    zend_is_auto_global_str(ZEND_STRL("_SERVER"));

    /* Create transaction */
    transaction = waf_modsec_transaction_begin();
    if (transaction == NULL) return 0;

    /* Get connection info */
    client_ip = waf_get_client_ip();
    client_port = waf_get_client_port();
    server_ip = waf_get_server_ip();
    server_port = waf_get_server_port();

    /* Process connection phase */
    waf_modsec_process_connection(client_ip, client_port, server_ip, server_port);

    /* Get request info from $_SERVER */
    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);

    request_uri = "/";
    request_method = "GET";
    http_version = waf_get_http_version();
    server_name = "localhost";

    if (server_vars != NULL && Z_TYPE_P(server_vars) == IS_ARRAY) {
        zval *uri_val = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REQUEST_URI",
                                           sizeof("REQUEST_URI") - 1);
        if (uri_val != NULL && Z_TYPE_P(uri_val) == IS_STRING) {
            request_uri = Z_STRVAL_P(uri_val);
        }

        zval *method_val = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REQUEST_METHOD",
                                              sizeof("REQUEST_METHOD") - 1);
        if (method_val != NULL && Z_TYPE_P(method_val) == IS_STRING) {
            request_method = Z_STRVAL_P(method_val);
        }

        zval *name_val = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_NAME",
                                            sizeof("SERVER_NAME") - 1);
        if (name_val != NULL && Z_TYPE_P(name_val) == IS_STRING) {
            server_name = Z_STRVAL_P(name_val);
        }
    }

    /* Set hostname */
    waf_modsec_set_hostname(server_name);

    /* Process URI phase */
    waf_modsec_process_uri(request_uri, request_method, http_version);

    /* Check intervention after URI/connection phases (phase 1 rules) */
    intervention_status = waf_modsec_check_intervention();
    if (intervention_status > 0) {
        return intervention_status;
    }

    /* Add request headers from $_SERVER (HTTP_* entries) */
    if (server_vars != NULL && Z_TYPE_P(server_vars) == IS_ARRAY) {
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(server_vars), key, val) {
            if (key == NULL) continue;
            if (strncmp(ZSTR_VAL(key), "HTTP_", WAF_HTTP_PREFIX_LEN) != 0) continue;

            /* Convert HTTP_HEADER_NAME to Header Name format */
            const char *header_name = ZSTR_VAL(key) + WAF_HTTP_PREFIX_LEN;
            size_t header_name_len = ZSTR_LEN(key) - WAF_HTTP_PREFIX_LEN;
            char *formatted_name = estrndup(header_name, header_name_len);

            /* Convert underscores to hyphens and proper casing */
            for (size_t i = 0; i < header_name_len; i++) {
                if (formatted_name[i] == '_') {
                    formatted_name[i] = '-';
                } else if (formatted_name[i] >= 'A' && formatted_name[i] <= 'Z') {
                    if (i > 0 && formatted_name[i - 1] != '-') {
                        formatted_name[i] = (char)(formatted_name[i] + WAF_ASCII_UPPERCASE_OFFSET);
                    }
                }
            }

            if (Z_TYPE_P(val) == IS_STRING) {
                waf_modsec_add_request_header(formatted_name, header_name_len,
                                              Z_STRVAL_P(val), Z_STRLEN_P(val));
            }

            efree(formatted_name);
        }
        ZEND_HASH_FOREACH_END();

        /* Forward CONTENT_TYPE/CONTENT_LENGTH only when non empty. PHP FPM
         * always sets them (empty for bodyless GETs), and an empty Content
         * Length trips negated operators like rule 1071 since an empty value
         * fails the positive regex. An absent variable is skipped, so mirror
         * that by forwarding only real values. */
        zval *ct = zend_hash_str_find(Z_ARRVAL_P(server_vars), "CONTENT_TYPE",
                                      sizeof("CONTENT_TYPE") - 1);
        if (ct != NULL && Z_TYPE_P(ct) == IS_STRING && Z_STRLEN_P(ct) > 0) {
            waf_modsec_add_request_header("Content-Type", WAF_CONTENT_TYPE_HEADER_LEN,
                                          Z_STRVAL_P(ct), Z_STRLEN_P(ct));
        }

        zval *cl = zend_hash_str_find(Z_ARRVAL_P(server_vars), "CONTENT_LENGTH",
                                      sizeof("CONTENT_LENGTH") - 1);
        if (cl != NULL && Z_TYPE_P(cl) == IS_STRING && Z_STRLEN_P(cl) > 0) {
            waf_modsec_add_request_header("Content-Length", WAF_CONTENT_LENGTH_HEADER_LEN,
                                          Z_STRVAL_P(cl), Z_STRLEN_P(cl));
        }
    }

    /* Process request headers phase */
    waf_modsec_process_request_headers();

    /* Check intervention after headers */
    intervention_status = waf_modsec_check_intervention();
    if (intervention_status > 0) {
        return intervention_status;
    }

    /* Append request body if available */
    if (WAF_G(request_body) != NULL && ZSTR_LEN(WAF_G(request_body)) > 0) {
        waf_modsec_append_request_body(
            (const unsigned char *)ZSTR_VAL(WAF_G(request_body)),
            ZSTR_LEN(WAF_G(request_body)));
    }

    /* Process request body phase */
    waf_modsec_process_request_body();

    /* Check intervention after body */
    intervention_status = waf_modsec_check_intervention();

    return intervention_status;
}

/* ============================================================================
 * High Level Response Processing
 * ============================================================================ */

int waf_modsec_process_response(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    int intervention_status = 0;
    int response_code = 0;
    const char *http_version = waf_get_http_version();
    sapi_header_struct *h = NULL;

    if (transaction == NULL) return 0;

    /* Get response code */
    response_code = SG(sapi_headers).http_response_code;
    if (response_code == 0) {
        response_code = WAF_HTTP_STATUS_OK;
    }

    /* Add response headers from SAPI */
    h = zend_llist_get_first(&SG(sapi_headers).headers);
    while (h != NULL) {
        char *colon = strchr(h->header, ':');
        if (colon != NULL) {
            size_t name_len = colon - h->header;
            const char *value = colon + 1;
            while (*value == ' ') value++;

            waf_modsec_add_response_header(h->header, name_len, value, strlen(value));
        }
        h = zend_llist_get_next(&SG(sapi_headers).headers);
    }

    /* Process response headers phase */
    waf_modsec_process_response_headers(response_code, http_version);

    /* Check intervention after headers */
    intervention_status = waf_modsec_check_intervention();
    if (intervention_status > 0) {
        /* Defer transaction end and logging to the caller (RSHUTDOWN) so the
         * block response can still read the transaction ID and redirect URL. */
        return intervention_status;
    }

    /* Append response body if available, then evaluate phase 4 body rules.
     * Skipped entirely when response body inspection is disabled
     * (modsec_response_body_limit == 0): nothing was buffered, so there is no
     * body to feed libmodsecurity and RESPONSE_BODY rules cannot fire. */
    if (WAF_G(modsec_response_body_limit) != 0 &&
        WAF_G(response_body) != NULL && ZSTR_LEN(WAF_G(response_body)) > 0) {
        waf_modsec_append_response_body(
            (const unsigned char *)ZSTR_VAL(WAF_G(response_body)),
            ZSTR_LEN(WAF_G(response_body)));
    }

    /* Process response body phase */
    if (WAF_G(modsec_response_body_limit) != 0) {
        waf_modsec_process_response_body();
    }

    /* libmodsecurity may rewrite the body replace our buffer with the
     * transaction's inspected version for RSHUTDOWN to flush. Only meaningful
     * when the body was NOT already streamed to the client on overflow
     * (response_body_sent): once sent, a rewrite cannot be re-delivered, so
     * skip it to avoid a pointless allocation that would never be flushed. */
    if (!WAF_G(response_body_sent) && WAF_G(modsec_response_body_limit) != 0) {
        size_t new_len = 0;
        const char *new_body = waf_modsec_get_response_body(&new_len);
        if (new_body != NULL && new_len > 0) {
            zend_string *replaced = zend_string_init(new_body, new_len, 0);
            if (WAF_G(response_body) != NULL) {
                zend_string_release(WAF_G(response_body));
            }
            WAF_G(response_body) = replaced;
        }
    }

    /* Check intervention after body */
    intervention_status = waf_modsec_check_intervention();

    /* Note logging + transaction end are deferred to the caller (RSHUTDOWN). */
    return intervention_status;
}

#ifdef __cplusplus
}
#endif
