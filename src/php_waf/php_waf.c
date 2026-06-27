#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modsec.h"
#include "php_waf.h"

/* HTTP status constants (local) body size limits live in modsec.h. */
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_FORBIDDEN 403

// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
ZEND_DECLARE_MODULE_GLOBALS(waf)

// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
/* Original execute_ex */
// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
static void (*original_execute_ex)(zend_execute_data *execute_data) = NULL;

/* Original SAPI ub_write for response body capture */
// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
static size_t (*original_ub_write)(const char *str, size_t len) = NULL;

/* Accessor for original ub_write so modsec.c can emit output that must reach
 * the client immediately, bypassing the response body buffer. */
size_t (*waf_original_ub_write(void))(const char *str, size_t str_len) {
  return original_ub_write;
}

/* SAPI ub_write hook capturing the response body for ModSecurity.
 *
 * Buffers the first `modsec_response_body_limit` bytes (default 10MB) of the
 * response for inspection at RSHUTDOWN. Once the limit is reached the buffer is
 * flushed to the client (to preserve output ordering) but RETAINED so it is
 * still fed to libmodsecurity at RSHUTDOWN; `response_body_sent` marks this so
 * RSHUTDOWN does not flush it a second time. All bytes beyond the limit stream
 * straight through (only the leading prefix is inspected, to bound memory).
 *
 * A limit of 0 disables response body inspection entirely: nothing is buffered
 * and everything passes through directly. */
static size_t waf_ub_write(const char *str, size_t len) {
  /* Buffer when the WAF is enabled and body inspection is on (limit != 0) AND
   * we are under the fpm-fcgi SAPI. The fpm-fcgi gate mirrors RINIT/RSHUTDOWN:
   * under CLI (e.g. `php -m`, `php -i`) waf.enabled may still be 1 (the conf.d
   * INI is shared), but no transaction is ever created and RSHUTDOWN does NOT
   * flush (it early-returns for non-fpm SAPIs). Buffering CLI output would then
   * swallow it entirely (e.g. an empty `php -m`), so never buffer off-FPM.
   *
   * Buffering is NOT gated on an active transaction. Output emitted BEFORE the
   * transaction is created must also be buffered: PHP reads POST data during
   * sapi_activate (before waf_RINIT), so a malformed multipart body raises
   * "Missing boundary in multipart/form-data POST data" as an E_WARNING that
   * reaches ub_write before waf_execute_ex runs. If that warning streams to the
   * client, it precedes a later WAF block response's Status header and corrupts
   * the client's status-line parse (the request is framed as 200). Buffering it
   * lets the block path (waf_execute_ex) discard it, or RSHUTDOWN flush it on
   * allow. Do NOT key this on modsec_processed: that flag is reset in RINIT,
   * which runs AFTER sapi_activate, so it is stale (==1 from the prior request)
   * on warm workers and would let the warning leak on the 2nd+ request.
   *
   * The response_body_sent overflow path and RSHUTDOWN flush handle the rest. */
  if (WAF_G(enabled) && WAF_G(modsec_response_body_limit) != 0 &&
      strcmp(sapi_module.name, "fpm-fcgi") == 0) {

    /* Buffer already flushed on overflow: pass everything through directly.
     * The retained prefix is inspected at RSHUTDOWN but not re-delivered. */
    if (WAF_G(response_body_sent)) {
      return original_ub_write(str, len);
    }

    size_t current_len = WAF_G(response_body) ? ZSTR_LEN(WAF_G(response_body)) : 0;
    size_t max_size = (size_t)WAF_G(modsec_response_body_limit);

    if (current_len < max_size) {
      size_t remaining = max_size - current_len;
      size_t to_buffer = (len < remaining) ? len : remaining;

      /* Buffer this chunk for inspection up to max_size */
      if (WAF_G(response_body) == NULL) {
        WAF_G(response_body) = zend_string_init(str, to_buffer, 0);
      } else {
        WAF_G(response_body) =
            zend_string_extend(WAF_G(response_body), current_len + to_buffer, 0);
        /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
        memcpy(ZSTR_VAL(WAF_G(response_body)) + current_len, str, to_buffer);
        ZSTR_VAL(WAF_G(response_body))[current_len + to_buffer] = '\0';
      }

      if (to_buffer < len) {
        /* Buffer now full: flush the inspected prefix to the client to keep
         * output ordered, RETAIN it for ModSecurity inspection at RSHUTDOWN
         * (response_body_sent guards the double flush), then pass the overflow
         * tail through directly. */
        original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                          ZSTR_LEN(WAF_G(response_body)));
        WAF_G(response_body_sent) = 1;
        return original_ub_write(str + to_buffer, len - to_buffer);
      }
      return len;
    }

    /* Buffer exactly full from a prior chunk (no overflow yet): flush it, mark
     * sent, and pass this chunk through. */
    original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                      ZSTR_LEN(WAF_G(response_body)));
    WAF_G(response_body_sent) = 1;
    return original_ub_write(str, len);
  }

  /* Send the output via the original ub_write */
  return original_ub_write(str, len);
}

/* execute_ex hook. Request inspection now runs in RINIT (see waf_RINIT) so the
 * WAF sees requests even when FPM later 404s a non-existent SCRIPT_FILENAME.
 * This hook remains as a no-op fallback: RINIT sets modsec_processed=1, so the
 * guard below is always false and we just forward to the original executor.
 * Kept (rather than unhooked) to avoid touching MINIT and to preserve the
 * original ub_write/execute_ex hook pairing. */
static void waf_execute_ex(zend_execute_data *execute_data) {
  int modsec_intervention = 0;

  /* Process once per request, for user space code only */
  if (!WAF_G(modsec_processed) && execute_data->func &&
      ZEND_USER_CODE(execute_data->func->type)) {

    WAF_G(modsec_processed) = 1;

    /* Run ModSecurity request phases now that $_SERVER is available */
    if (waf_modsec_is_enabled()) {
      modsec_intervention = waf_modsec_process_request();
      if (modsec_intervention > 0) {
        /* Blocked by ModSecurity, drop buffered body (e.g. auto_prepend_file
         * output), send the error response, then end the transaction. */
        if (WAF_G(response_body)) {
          zend_string_release(WAF_G(response_body));
          WAF_G(response_body) = NULL;
        }
        waf_send_block_response(modsec_intervention);

        /* Cleanup transaction */
        waf_modsec_process_logging();
        waf_modsec_transaction_end();

        /* Bail out back to the main loop */
        zend_bailout();
      }
    }
  }

  /* Call the original execute_ex */
  original_execute_ex(execute_data);
}

PHP_INI_BEGIN()
STD_PHP_INI_BOOLEAN("waf.enabled", "0", PHP_INI_SYSTEM, OnUpdateBool, enabled,
                    zend_waf_globals, waf_globals)
STD_PHP_INI_BOOLEAN("waf.trust_proxy_headers", "0", PHP_INI_SYSTEM, OnUpdateBool,
                    trust_proxy_headers, zend_waf_globals, waf_globals)
/* ModSecurity INI entries */
STD_PHP_INI_ENTRY("waf.modsec_rules_file", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_rules_file, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_rules_inline", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_rules_inline, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_block_status", "403", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_block_status, zend_waf_globals,
                  waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_debug_log", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_debug_log, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_debug_level", "0", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_debug_level, zend_waf_globals,
                  waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_transaction_id", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_transaction_id, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_audit_log", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_audit_log, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_audit_log_parts", "ABCFHZ", PHP_INI_SYSTEM,
                  OnUpdateString, modsec_audit_log_parts, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_response_body_limit", "10485760", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_response_body_limit, zend_waf_globals,
                  waf_globals)
PHP_INI_END()

void waf_init_globals(zend_waf_globals *globals) {
  globals->enabled = 0;
  globals->trust_proxy_headers = 0;
  globals->request_body = NULL;
  globals->response_body = NULL;
  globals->response_body_sent = 0;

  /* ModSecurity globals */
  globals->modsec_rules_file = NULL;
  globals->modsec_rules_inline = NULL;
  globals->modsec_block_status = HTTP_STATUS_FORBIDDEN;
  globals->modsec_debug_log = NULL;
  globals->modsec_debug_level = 0;
  globals->modsec_transaction_id = NULL;
  globals->modsec_audit_log = NULL;
  globals->modsec_audit_log_parts = NULL;
  globals->modsec_response_body_limit = WAF_RESPONSE_BODY_MAX_SIZE;
  globals->modsec_transaction = NULL;
  globals->modsec_processed = 0;
  globals->transaction_id = NULL;

  /* Initialize intervention */
  globals->intervention.status = HTTP_STATUS_OK;
  globals->intervention.pause = 0;
  globals->intervention.url = NULL;
  globals->intervention.log = NULL;
  globals->intervention.disruptive = 0;
}

/* Capture the request body from php //input for inspection.
 *
 * php //input is empty for multipart/form data because PHP consumes it into
 * $_FILES before userland runs, so multipart bodies and POST form fields are
 * not inspected here (only query string ARGS parsed by libmodsecurity are
 * available). A full fix would read the raw SAPI stream in RINIT before POST
 * processing out of scope for this path. */
zend_string *waf_capture_request_body(void) {
  php_stream *stream = NULL;
  zend_string *body = NULL;

  stream = php_stream_open_wrapper("php://input", "rb", REPORT_ERRORS, NULL);
  if (stream == NULL) {
    return zend_string_init("", 0, 0);
  }

  /* Read up to the request body size limit */
  zend_string *content = php_stream_copy_to_mem(stream, WAF_REQUEST_BODY_MAX_SIZE, 0);
  php_stream_close(stream);

  if (content == NULL) {
    body = zend_string_init("", 0, 0);
  } else {
    body = content;
  }

  return body;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_MINIT_FUNCTION(waf) {
  (void)type;
  (void)module_number;

  ZEND_INIT_MODULE_GLOBALS(waf, waf_init_globals, NULL);
  REGISTER_INI_ENTRIES();

  /* Initialize ModSecurity */
  waf_modsec_init();

  /* Hook execute_ex to process ModSecurity after $_SERVER is populated */
  if (original_execute_ex == NULL) {
    original_execute_ex = zend_execute_ex;
    zend_execute_ex = waf_execute_ex;
  }

  /* Hook SAPI ub_write to capture response body for ModSecurity */
  if (original_ub_write == NULL) {
    original_ub_write = sapi_module.ub_write;
    sapi_module.ub_write = waf_ub_write;
  }

  return SUCCESS;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_MSHUTDOWN_FUNCTION(waf) {
  (void)type;
  (void)module_number;

  /* Restore original execute_ex */
  if (original_execute_ex != NULL) {
    zend_execute_ex = original_execute_ex;
    original_execute_ex = NULL;
  }

  /* Restore original SAPI ub_write */
  if (original_ub_write != NULL) {
    sapi_module.ub_write = original_ub_write;
    original_ub_write = NULL;
  }

  /* Cleanup ModSecurity */
  waf_modsec_shutdown();

  UNREGISTER_INI_ENTRIES();
  return SUCCESS;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_RINIT_FUNCTION(waf) {
  (void)type;
  (void)module_number;

#if defined(ZTS) && defined(COMPILE_DL_WAF)
  ZEND_TSRMLS_CACHE_UPDATE();
#endif

  if (!WAF_G(enabled)) {
    return SUCCESS;
  }

  if (strcmp(sapi_module.name, "fpm-fcgi") != 0) {
    return SUCCESS;
  }

  /* Release any response body buffered BEFORE RINIT. sapi_activate (which runs
   * before module RINITs) reads POST data; a malformed multipart body emits an
   * E_WARNING through ub_write that waf_ub_write buffers into response_body.
   * Nulling the pointer without releasing would leak that zend_string every
   * request. The buffered bytes are not meaningful response output (they are a
   * startup warning) and are intentionally dropped here; a later WAF block
   * re-discards response_body, and the allow path flushes only post-RINIT
   * output. */
  if (WAF_G(response_body) != NULL) {
    zend_string_release(WAF_G(response_body));
  }
  WAF_G(request_body) = NULL;
  WAF_G(response_body) = NULL;
  WAF_G(response_body_sent) = 0;
  WAF_G(modsec_transaction) = NULL;
  WAF_G(modsec_processed) = 0;
  WAF_G(transaction_id) = NULL;

  /* Initialize intervention for this request */
  WAF_G(intervention).status = HTTP_STATUS_OK;
  WAF_G(intervention).pause = 0;
  WAF_G(intervention).url = NULL;
  WAF_G(intervention).log = NULL;
  WAF_G(intervention).disruptive = 0;

  /* Capture request body for ModSecurity inspection */
  WAF_G(request_body) = waf_capture_request_body();

  /* Process ModSecurity request phases (headers + body) here in RINIT, BEFORE
   * FPM resolves SCRIPT_FILENAME. waf_execute_ex fires only during
   * php_execute_script, i.e. AFTER php_fopen_primary_script: a request for a
   * non-existent script (/admin, /.env, /wp-config.php, /index.php.bak, ...)
   * would 404 ("Primary script unknown") before execute_ex ever ran, silently
   * bypassing every path-based rule. Running here instead mirrors Apache's
   * post_read_request hook (where real mod_security inspects) and guarantees
   * the WAF sees EVERY request regardless of whether the target file exists.
   *
   * $_SERVER is populated: sapi_activate (which registers server variables
   * from the FastCGI env parsed by FPM's init_request_info) runs before module
   * RINITs, and zend_is_auto_global_str forces it under auto_globals_jit. The
   * request body is captured above. On a block we send the response and
   * zend_bailout back to FPM's zend_first_try, skipping file resolution and
   * execution; RSHUTDOWN then runs but sees modsec_transaction==NULL (ended
   * below) so it does not double-process. Setting modsec_processed here also
   * makes waf_execute_ex's guard skip (no second run). */
  WAF_G(modsec_processed) = 1;
  if (waf_modsec_is_enabled()) {
    int modsec_intervention = waf_modsec_process_request();
    if (modsec_intervention > 0) {
      /* Blocked: drop any buffered body (none expected here, but be safe) and
       * emit the block page, then bail out of the request. */
      if (WAF_G(response_body)) {
        zend_string_release(WAF_G(response_body));
        WAF_G(response_body) = NULL;
      }
      waf_send_block_response(modsec_intervention);
      waf_modsec_process_logging();
      waf_modsec_transaction_end();
      zend_bailout();
    }
  }

  return SUCCESS;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_RSHUTDOWN_FUNCTION(waf) {
  (void)type;
  (void)module_number;

  int modsec_intervention = 0;

  if (!WAF_G(enabled)) {
    return SUCCESS;
  }

  if (strcmp(sapi_module.name, "fpm-fcgi") != 0) {
    return SUCCESS;
  }

  /* Process ModSecurity response phases */
  if (waf_modsec_is_enabled() && WAF_G(modsec_transaction) != NULL) {
    modsec_intervention = waf_modsec_process_response();
    if (modsec_intervention > 0) {
      /* Response blocked discard buffered body and emit the block page.
       * Logging and transaction end run after so the block can read the ID
       * and redirect URL. */
      if (WAF_G(response_body)) {
        zend_string_release(WAF_G(response_body));
        WAF_G(response_body) = NULL;
      }
      waf_send_block_response(modsec_intervention);
      waf_modsec_process_logging();
      waf_modsec_transaction_end();
    } else {
      /* Response allowed: flush the buffered (possibly rewritten) body, sending
       * headers first since ub_write buffering suppressed the implicit send.
       * Skip the flush if the buffer was already streamed to the client on
       * overflow (response_body_sent): the bytes already went out, in order, so
       * only inspection (done in waf_modsec_process_response) is needed. */
      if (!WAF_G(response_body_sent) &&
          WAF_G(response_body) != NULL && ZSTR_LEN(WAF_G(response_body)) > 0) {
        sapi_send_headers();
        original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                          ZSTR_LEN(WAF_G(response_body)));
      }
      waf_modsec_process_logging();
      waf_modsec_transaction_end();
    }
  } else {
    /* No transaction: send the buffered response body, unless it was already
     * streamed to the client on overflow. */
    if (!WAF_G(response_body_sent) &&
        WAF_G(response_body) != NULL && ZSTR_LEN(WAF_G(response_body)) > 0) {
      sapi_send_headers();
      original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                        ZSTR_LEN(WAF_G(response_body)));
    }
  }

  if (WAF_G(request_body)) {
    zend_string_release(WAF_G(request_body));
    WAF_G(request_body) = NULL;
  }

  if (WAF_G(response_body)) {
    zend_string_release(WAF_G(response_body));
    WAF_G(response_body) = NULL;
  }

  if (WAF_G(transaction_id)) {
    efree(WAF_G(transaction_id));
    WAF_G(transaction_id) = NULL;
  }

  return SUCCESS;
}

PHP_MINFO_FUNCTION(waf) {
  php_info_print_table_start();
  php_info_print_table_header(2, "waf support", "enabled");
  php_info_print_table_row(2, "Version", PHP_WAF_VERSION);
  php_info_print_table_end();

  DISPLAY_INI_ENTRIES();
}

static const zend_function_entry waf_functions[] = {PHP_FE_END};

// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
zend_module_entry waf_module_entry = {
    STANDARD_MODULE_HEADER, PHP_WAF_EXTNAME,
    waf_functions,          PHP_MINIT(waf),
    PHP_MSHUTDOWN(waf),     PHP_RINIT(waf),
    PHP_RSHUTDOWN(waf),     PHP_MINFO(waf),
    PHP_WAF_VERSION,        STANDARD_MODULE_PROPERTIES};

#ifdef COMPILE_DL_WAF
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(waf)
#endif
