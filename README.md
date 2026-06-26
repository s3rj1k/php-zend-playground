# php-waf

A PHP extension (`waf`) that embeds **libmodsecurity** into the PHP request
lifecycle by hooking Zend Engine internals (`zend_execute_ex`) and the SAPI
output path (`sapi_module.ub_write`). ModSecurity request/response phases run
from inside PHP FPM, with no separate WAF proxy.
