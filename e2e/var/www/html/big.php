<?php
// Generates an oversized response body for testing response-body inspection
// across the waf.modsec_response_body_limit boundary (1MB in the bench/rule
// scenario configs). Padding is emitted first so the blocked marker lands at a
// configurable offset, then the marker (rule 1008: blocked_response_content).
//
// Usage:
//   big.php?pad=2000000           -> ~2MB of 'a' padding, no marker (benign)
//   big.php?pad=2000000&mark=1    -> padding then the blocked marker
//
// When mark=1 the marker sits AFTER the padding. With the default 1MB limit
// and pad > limit, the marker is in the overflow tail and must NOT be blocked
// (only the first limit bytes are inspected, by design). To test that the
// inspected prefix still blocks, request pad=0&mark=1 (marker in the prefix).
header('Content-Type: text/plain');

$pad = isset($_GET['pad']) ? (int)$_GET['pad'] : 0;
if ($pad < 0 || $pad > 20 * 1024 * 1024) {
    $pad = 0;
}

if ($pad > 0) {
    // str_repeat in 1MB chunks keeps memory bounded.
    $chunk = str_repeat('a', 1024 * 1024);
    $full = (int)($pad / (1024 * 1024));
    for ($i = 0; $i < $full; $i++) {
        echo $chunk;
    }
    $rest = $pad % (1024 * 1024);
    if ($rest > 0) {
        echo str_repeat('a', $rest);
    }
}

if (isset($_GET['mark']) && $_GET['mark'] === '1') {
    echo "blocked_response_content";
}
