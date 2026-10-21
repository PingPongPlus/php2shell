<?php
// Intentionally LFI-vulnerable — php2shell CVE-2026-109618/9 PoC lab target.
// LAB_MODE env var required; container-only, never expose externally.
if (getenv('LAB_MODE') !== 'true') { http_response_code(403); exit('Lab only'); }
session_start();
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "PHP " . phpversion() . " | session.upload_progress.enabled=" . ini_get('session.upload_progress.enabled');
}
?>
