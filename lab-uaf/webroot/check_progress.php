<?php
header('Content-Type: application/json');
$sid = $_GET['sid'] ?? '';
if (!$sid || !preg_match('/^[a-f0-9]{32}$/', $sid)) {
    echo json_encode([]);
    exit;
}

// Read session file directly (no session_start lock) so we can observe
// upload_progress data while the upload request holds the exclusive lock.
$path = ini_get('session.save_path') ?: '/var/lib/php/sessions';
$file = $path . '/sess_' . $sid;

$raw = @file_get_contents($file);
if ($raw === false || $raw === '') {
    echo json_encode([]);
    exit;
}

// Parse PHP session serialization format: key|serialized_value ...
// We need to decode `bytes_processed` from the upload_progress entry.
$result = [];
$pos = 0;
$len = strlen($raw);
while ($pos < $len) {
    $sep = strpos($raw, '|', $pos);
    if ($sep === false) break;
    $key = substr($raw, $pos, $sep - $pos);
    $value_str = substr($raw, $sep + 1);
    $value = @unserialize($value_str);
    if ($value !== false) {
        $result[$key] = $value;
        // Advance past the serialized value.
        // unserialize doesn't tell us how many bytes it consumed, so
        // re-serialize and measure — good enough for lab use.
        $re = serialize($value);
        $pos = $sep + 1 + strlen($re);
    } else {
        break;
    }
}

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
