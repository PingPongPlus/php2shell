#!/bin/bash
set -e

mkdir -p /var/lib/php/sessions /run/php
chown www-data:www-data /var/lib/php/sessions
chmod 1733 /var/lib/php/sessions

# Default: ZendMM enabled (USE_ZEND_ALLOC=1)
export USE_ZEND_ALLOC=${USE_ZEND_ALLOC:-1}

echo "[*] PHP $(php -r 'echo PHP_VERSION;') ($(php -r 'echo PHP_SAPI;'))"
echo "[*] USE_ZEND_ALLOC=$USE_ZEND_ALLOC"
echo "[*] session.upload_progress.enabled = $(php -r "echo ini_get('session.upload_progress.enabled');")"
echo "[*] session.upload_progress.min_freq = $(php -r "echo ini_get('session.upload_progress.min_freq');")"

php-fpm --nodaemonize &
FPM_PID=$!

sleep 1
if ! kill -0 $FPM_PID 2>/dev/null; then
    echo "[!] PHP-FPM failed to start"
    exit 1
fi
echo "[*] PHP-FPM started (pid $FPM_PID)"
echo "[*] nginx starting on :80"
nginx -g 'daemon off;'
