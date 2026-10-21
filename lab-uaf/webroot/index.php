<?php
session_start();
header('Content-Type: text/plain');

printf("PHP %s (%s)\n", PHP_VERSION, PHP_SAPI);
printf("session.upload_progress.enabled = %s\n", ini_get('session.upload_progress.enabled'));
printf("session.upload_progress.min_freq = %s\n", ini_get('session.upload_progress.min_freq'));
printf("session.upload_progress.name = %s\n", ini_get('session.upload_progress.name'));
printf("session.save_handler = %s\n", ini_get('session.save_handler'));
printf("file_uploads = %s\n", ini_get('file_uploads'));
printf("USE_ZEND_ALLOC = %s\n", getenv('USE_ZEND_ALLOC') ?: '(not set)');
echo "OK\n";
