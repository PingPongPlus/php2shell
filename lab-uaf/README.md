# PHP2Shell Lab

CVE-2026-109618 / CVE-2026-109619

Use-After-Free in PHP's `session.upload_progress` feature. The rfc1867 upload handler caches raw pointers into a session HashTable. A timed stall between file data chunks causes the session to re-initialize, freeing the HashTable while the cached pointers still reference it. Later file data events write through these stale pointers.

Tested on PHP 8.4.4 FPM (Debian Bookworm).

Author: Ahmed Sultan (0x4148)

## Requirements

- Docker and Docker Compose
- Python 3

## Quick Start

Build and start the lab:

```
docker compose up -d --build
```

The container listens on port 19268.

Verify it is running:

```
python3 scripts/php2shell_poc.py --verify
```

You should see `upload_progress: ENABLED (vulnerable)`.

## Trigger the Vulnerability

Basic trigger:

```
python3 scripts/php2shell_poc.py --monitor
```

With verbose output and multiple rounds:

```
python3 scripts/php2shell_poc.py --monitor --verbose --rounds 5
```

Custom stall time (must be greater than 1 second, the default min_freq):

```
python3 scripts/php2shell_poc.py --monitor --stall 2.0
```

If it works, you will see:

```
Armed:   YES - bytes_processed = 5376
Cached zval* pointers were written through (stale path reached)
```

This means the vulnerable code path was reached. The cached pointers in session.c lines 3292 and 3318 were armed, and the writes at lines 3331-3332 went through them.

## Apply the Mitigation

Switch to the mitigated config (disables upload_progress):

```
docker compose -f docker-compose.yml -f docker-compose.mitigated.yml up -d
```

Test again:

```
python3 scripts/php2shell_poc.py --monitor --verify
```

You should see:

```
upload_progress: DISABLED (mitigated)
Armed:   NO - session empty (mitigation active or stall too short)
```

## Revert to Vulnerable Mode

```
docker compose up -d
```

## Clean Up

```
docker compose down
```

## Files

```
Dockerfile                      PHP 8.4.4 FPM image with nginx
docker-compose.yml              Base config, port 19268
docker-compose.mitigated.yml    Override that disables upload_progress
entrypoint.sh                   Starts PHP-FPM and nginx
conf/php.ini                    Vulnerable config (upload_progress enabled)
conf/php-mitigated.ini          Mitigated config (upload_progress disabled)
conf/nginx.conf                 fastcgi_request_buffering off (required)
conf/php-fpm.conf               FPM master config
conf/www.conf                   FPM pool config
scripts/php2shell_poc.py        PoC script (main tool)
scripts/trigger.py              Simpler trigger script
scripts/verify.sh               Quick verification script
webroot/index.php               Shows PHP version and config
webroot/check_progress.php      Reads session data for monitoring
```

## How It Works

1. The PoC sends a multipart POST with a session ID and `PHP_SESSION_UPLOAD_PROGRESS` field
2. File data is sent in two bursts with a pause between them
3. The first burst triggers `FILE_START` and `FILE_DATA`, which caches `zval*` pointers into the session HashTable
4. The pause lasts longer than `session.upload_progress.min_freq` (1 second by default)
5. The second burst triggers another `FILE_DATA`, which calls `update()`
6. `update()` re-initializes the session, freeing the old HashTable
7. Any further `FILE_DATA` writes go through the now-stale pointers into freed memory

Without heap grooming, the freed memory is still mapped by PHP's allocator (ZendMM), so the write is silent. A crafted heap spray could reclaim that memory and turn this into code execution.

## Limitations

This PoC proves the vulnerable code path is reachable. It does not achieve a crash or code execution. That requires a heap groom (spraying fake structures into ZendMM's 320-byte slab bin) with build-specific symbol offsets. See WRITEUP.md in the full archive for details.

## Mitigation Summary

- Set `session.upload_progress.enabled = Off` in php.ini (primary fix)
- Update PHP to a patched version
- As defense in depth: keep `fastcgi_request_buffering on` in nginx (the default), which prevents the stall from reaching FPM

## Reference
Ahmed Sultan (0x4148) : PHP2Shell - PHP Core RCE, Session Upload Progress, and My PHP 8.4.4 Lab Analysis : https://0x4148.com/posts/php2shell-php-core-rce-cve-2026-109618-109619/

## Disclaimer

For educational and authorized security testing only. Do not use against systems you do not own or have permission to test.
