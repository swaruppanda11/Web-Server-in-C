#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
import time
import re
from pathlib import Path
from typing import Optional, Tuple
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import socket
from typing import Optional

# ---------- utilities ----------


def _read_headers_and_len(sock, timeout: float = 5.0):
    """Return (status_code:int, content_length:int|None, rest_body_bytes:bytes)."""
    sock.settimeout(timeout)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed before headers")
        buf.extend(chunk)
    header_bytes, rest = bytes(buf).split(b"\r\n\r\n", 1)
    lines = header_bytes.split(b"\r\n")
    status_line = lines[0].decode("iso-8859-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ValueError(f"bad status line: {status_line!r}")
    try:
        code = int(parts[1])
    except Exception:
        raise ValueError(f"bad status code in: {status_line!r}")

    content_length = None
    for ln in lines[1:]:
        if ln.lower().startswith(b"content-length:"):
            try:
                content_length = int(ln.split(b":", 1)[1].strip())
            except Exception:
                content_length = None
            break
    return code, content_length, rest

def _drain_body(sock, content_length: int, rest: bytes, timeout: float = 5.0):
    """Consume exactly content_length bytes; return (body:bytes, leftover:bytes)."""
    sock.settimeout(timeout)
    data = bytearray(rest)
    need = content_length - len(data)
    while need > 0:
        chunk = sock.recv(min(4096, need))
        if not chunk:
            raise EOFError("connection closed mid-body")
        data.extend(chunk)
        need -= len(chunk)
    body = bytes(data[:content_length])
    leftover = bytes(data[content_length:])
    return body, leftover


def run(cmd, timeout=None, capture=False):
    try:
        res = subprocess.run(
            cmd,
            timeout=timeout,
            check=False,
            text=False,  # keep bytes
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
        return res.returncode, (res.stdout or b""), (res.stderr or b"")
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or b""), (e.stderr or b"")

def ensure_tool(name):
    from shutil import which
    if which(name) is None:
        print(f"[FATAL] Required tool '{name}' not found in PATH.", file=sys.stderr)
        sys.exit(2)

def is_segfault(proc: subprocess.Popen) -> bool:
    if proc.poll() is None:
        return False
    rc = proc.returncode
    return rc is not None and rc == -signal.SIGSEGV

def kill_process_group(proc: Optional[subprocess.Popen]):
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        pass

def curl_get(url: str, timeout_s: int = 5) -> Tuple[int, bytes, bytes]:
    code, out, err = run(["curl", "-fsS", "--max-time", str(timeout_s), url], timeout=timeout_s + 1, capture=True)
    return code, out, err

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------- raw HTTP helpers (for error-code tests) ----------

def parse_status_code(buf: bytes) -> int:
    try:
        # Status line: HTTP/1.1 200 OK
        line = buf.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("HTTP/"):
            return int(parts[1])
    except Exception:
        pass
    return -1

def send_raw_request(host: str, port: int, req_bytes: bytes, timeout: float = 2.0) -> Tuple[int, bytes]:
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(req_bytes)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        buf = b"".join(chunks)
        return parse_status_code(buf), buf
    except Exception:
        return -1, b""
    finally:
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sock.close()

# ---------- grading logic ----------

def wait_for_server(proc, url, curl_timeout_s=2, ready_timeout_s=10):
    start = time.time()
    while time.time() - start < ready_timeout_s:
        if is_segfault(proc):
            print("[ERROR] Server crashed with SIGSEGV during startup. Stopping tests.")
            return False, "segfault"
        code, out, err = curl_get(url, timeout_s=curl_timeout_s)
        if code == 0:
            return True, out
        time.sleep(0.2)
    return False, "timeout"

def check_expect(req: bytes, want: int, label: str, alt_reqs: Optional[list] = None) -> bool:
    """Send req; if status==want -> pass. If alt_reqs provided, try them until one matches."""
    status, _ = send_raw_request(host, port, req, timeout=2.0)
    if status == want:
        print(f"[OK] {label}: got {status}")
        return True
    if alt_reqs:
        for r in alt_reqs:
            status2, _ = send_raw_request(host, port, r, timeout=2.0)
            if status2 == want:
                print(f"[OK] {label} (alt): got {status2}")
                return True
    print(f"[FAIL] {label}: got {status}")
    return False
        
def server_running(proc) -> bool:
    return proc.poll() is None

def curl_body(url: str, timeout_s: int = 8) -> tuple[int, bytes, bytes]:
    # Mirror the terminal behavior: fetch body; no -f/-I/-w, just the body
    return run(["curl", "-sS", "--max-time", str(timeout_s), url], timeout=timeout_s + 2, capture=True)

def curl_http_code(url: str, timeout_s: int = 8, method: Optional[str] = None) -> int:
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
           "--max-time", str(timeout_s)]
    if method:
        cmd += ["-X", method]
    cmd.append(url)
    code, out, err = run(cmd, timeout=timeout_s + 2, capture=True)
    try:
        return int((out or b"").decode().strip())  # e.g., 200, 404, or 000
    except Exception:
        return 0

# relaxed status parser for raw-socket test
def _parse_status_code_relaxed(buf: bytes) -> int:
    # Accept CRLF or LF, skip leading blanks
    # Look for first non-empty line that starts with HTTP/x.y
    hdr_end = buf.find(b"\r\n\r\n")
    header_block = buf[:hdr_end if hdr_end != -1 else len(buf)]
    for line in header_block.splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", s)
        if m:
            return int(m.group(1))
        break
    # fallback to first line
    first = buf.split(b"\n", 1)[0].strip()
    m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", first)
    return int(m.group(1)) if m else -1

def _send_raw_request(host: str, port: int, req_bytes: bytes, timeout: float = 5.0) -> int:
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(req_bytes)
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        return _parse_status_code_relaxed(b"".join(chunks))
    except Exception:
        return -1
    finally:
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sock.close()

def main():
    parser = argparse.ArgumentParser(description="Web server grader")
    parser.add_argument("--exe", default="./server", help="Path to server executable")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server")
    parser.add_argument("--www", default="./www", help="Local www directory containing expected resources")
    parser.add_argument("--make-timeout", type=int, default=300)
    parser.add_argument("--server-ready-timeout", type=int, default=10)
    parser.add_argument("--curl-timeout", type=int, default=5)
    parser.add_argument("--class-code", type=int, default=5273)

    # Step 5 parameters
    parser.add_argument("--multi-total", type=int, default=15, help="Total requests in multi-conn test")
    parser.add_argument("--multi-concurrency", type=int, default=15, help="Concurrent workers in multi-conn test")
    parser.add_argument("--multi-timeout", type=float, default=2.0, help="Per-request timeout (seconds) in multi-conn test")
    args = parser.parse_args()

    ensure_tool("make")
    ensure_tool("curl")

    total_points = 0
    max_points = 100  # 60 (index.html) + 10 (images) + 15 (multi-conn) + 5 (error handling) + 10 (persistent conn)

    # 1) Build
    print("== Step 1: Build ==")
    code, _, err = run(["make", "clean"], timeout=60, capture=True)
    if code != 0 and err:
        print("[WARN] `make clean` failed (continuing):")
        sys.stdout.buffer.write(err + b"\n")

    code, out, err = run(["make", "-j"], timeout=args.make_timeout, capture=True)
    if code != 0:
        print("[FAIL] Compilation failed. Total points: 0 /", max_points)
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.write(err)
        sys.exit(1)
    print("[OK] Build succeeded.")

    # 2) Launch server
    print("== Step 2: Launch server ==")
    if not (os.path.isfile(args.exe) and os.access(args.exe, os.X_OK)):
        print(f"[FAIL] Executable '{args.exe}' not found or not executable. Total points: 0 / {max_points}")
        sys.exit(1)

    env = os.environ.copy()
    server = subprocess.Popen(
        [args.exe, str(args.port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
        env=env,
    )

    try:
        root_url = f"http://127.0.0.1:{args.port}/"
        index_url = root_url + "index.html"
        images_url = root_url + "images/"

        print(f"[INFO] Waiting for server readiness at {root_url} ...")
        ok, data = wait_for_server(server, root_url, curl_timeout_s=args.curl_timeout, ready_timeout_s=args.server_ready_timeout)
        if data == "segfault":
            try:
                _, serr = server.communicate(timeout=1)
                if serr:
                    print("[server stderr]")
                    sys.stdout.write(serr)
            except Exception:
                pass
        if not ok:
            print(f"[FAIL] Server did not become ready: {data}. Total points: 0 / {max_points}")
            sys.exit(1)

        # 3) Compare index.html (60 pts)
        print("== Step 3: Check index.html (60 or 70 pts) ==")
        local_index_path = Path(args.www) / "index.html"
        if not local_index_path.is_file():
            print(f"[FAIL] Expected file not found: {local_index_path}")
            print(f"Score for index.html: 0")
        else:
            code, served_index, err = curl_get(index_url, timeout_s=args.curl_timeout)
            if code != 0:
                print(f"[FAIL] Could not fetch {index_url}")
                if err:
                    sys.stdout.buffer.write(err + b"\n")
                print(f"Score for index.html: 0")
            else:
                local_bytes = local_index_path.read_bytes()
                if served_index == local_bytes:
                    if args.class_code == 4273:
                        total_points += 70
                        print(f"[OK] index.html matches exactly -> +70 pts")
                    else:
                        total_points += 60
                        print(f"[OK] index.html matches exactly -> +60 pts")
                else:
                    print("[FAIL] index.html does not match.")
                    print(f"served sha256: {sha256(served_index)}")
                    print(f"local  sha256: {sha256(local_bytes)}")
                    print(f"Score for index.html: 0")

        # 4) Check images (up to 10 pts; -3 per mismatch; 0 if none match)
        print("== Step 4: Check images (up to 10 pts) ==")
        images = ["apple_ex.png", "exam.gif", "wine3.jpg"]
        matched = 0
        for img in images:
            url = images_url + img
            local_path = Path(args.www) / "images" / img
            print(f" - {img}: ", end="", flush=True)

            if not local_path.is_file():
                print("missing locally -> mismatch")
                continue

            code, served_bytes, err = curl_get(url, timeout_s=args.curl_timeout)
            if code != 0:
                print("fetch failed -> mismatch")
                continue

            local_bytes = local_path.read_bytes()
            if served_bytes == local_bytes:
                matched += 1
                print("match")
            else:
                print("mismatch")

        if matched == 0:
            img_points = 0
        else:
            img_points = max(0, 10 - 3 * (len(images) - matched))
        total_points += img_points
        print(f"[RESULT] Images matched: {matched}/{len(images)} -> +{img_points} pts")

        # 5) Handling multiple connections (15 pts)
        print("== Step 5: Handling multiple connections (15 pts) ==")

        # Prepare expected bytes for strict comparison during concurrency
        exp_map = {}
        exp_targets = [("index.html", Path(args.www) / "index.html")]
        for img in images:
            exp_targets.append((f"images/{img}", Path(args.www) / "images" / img))

        for rel_path, p in exp_targets:
            if p.is_file():
                exp_map[rel_path] = p.read_bytes()
            else:
                exp_map[rel_path] = None

        paths_cycle = [k for k in exp_map.keys()]
        if not paths_cycle:
            print("[WARN] No expected resources available for concurrency check; awarding 0 / 15.")
            multi_points = 0
            total_points += multi_points
        else:
            req_paths = [paths_cycle[i % len(paths_cycle)] for i in range(args.multi_total)]

            def fetch_and_check(rel_path: str) -> bool:
                if is_segfault(server):
                    return False
                url = f"http://127.0.0.1:{args.port}/{rel_path}"
                try:
                    with urllib.request.urlopen(url, timeout=args.multi_timeout) as resp:
                        if resp.status != 200:
                            return False
                        body = resp.read()
                except Exception:
                    return False
                expected = exp_map.get(rel_path)
                if expected is not None:
                    return body == expected
                return len(body) > 0

            successes = 0
            failed_early = False
            with ThreadPoolExecutor(max_workers=args.multi_concurrency) as ex:
                futures = {ex.submit(fetch_and_check, rp): rp for rp in req_paths}
                for fut in as_completed(futures):
                    if is_segfault(server):
                        failed_early = True
                        break
                    ok = fut.result()
                    successes += 1 if ok else 0

            if failed_early or is_segfault(server):
                print("[ERROR] Server crashed (SIGSEGV) during multi-connection test. Stopping tests.")
                print("[RESULT] Multi-connection score: +0 pts")
                print("== Final Score ==")
                print(f"Total points: {total_points} / {max_points}")
                sys.exit(1)

            multi_points = round(15 * (successes / max(1, len(req_paths))))
            total_points += multi_points
            print(f"[RESULT] {successes}/{len(req_paths)} successful concurrent requests -> +{multi_points} pts")

        # 6) Error handling (5 pts total)
        print("== Step 6: Error handling (5 pts) ==")
        eh_points = 0
        if not server_running(server):
            print(f"[FAIL] Server not running at Step 6 (exit={server.returncode}). Score: 0 / 5")
        else:
            host, port = "127.0.0.1", args.port

            # 6a) 404 Not Found via curl|grep-style body check (+3)
            url_404 = f"http://{host}:{port}/images/wine4.jpg"
            code, out, err = curl_body(url_404, timeout_s=8)
            if code != 0:
                print(f"[FAIL] 404 test: curl failed (exit={code})")
            else:
                body = out.decode("iso-8859-1", "replace")
                if re.search(r"\b404\b", body, re.IGNORECASE):
                    eh_points += 3
                    print("[OK] 404 Not Found (+3)")
                else:
                    print(f"[FAIL] 404 test: '404' not found in body. Got: {body}")

            # 6b) 405 Method Not Allowed via curl status (+1)
            # Use POST to a known existing resource
            url_index = f"http://{host}:{port}/index.html"
            status_405 = curl_http_code(url_index, timeout_s=8, method="PUT")
            if status_405 == 405:
                eh_points += 1
                print("[OK] 405 PUT method Not Allowed (+1)")
            else:
                print(f"[FAIL] 405 test: expected 405, got {status_405}")

            # 6c) 505 HTTP Version Not Supported via raw request (+1)
            req_505 = (f"GET / HTTP/2.0\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n").encode()
            status_505 = _send_raw_request(host, port, req_505, timeout=5.0)
            if status_505 == 505:
                eh_points += 1
                print("[OK] 505 HTTP Version 2.0 Not Supported (+1)")
            else:
                print(f"[FAIL] 505 test: expected 505, got {status_505}")

            print(f"[RESULT] Error handling score: +{eh_points} / 5 pts")
            total_points += eh_points

        # 7) Persistent connection (10 pts)
        print("== Step 7: Persistent connection (10 or 5 extra pts) ==")

        if is_segfault(server):
            print("[FAIL] Server crashed before persistent-connection test.")
            print("Score for persistent connections: 0")
        else:
            index_path = Path(args.www) / "index.html"
            if not index_path.is_file():
                print(f"[FAIL] Missing expected file: {index_path}")
                print("Score for persistent connections: 0")
            else:
                expected = index_path.read_bytes()
                host, port = "127.0.0.1", args.port

                # one TCP connection, three requests
                try:
                    with socket.create_connection((host, port), timeout=3.0) as sock:
                        sock.settimeout(5.0)
                        req1 = (f"GET /index.html HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n").encode()
                        req2 = (f"GET /index.html HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n").encode()
                        req3 = (f"GET /index.html HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n").encode()

                        # Send 1st request and parse response
                        sock.sendall(req1)
                        code1, cl1, rest1 = _read_headers_and_len(sock, timeout=5.0)
                        if cl1 is None:
                            raise ValueError("response #1 missing Content-Length (required for persistent parsing)")
                        body1, leftover = _drain_body(sock, cl1, rest1, timeout=5.0)
                        if code1 != 200 or body1 != expected:
                            raise AssertionError(f"resp #1 mismatch (code={code1}, len={len(body1)})")

                        # Send 2nd request on same connection
                        sock.sendall(req2)
                        # If previous recv over-read (leftover), use it first by prepending to socket buffer? Not possible;
                        # We only read exactly Content-Length, so leftover should be empty.
                        code2, cl2, rest2 = _read_headers_and_len(sock, timeout=5.0)
                        if cl2 is None:
                            raise ValueError("response #2 missing Content-Length (required for persistent parsing)")
                        body2, leftover2 = _drain_body(sock, cl2, rest2, timeout=5.0)
                        if code2 != 200 or body2 != expected:
                            raise AssertionError(f"resp #2 mismatch (code={code2}, len={len(body2)})")

                        # Send 3rd request with Connection: close
                        sock.sendall(req3)
                        code3, cl3, rest3 = _read_headers_and_len(sock, timeout=5.0)
                        if cl3 is None:
                            raise ValueError("response #3 missing Content-Length (required for persistent parsing)")
                        body3, leftover3 = _drain_body(sock, cl3, rest3, timeout=5.0)
                        if code3 != 200 or body3 != expected:
                            raise AssertionError(f"resp #3 mismatch (code={code3}, len={len(body3)})")

                        # Success: three 200s over one connection
                        if args.class_code == 4273:
                            total_points += 5
                            print("[OK] Served 3 requests over the same TCP connection with 200 OK each. -> +5 pts")
                        else:
                            total_points += 10
                            print("[OK] Served 3 requests over the same TCP connection with 200 OK each. -> +10 pts")

                except (AssertionError, ValueError, EOFError, socket.timeout, OSError) as e:
                    print(f"[FAIL] Persistent-connection test failed: {e}")
                    print("Score for persistent connections: 0 / 10")


        # Final
        print("== Final Score ==")
        print(f"Total points: {total_points} / {max_points}")
        sys.exit(0 if total_points == max_points else 1)

    finally:
        kill_process_group(server)

if __name__ == "__main__":
    main()

