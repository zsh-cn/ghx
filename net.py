from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.request
import zlib
from urllib.parse import urlsplit
from collections.abc import Callable
from dataclasses import dataclass, field

import config
from store import Cache, CacheEntry

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

META_URL = "https://api.github.com/meta"
META_FILE = config.HOME_DIR / "meta.json"
META_TTL = 24 * 3600

_BARE_SUFFIXES = {"githubusercontent.com", "githubassets.com"}

_RUNNER_SUFFIXES = ("actions.githubusercontent.com",)


def _is_runner_host(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in _RUNNER_SUFFIXES)


@dataclass
class MetaInfo:
    domains: list[str] = field(default_factory=list)
    accelerated: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    updated: float = 0.0

    @property
    def known(self) -> bool:
        return bool(self.domains)

    def as_dict(self) -> dict:
        return {
            "updated": self.updated,
            "domains": self.domains,
            "accelerated": self.accelerated,
            "ips": self.ips,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MetaInfo":
        domains = [str(d) for d in data.get("domains") or []]
        accelerated = data.get("accelerated")
        if accelerated is None:
            accelerated = [d for d in domains if not _is_runner_host(d)]
        return cls(
            domains=domains,
            accelerated=[str(d) for d in accelerated],
            ips=[str(i) for i in data.get("ips") or []],
            updated=float(data.get("updated") or 0.0),
        )


def _walk_domains(node, out: set[str]) -> None:
    if isinstance(node, str):
        host = node.strip().lower()
        if host.startswith("*."):
            host = host[2:]
        if not host or "/" in host or " " in host or ":" in host:
            return
        if host in _BARE_SUFFIXES:
            return
        if config.is_github_host(host):
            out.add(host)
    elif isinstance(node, list):
        for item in node:
            _walk_domains(item, out)
    elif isinstance(node, dict):
        for item in node.values():
            _walk_domains(item, out)


def _collect_official_ips(node, out: set[str]) -> None:
    if isinstance(node, str):
        if "/" not in node:
            return
        try:
            net = ipaddress.ip_network(node.strip(), strict=False)
        except ValueError:
            return
        if net.version == 4 and net.prefixlen == 32:
            out.add(str(net.network_address))
    elif isinstance(node, list):
        for item in node:
            _collect_official_ips(item, out)
    elif isinstance(node, dict):
        for item in node.values():
            _collect_official_ips(item, out)


def _parse_meta(payload: dict) -> MetaInfo:
    domains: set[str] = set()
    official: set[str] = set()
    _walk_domains(payload.get("domains") or {}, domains)
    _collect_official_ips(payload, official)
    ordered = sorted(domains)
    return MetaInfo(
        domains=ordered,
        accelerated=[d for d in ordered if not _is_runner_host(d)],
        ips=sorted(official),
        updated=time.time(),
    )


_memo: MetaInfo | None = None


def fetch_meta(timeout: float = 10.0) -> MetaInfo:
    req = urllib.request.Request(
        META_URL,
        headers={
            "accept": "application/vnd.github+json",
            "user-agent": f"ghx/{config.VERSION}",
        },
    )
    with _OPENER.open(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))
    if not isinstance(payload, dict):
        raise ValueError("meta 返回格式异常")
    return _parse_meta(payload)


def load_cached_meta() -> MetaInfo | None:
    try:
        with open(META_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    info = MetaInfo.from_dict(data)
    return info if info.known else None


def save_meta(info: MetaInfo) -> None:
    try:
        META_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = f"{META_FILE}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(info.as_dict(), fh, ensure_ascii=False)
        os.replace(tmp, META_FILE)
    except OSError:
        pass


def current_meta() -> MetaInfo:
    global _memo
    if _memo is None:
        _memo = load_cached_meta() or MetaInfo()
    return _memo


def meta_stale(ttl: float = META_TTL) -> bool:
    info = current_meta()
    return not info.known or (time.time() - info.updated) > ttl


def refresh_meta(timeout: float = 8.0) -> MetaInfo:
    global _memo
    try:
        info = fetch_meta(timeout)
    except Exception:
        _memo = load_cached_meta() or _memo or MetaInfo()
        return _memo
    save_meta(info)
    _memo = info
    return info


def ensure_fresh_meta(timeout: float = 8.0) -> MetaInfo:
    if meta_stale():
        return refresh_meta(timeout)
    return current_meta()


DOH_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("doh.pub", "https://doh.pub/dns-query"),
    ("alidns", "https://dns.alidns.com/resolve"),
)

QUERY_TIMEOUT = 10.0
RESOLVE_BUDGET = 30.0


class DnsError(RuntimeError):
    pass


def is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return bool(addr.is_global) and not addr.is_multicast and not addr.is_link_local


def _doh_query(source: str, endpoint: str, domain: str, timeout: float) -> list[str]:
    url = f"{endpoint}?name={domain}&type=A"
    req = urllib.request.Request(
        url,
        headers={
            "accept": "application/dns-json",
            "user-agent": f"ghx/{config.VERSION} (+local github accelerator)",
        },
    )
    with _OPENER.open(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))

    status = payload.get("Status", payload.get("status", 0))
    if status not in (0, None):
        raise DnsError(f"{source} 返回状态码 {status}")

    ips: list[str] = []
    for answer in payload.get("Answer") or payload.get("answer") or []:
        if answer.get("type") == 1:
            data = str(answer.get("data", "")).strip()
            if data:
                ips.append(data)
    return ips


def _system_query(domain: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        raise DnsError(f"系统解析失败: {exc}") from exc
    return [info[4][0] for info in infos]


async def resolve_dns(domain: str) -> dict[str, list[str]]:
    labelled: list[tuple[str, asyncio.Task]] = []
    for name, endpoint in DOH_ENDPOINTS:
        labelled.append((f"doh:{name}", asyncio.ensure_future(
            asyncio.to_thread(_doh_query, name, endpoint, domain, QUERY_TIMEOUT))))
    labelled.append(("system", asyncio.ensure_future(
        asyncio.to_thread(_system_query, domain))))

    by_task = {task: source for source, task in labelled}
    merged: dict[str, list[str]] = {}

    def absorb(done: set[asyncio.Task]) -> None:
        for task in done:
            source = by_task[task]
            if task.cancelled() or task.exception() is not None:
                continue
            for ip in task.result() or []:
                if not is_public_ipv4(ip):
                    continue
                bucket = merged.setdefault(ip, [])
                if source not in bucket:
                    bucket.append(source)

    done, pending = await asyncio.wait(
        set(by_task), timeout=RESOLVE_BUDGET, return_when=asyncio.ALL_COMPLETED
    )
    absorb(done)

    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    if not merged:
        raise DnsError(f"所有解析通道均失败: {domain}")
    return merged


PROBE_PORT = 443
_SSL_CTX = ssl.create_default_context()


@dataclass(slots=True)
class ProbeResult:
    ip: str
    ok: bool
    total_ms: float = 0.0
    error: str = ""


class ProbeRejected(RuntimeError):
    pass


def _describe(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "超时"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "证书不匹配（疑似污染）"
    if isinstance(exc, ssl.SSLError):
        return f"TLS 失败: {exc.reason or exc}"
    if isinstance(exc, ConnectionRefusedError):
        return "连接被拒绝"
    if isinstance(exc, ConnectionResetError):
        return "连接被重置"
    if isinstance(exc, ProbeRejected):
        return str(exc)
    if isinstance(exc, OSError):
        return f"网络错误: {exc.strerror or exc}"
    return type(exc).__name__


class SniBlocked(RuntimeError):
    pass


_HANDSHAKE_ONLY = ("超时", "连接被重置", "TLS 失败", "对端在 HTTP 层直接断开", "网络错误")


async def _tcp_reachable(ip: str, timeout: float = 3.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, PROBE_PORT), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return False
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    return True


_ABUSE_MARKERS = (
    b"you have sent an invalid request",
    b"do not send this request again",
)
_REJECT_STATUS = frozenset((403, 429, 451))

_PROBE_PATHS: dict[str, str] = {
    "avatars.githubusercontent.com": "/u/1?s=40",
    "raw.githubusercontent.com": "/github/gitignore/main/README.md",
}

_UNSERVING_MARKERS = ("拒绝无效请求", "健康检查", "跳转 github.com")

_REDIRECT_TO_GITHUB_OK = frozenset(("github.com", "www.github.com", "codeload.github.com"))


def _http_status(head: bytes) -> int | None:
    line = (head or b"").split(b"\r\n", 1)[0]
    parts = line.split()
    if len(parts) < 2 or not parts[0].upper().startswith(b"HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _is_abuse_page(head: bytes, body: bytes) -> bool:
    lowered = ((head or b"") + b"\r\n" + (body or b"")).lower()
    return any(marker in lowered for marker in _ABUSE_MARKERS)


def _decode_chunked(body: bytes) -> bytes:
    out = b""
    rest = body or b""
    while rest:
        line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(line.strip(), 16)
        except ValueError:
            return out or body
        if size <= 0:
            break
        out += rest[:size]
        rest = rest[size + 2:]
    return out or body


def _is_health_page(head: bytes, body: bytes) -> bool:
    if b"transfer-encoding: chunked" in (head or b"").lower():
        body = _decode_chunked(body)
    return (body or b"").strip().lower() == b"ok"


async def _read_probe_body(reader: asyncio.StreamReader) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(2048), timeout=0.8)
    except (asyncio.TimeoutError, OSError):
        return b""


async def _response_error(
    reader: asyncio.StreamReader, head: bytes, domain: str = ""
) -> str:
    status = _http_status(head)
    if status is None:
        return "响应不是 HTTP（疑似非目标服务）"
    if status in _REJECT_STATUS or status >= 500:
        return f"HTTP {status}（被拒绝/限流）"
    if 300 <= status < 400 and domain not in _REDIRECT_TO_GITHUB_OK:
        if _redirects_to_github(head):
            return f"HTTP {status}（跳转 github.com，不服务该域名）"
    if 200 <= status < 300:
        if _is_health_page(head, await _read_probe_body(reader)):
            return "HTTP 200（健康检查页，不服务该域名）"
    if status == 400:
        body = await _read_probe_body(reader)
        if _is_abuse_page(head, body):
            return "HTTP 400（GitHub 拒绝无效请求）"
    return ""


def _redirects_to_github(head: bytes) -> bool:
    for line in (head or b"").split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() != b"location":
            continue
        target = value.strip().decode("latin-1", "replace")
        host = (urlsplit(target).hostname or "").lower()
        return host in ("github.com", "www.github.com")
    return False


async def _probe_once(ip: str, domain: str) -> float:
    path = _PROBE_PATHS.get(domain, "/")
    started = time.perf_counter()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host=ip,
            port=PROBE_PORT,
            ssl=_SSL_CTX,
            server_hostname=domain,
        ),
        timeout=config.PROBE_TIMEOUT,
    )
    handshake_ms = (time.perf_counter() - started) * 1000.0

    try:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: ghx-probe\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii", "replace")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=config.PROBE_TIMEOUT)
        try:
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=config.PROBE_TIMEOUT
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise ConnectionResetError("对端在 HTTP 层直接断开") from exc
        error = await _response_error(reader, head, domain)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    if error:
        raise ProbeRejected(error)
    return handshake_ms


async def probe_ip(
    domain: str,
    ip: str,
    *,
    samples: int = config.PROBE_SAMPLES,
) -> ProbeResult:
    best: float | None = None
    last_error = ""

    for _ in range(max(1, samples)):
        try:
            handshake_ms = await _probe_once(ip, domain)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            last_error = _describe(exc)
            continue
        if best is None or handshake_ms < best:
            best = handshake_ms

    if best is None:
        return ProbeResult(ip=ip, ok=False, error=last_error or "不可达")
    return ProbeResult(ip=ip, ok=True, total_ms=best)


async def probe_domain(
    domain: str,
    ips: list[str],
    *,
    samples: int = config.PROBE_SAMPLES,
) -> list[ProbeResult]:
    limit = asyncio.Semaphore(max(1, config.PROBE_CONCURRENCY))

    async def guarded(ip: str) -> ProbeResult:
        async with limit:
            return await probe_ip(domain, ip, samples=samples)

    results = await asyncio.gather(*(guarded(ip) for ip in ips))
    return sorted(results, key=lambda r: (not r.ok, r.total_ms))


CANDIDATE_LIMIT = 8
OFFICIAL_FALLBACK_LIMIT = 64
OFFICIAL_FALLBACK_BATCH = 32

SNI_BLOCK_TTL = 3600.0
SNI_BLOCK_MIN_PROBES = 16
SNI_BLOCK_MIN_NETS = 4
SNI_BLOCK_TCP_SAMPLES = 4
REPROBE_COOLDOWN = 20.0
REFRESH_INTERVAL = 900.0


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class IpResolver:
    def __init__(
        self,
        cache: Cache | None = None,
        *,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.cache = cache or Cache()
        self.ttl = config.CACHE_TTL
        self.log = log or (lambda _msg: None)
        self._inflight: dict[str, asyncio.Task[CacheEntry | None]] = {}
        self._background: set[asyncio.Task] = set()
        self._fallback_ok: dict[str, float] = {}
        self._fallback_seeded = False
        self._reprobe_at: dict[str, float] = {}

    def report_failure(self, host: str, ip: str = "") -> None:
        host = (host or "").strip().lower().rstrip(".")
        if not host or _is_ip_literal(host) or not config.is_github_host(host):
            return
        if ip:
            self.cache.evict_ip(host, ip)

        now = time.monotonic()
        if now - self._reprobe_at.get(host, 0.0) < REPROBE_COOLDOWN:
            return
        self._reprobe_at[host] = now
        self.log(f"{host} 的 IP 失效，重新优选")
        self._spawn(self._refresh_quietly(host))

    async def ensure(
        self,
        host: str,
        *,
        samples: int | None = None,
        force: bool = False,
    ) -> CacheEntry | None:
        if not force:
            entry = self.cache.fresh(host, self.ttl)
            if entry:
                return entry
        return await self._join_refresh(host, samples=samples)

    async def candidates(self, host: str) -> list[str]:
        host = host.strip().lower().rstrip(".")
        if not host:
            return []
        if _is_ip_literal(host):
            return [host]
        if not config.is_github_host(host):
            ip = await self._system_resolve(host)
            return [ip] if ip else []

        entry = self.cache.fresh(host, self.ttl)
        if entry is None:
            try:
                entry = await asyncio.shield(self._join_refresh(host))
            except Exception:
                entry = self.cache.get(host)
        if entry is None:
            ip = await self._system_resolve(host)
            return [ip] if ip else []

        ordered = [entry.ip] + [ip for ip in entry.candidates if ip != entry.ip]
        return ordered[:CANDIDATE_LIMIT]

    def start_auto_refresh(self) -> None:
        async def runner() -> None:
            while True:
                await asyncio.sleep(REFRESH_INTERVAL)
                now = time.time()
                stale = [
                    entry.domain
                    for entry in self.cache.snapshot().values()
                    if now - entry.updated > self.ttl * 0.75
                ]
                for host in stale:
                    try:
                        await self._join_refresh(host)
                    except Exception as exc:
                        self.log(f"续期失败 {host}: {exc}")
                if stale:
                    self.cache.save()

        self._spawn(runner())

    def shutdown(self) -> None:
        tasks = list(self._background) + [t for t in self._inflight.values() if not t.done()]
        for task in tasks:
            task.cancel()
        self._background.clear()
        self._inflight.clear()

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _refresh_quietly(self, host: str) -> None:
        try:
            await self._join_refresh(host, samples=1)
        except SniBlocked as exc:
            self.log(str(exc))
        except Exception as exc:
            self.log(f"{host} 重新优选失败: {exc}")

    def _join_refresh(self, host: str, *, samples: int | None = None) -> asyncio.Task[CacheEntry | None]:
        task = self._inflight.get(host)
        if task and not task.done():
            return task

        task = asyncio.create_task(self._refresh(host, samples=samples))
        self._inflight[host] = task

        def _cleanup(done: asyncio.Task) -> None:
            if self._inflight.get(host) is done:
                self._inflight.pop(host, None)

        task.add_done_callback(_cleanup)
        return task

    def _fallback_ips(self, host: str, *, exclude: set[str]) -> list[str]:
        info = current_meta()
        pool = [ip for ip in info.ips if ip not in exclude and is_public_ipv4(ip)]
        if not pool:
            return []

        self._seed_fallback_ok(set(info.ips))
        allowed = set(pool)
        known = sorted(
            (ip for ip in self._fallback_ok if ip in allowed),
            key=lambda ip: -self._fallback_ok[ip],
        )
        rest = [ip for ip in pool if ip not in self._fallback_ok]
        if rest:
            offset = zlib.crc32(host.encode("utf-8")) % len(rest)
            rest = rest[offset:] + rest[:offset]
        return known + rest

    def _seed_fallback_ok(self, official: set[str]) -> None:
        if self._fallback_seeded:
            return
        self._fallback_seeded = True
        for entry in sorted(
            self.cache.snapshot().values(), key=lambda e: e.updated, reverse=True
        ):
            for ip in (entry.ip, *entry.candidates):
                if ip in official and ip not in self._fallback_ok:
                    self._fallback_ok[ip] = entry.updated

    async def _sni_block_verdict(self, host: str, results: list[ProbeResult]) -> bool:
        if len(results) < SNI_BLOCK_MIN_PROBES or any(r.ok for r in results):
            return False

        nets: set[str] = set()
        for r in results:
            if not any(key in r.error for key in _HANDSHAKE_ONLY):
                return False
            nets.add(r.ip.rsplit(".", 2)[0])
        if len(nets) < SNI_BLOCK_MIN_NETS:
            return False

        sample = [r.ip for r in results if not r.ok][:SNI_BLOCK_TCP_SAMPLES]
        checks = await asyncio.gather(*(_tcp_reachable(ip) for ip in sample))
        if not any(checks):
            return False

        self.cache.mark_blocked(host)
        self.log(
            f"{host} 疑似 SNI 阻断（TCP 可达、TLS 全被重置），"
            f"{SNI_BLOCK_TTL / 60:.0f} 分钟内直接跳过"
        )
        return True

    async def _probe_fallback(
        self,
        host: str,
        results: list[ProbeResult],
        sample_count: int,
    ) -> list[ProbeResult]:
        fallback = self._fallback_ips(host, exclude={r.ip for r in results})
        if not fallback:
            return []

        self.log(
            f"{host} DNS 候选全部不可用，改用官方 /32 兜底（候选 {len(fallback)} 个）"
        )
        cap = min(OFFICIAL_FALLBACK_LIMIT, len(fallback))
        start = 0
        now = time.time()
        while start < cap:
            chunk = fallback[start:start + OFFICIAL_FALLBACK_BATCH]
            extra = await probe_domain(host, chunk, samples=sample_count)
            results.extend(extra)

            hit = [r for r in extra if r.ok]
            if hit:
                for r in hit:
                    self._fallback_ok[r.ip] = now
                return hit

            if await self._sni_block_verdict(host, results):
                raise SniBlocked(
                    f"{host} 疑似 SNI 阻断（TCP 可达、TLS 全被重置），跳过"
                )

            start += OFFICIAL_FALLBACK_BATCH
            if start >= cap and cap < len(fallback):
                self.log(
                    f"{host} 前 {cap} 个官方 /32 都不通，扩大到全部 {len(fallback)} 个"
                )
                cap = len(fallback)
        return []

    async def _refresh(self, host: str, *, samples: int | None = None) -> CacheEntry | None:
        if self.cache.blocked(host, SNI_BLOCK_TTL):
            raise SniBlocked(
                f"{host} 已判定为 SNI 阻断，{SNI_BLOCK_TTL / 60:.0f} 分钟内跳过"
            )

        started = time.perf_counter()
        dns_failure = ""
        try:
            mapping = await resolve_dns(host)
        except DnsError as exc:
            dns_failure = str(exc)
            self.log(f"{host} 解析失败（{dns_failure}），转向官方 /32 兜底")
            mapping = {}
        ips = list(mapping)
        sample_count = samples or config.PROBE_SAMPLES

        results = (
            await probe_domain(host, ips, samples=sample_count) if ips else []
        )
        blocked = sum(
            1
            for r in results
            if not r.ok and any(k in r.error for k in _UNSERVING_MARKERS)
        )
        if blocked:
            self.log(f"{host} 排除 {blocked} 个不服务该域名的 IP（拒绝页/健康检查/跳 github.com）")

        alive = [r for r in results if r.ok]

        if not alive:
            alive = await self._probe_fallback(host, results, sample_count)
        probed = len(results)

        if not alive:
            reasons: dict[str, int] = {}
            for result in results:
                reason = result.error or "不可达"
                reasons[reason] = reasons.get(reason, 0) + 1
            detail = "、".join(
                f"{reason}×{count}" if count > 1 else reason
                for reason, count in reasons.items()
            )
            raise RuntimeError(
                f"DNS 解析失败且兜底地址池为空（{dns_failure}）"
                if not results and dns_failure
                else f"所有候选 IP 均不可用（{detail or dns_failure or '没有候选'}）"
            )

        self.cache.clear_blocked(host)

        best = alive[0]
        ordered = [r.ip for r in alive] + [
            r.ip
            for r in results
            if not r.ok and not any(k in r.error for k in _UNSERVING_MARKERS)
        ]
        entry = self.cache.put(host, best.ip, best.total_ms, ordered)
        self.cache.save()
        self.log(
            f"优选 {host} -> {best.ip} ({best.total_ms:.0f} ms, "
            f"{len(alive)}/{probed} 可用, {time.perf_counter() - started:.1f}s)"
        )
        return entry

    async def _system_resolve(self, host: str) -> str | None:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        except OSError:
            return None
        return infos[0][4][0] if infos else None


def all_domains() -> list[str]:
    seen: dict[str, None] = {d: None for d in config.builtin_domains()}
    try:
        for domain in current_meta().accelerated:
            seen.setdefault(domain, None)
    except Exception:
        pass
    return list(seen)


def split_domains() -> tuple[list[str], list[str]]:
    core: list[str] = []
    rest: list[str] = []
    for domain in all_domains():
        (core if config.is_core_domain(domain) else rest).append(domain)
    return core, rest
