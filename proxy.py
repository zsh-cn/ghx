from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from config import GITHUB_SUFFIXES, MAX_HEADER
from net import IpResolver, all_domains

BUF_SIZE = 64 * 1024
CONNECT_TIMEOUT = 4.0
HEADER_TIMEOUT = 30.0
STOP_TIMEOUT = 2.0
CRLF = b"\r\n"


@dataclass
class ProxyStats:
    requests: int = 0
    bytes_up: int = 0
    bytes_down: int = 0


class ProxyServer:
    def __init__(
        self,
        resolver: IpResolver,
        *,
        host: str = "127.0.0.1",
        port: int = 7801,
        log=None,
    ) -> None:
        self.resolver = resolver
        self.host = host
        self.port = port
        self._log = log or (lambda _m: None)
        self.stats = ProxyStats()
        self._server: asyncio.base_events.Server | None = None
        self._closing = False
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
            limit=MAX_HEADER,
            reuse_address=True,
        )
        sockets = self._server.sockets or []
        if sockets:
            self.port = sockets[0].getsockname()[1]
        return self.host, self.port

    async def stop(self) -> None:
        self._closing = True
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.close()
        self._drop_connections()
        if self._server is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=STOP_TIMEOUT)

    def _drop_connections(self) -> None:
        for writer in list(self._writers):
            self._abort(writer)
        self._writers.clear()

    @staticmethod
    def _abort(writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            transport = writer.transport
            if transport is not None and not transport.is_closing():
                transport.abort()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        self._writers.add(writer)
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(CRLF + CRLF), HEADER_TIMEOUT)
            except (
                asyncio.TimeoutError,
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
                ConnectionResetError,
            ):
                return

            try:
                first_line = head.split(CRLF, 1)[0]
                parts = first_line.split(b" ")
                if len(parts) < 2:
                    raise ValueError("请求行格式错误")
                method = parts[0].decode("latin-1").upper()
                target = parts[1].decode("latin-1")
                version = parts[2].decode("latin-1") if len(parts) > 2 else "HTTP/1.1"

                if method == "CONNECT":
                    self.stats.requests += 1
                    upstream_writer = await self._do_connect(reader, writer, target)
                elif _is_pac_request(target):
                    await self._serve_pac(writer)
                else:
                    self.stats.requests += 1
                    upstream_writer = await self._do_plain(
                        reader, writer, head, method, target, version
                    )
            except _ProxyError as exc:
                self._log(f"✗ {exc}")
                with contextlib.suppress(Exception):
                    writer.write(_error_response(exc.status, str(exc)))
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
            except Exception as exc:
                self._log(f"✗ 连接异常 {peer}: {exc}")
        finally:
            if upstream_writer is not None:
                self._release(upstream_writer)
            self._release(writer)

    async def _do_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
    ) -> asyncio.StreamWriter:
        try:
            host, port = _split_authority(target, 443)
        except ValueError as exc:
            raise _ProxyError(400, f"CONNECT 目标无效: {target}") from exc

        started = time.perf_counter()
        ip, upstream = await self._open_upstream(host, port)
        elapsed = (time.perf_counter() - started) * 1000

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        self._log(f"→ {host}:{port} via {ip} ({elapsed:.0f} ms)")

        await self._pump_both(reader, writer, upstream[0], upstream[1])
        return upstream[1]

    async def _do_plain(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        head: bytes,
        method: str,
        target: str,
        version: str,
    ) -> asyncio.StreamWriter:
        parsed = urlsplit(target)
        if not parsed.scheme or not parsed.hostname:
            raise _ProxyError(400, "仅支持代理模式请求（absolute-form URL）")

        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        payload = _rewrite_head(head, method, path, version)
        ip, upstream = await self._open_upstream(host, port)

        self._log(f"→ {method} {host}{path} via {ip}")

        upstream[1].write(payload)
        await upstream[1].drain()
        await self._pump_both(reader, writer, upstream[0], upstream[1])
        return upstream[1]

    def pac_text(self) -> str:
        proxy = f"PROXY 127.0.0.1:{self.port}"
        hosts = all_domains()
        rules: list[str] = []
        for suffix in GITHUB_SUFFIXES:
            rules.append(
                f'  if (shExpMatch(host, "*{suffix}")) return "{proxy}; DIRECT";'
            )
        for domain in sorted(set(hosts)):
            rules.append(f'  if (host === "{domain}") return "{proxy}; DIRECT";')
        return "\n".join(
            [
                "function FindProxyForURL(url, host) {",
                "  host = host.toLowerCase();",
                *rules,
                '  return "DIRECT";',
                "}",
                "",
            ]
        )

    async def _serve_pac(self, writer: asyncio.StreamWriter) -> None:
        body = self.pac_text().encode("utf-8")
        head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/x-ns-proxy-autoconfig\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1")
        writer.write(head + body)
        await writer.drain()

    async def _open_upstream(
        self, host: str, port: int
    ) -> tuple[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        candidates = await self.resolver.candidates(host)
        if not candidates:
            self.resolver.report_failure(host)
            raise _ProxyError(502, f"无法解析 {host}")

        failures = 0
        last_error = ""
        for ip in candidates:
            try:
                upstream = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), CONNECT_TIMEOUT
                )
            except Exception as exc:
                failures += 1
                last_error = f"{ip}: {exc}"
                self._log(f"↻ {host} 的 {ip} 不通，换下一个")
                self.resolver.report_failure(host, ip)
                continue
            if failures:
                self._log(f"✓ {host} 第 {failures + 1} 个候选 {ip} 连接成功")
            self._writers.add(upstream[1])
            return ip, upstream

        raise _ProxyError(
            502, f"连接 {host} 失败（试过 {failures} 个 IP，最后一个：{last_error}）"
        )

    async def _pump_both(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        await asyncio.gather(
            self._pump(client_reader, upstream_writer, upload=True),
            self._pump(upstream_reader, client_writer, upload=False),
        )

    async def _pump(
        self,
        src: asyncio.StreamReader,
        dst: asyncio.StreamWriter,
        *,
        upload: bool,
    ) -> None:
        try:
            while not self._closing:
                chunk = await src.read(BUF_SIZE)
                if not chunk:
                    break
                if upload:
                    self.stats.bytes_up += len(chunk)
                else:
                    self.stats.bytes_down += len(chunk)
                dst.write(chunk)
                await dst.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                if dst.can_write_eof():
                    dst.write_eof()

    def _release(self, writer: asyncio.StreamWriter) -> None:
        self._writers.discard(writer)
        with contextlib.suppress(Exception):
            writer.close()


class _ProxyError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _is_pac_request(target: str) -> bool:
    path = target
    if "://" in target:
        try:
            path = urlsplit(target).path
        except ValueError:
            return False
    return path.split("?")[0].rstrip("/").endswith("proxy.pac")


def _error_response(status: int, message: str) -> bytes:
    body = f"ghx proxy: {message}\n".encode("utf-8")
    reason = {400: "Bad Request", 502: "Bad Gateway", 504: "Gateway Timeout"}.get(status, "Error")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")
    return head + body


def _rewrite_head(head: bytes, method: str, path: str, version: str) -> bytes:
    body = head[:-4] if head.endswith(CRLF + CRLF) else head
    lines = body.split(CRLF)
    out = [f"{method} {path} {version}".encode("latin-1", "replace")]
    for line in lines[1:]:
        low = line.lower()
        if low.startswith((b"proxy-connection:", b"proxy-authorization:", b"connection:")):
            continue
        out.append(line)
    out.append(b"Connection: close")
    return CRLF.join(out) + CRLF + CRLF


def _split_authority(target: str, default_port: int) -> tuple[str, int]:
    target = target.strip()
    if not target:
        raise ValueError("空目标")

    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port_text = rest.lstrip(":")
        return host, int(port_text) if port_text else default_port

    host, sep, port_text = target.rpartition(":")
    if sep and port_text.isdigit():
        return host, int(port_text)
    return target, default_port
