from __future__ import annotations

import asyncio
import contextlib
import ctypes
import itertools
import queue
import socket
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import config
import net
import store
import syscfg
from net import IpResolver
from proxy import ProxyServer
from store import Cache

APP_TITLE = "GHX"
MUTED = "#6b7280"

WARMUP_TIMEOUT = 90.0
WARMUP_CONCURRENCY = 8

CORE_WARMUP_TIMEOUT = 30.0
REST_WARMUP_CONCURRENCY = 3

STOP_WATCHDOG_MS = 12000

BOOST_STYLE: dict[str, dict[str, str]] = {
    "idle": {
        "disc": "#2563eb", "ring": "#dbeafe", "halo": "#eff6ff",
        "title": "一键加速", "sub": "点击启动",
    },
    "starting": {
        "disc": "#d97706", "ring": "#fde68a", "halo": "#fffbeb",
        "title": "启动中", "sub": "正在优选 IP",
    },
    "running": {
        "disc": "#059669", "ring": "#a7f3d0", "halo": "#ecfdf5",
        "title": "停止加速", "sub": "启动成功",
    },
    "stopping": {
        "disc": "#6b7280", "ring": "#e5e7eb", "halo": "#f9fafb",
        "title": "停止中", "sub": "正在恢复设置",
    },
    "error": {
        "disc": "#dc2626", "ring": "#fecaca", "halo": "#fef2f2",
        "title": "重试", "sub": "启动失败",
    },
}

BOOST_HOVER = {"idle": "#1d4ed8", "running": "#047857", "error": "#b91c1c"}

_RUNNER_UID = itertools.count(1)


def _font() -> tuple[str, int]:
    return ("Microsoft YaHei UI", 10) if sys.platform == "win32" else ("Helvetica", 10)


def format_bytes(size: int) -> str:
    value = float(max(0, int(size)))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.0f} B"


def pick_port() -> int:
    preferred = config.DEFAULT_PORT
    for port in range(preferred, min(preferred + 50, 65536)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    return 0


class ProxyRunner(threading.Thread):
    def __init__(self, port: int, bus: queue.Queue) -> None:
        super().__init__(daemon=True, name="ghx-proxy")
        self.port = port
        self.bus = bus
        self.uid = next(_RUNNER_UID)
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server: ProxyServer | None = None
        self.resolver: IpResolver | None = None
        self._rest_task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self._stop_requested = False
        self._stopped = False

    def run(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._main())
        except Exception as exc:
            if not self._stopped:
                self.bus.put(("proxy_state", ("error", str(exc), self.uid)))
        finally:
            self._drain_tasks()
            self.loop.close()

    def _drain_tasks(self) -> None:
        pending = [t for t in asyncio.all_tasks(self.loop) if not t.done()]
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        try:
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        except Exception:
            pass

    async def _main(self) -> None:
        cache = Cache()
        self.resolver = IpResolver(cache)
        self.server = ProxyServer(self.resolver, host="127.0.0.1", port=self.port)
        host, port = await self.server.start()
        self.port = port
        url = f"http://{host}:{port}"
        self._stop_event = asyncio.Event()
        if self._stop_requested:
            self._stop_event.set()
        self.bus.put(("proxy_state", ("listening", url, self.uid)))

        try:
            await self._warmup_core()

            if self._stop_requested:
                return

            self.bus.put(("proxy_state", ("running", url, self.uid)))
            self._rest_task = asyncio.create_task(self._warmup_rest())
            self.resolver.start_auto_refresh()
            await self._stop_event.wait()
        finally:
            await self._shutdown(cache)

    async def _shutdown(self, cache: Cache) -> None:
        task = self._rest_task
        self._rest_task = None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(task, return_exceptions=True)
        try:
            if self.server is not None:
                await self.server.stop()
        except Exception:
            pass
        try:
            if self.resolver is not None:
                self.resolver.shutdown()
        except Exception:
            pass
        try:
            cache.save()
        except Exception:
            pass
        self._stopped = True
        self.bus.put(("proxy_state", ("stopped", "", self.uid)))

    async def _warmup_core(self) -> None:
        if self.resolver is None:
            return
        await self._run_warmup(
            config.core_domains(),
            progress=True,
            timeout=CORE_WARMUP_TIMEOUT,
            concurrency=WARMUP_CONCURRENCY,
            force=True,
        )

    async def _warmup_rest(self) -> None:
        if self.resolver is None:
            return
        try:
            await asyncio.wait_for(
                asyncio.to_thread(net.ensure_fresh_meta, 6.0), timeout=7.0
            )
        except Exception:
            pass
        if self._stop_requested:
            return
        _, rest = net.split_domains()
        await self._run_warmup(
            rest,
            progress=False,
            timeout=WARMUP_TIMEOUT,
            concurrency=REST_WARMUP_CONCURRENCY,
            force=False,
        )

    async def _run_warmup(
        self,
        targets: list[str],
        *,
        progress: bool,
        timeout: float | None,
        concurrency: int,
        force: bool,
    ) -> None:
        if self.resolver is None or not targets:
            return
        total = len(targets)
        done = 0
        gate = asyncio.Semaphore(max(1, concurrency))
        if progress:
            self.bus.put(("warmup", (0, total)))

        async def one(host: str) -> None:
            nonlocal done
            async with gate:
                try:
                    if not self._stop_requested:
                        await self.resolver.ensure(host, samples=1, force=force)
                except Exception:
                    pass
                finally:
                    done += 1
                    if progress:
                        self.bus.put(("warmup", (done, total)))

        coro = asyncio.gather(*(one(h) for h in targets), return_exceptions=True)
        if timeout is None:
            await coro
            return
        try:
            await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            pass

    def stop(self) -> None:
        self._stop_requested = True
        loop = self.loop
        if loop is None or loop.is_closed():
            return
        event = self._stop_event
        if event is None or not event.is_set():
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(self._wake_stop)

    def _wake_stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()


class GhxApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("480x580")
        self.minsize(400, 520)

        self.bus: queue.Queue = queue.Queue()
        self.proxy: ProxyRunner | None = None

        self.syscfg = syscfg.SystemProxy()
        self._boost_state = "idle"
        self._boost_pending = False
        self._boost_hover = False

        self.usage = store.Usage()
        self.usage_vars: dict[str, tk.StringVar] = {}
        self._usage_mark: tuple[int, int, int] = (0, 0, 0)
        self._usage_server: object | None = None

        self._git_snapshot: dict | None = None
        self._active_port = config.DEFAULT_PORT

        self._setup_style()
        self._build_header()
        self._build_body()

        self.after(80, self._drain)
        self.after(1000, self._tick)
        self.after(300, self._check_stale_proxy)
        self.after(420, self._check_stale_git_proxy)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        try:
            if sys.platform == "win32" and "vista" in style.theme_names():
                style.theme_use("vista")
        except tk.TclError:
            pass
        family, size = _font()
        self.option_add("*Font", (family, size))
        style.configure("Treeview", rowheight=26, font=(family, size))
        style.configure("Title.TLabel", font=(family, 16, "bold"))
        style.configure("Sub.TLabel", foreground=MUTED, font=(family, 9))
        style.configure("Strong.TLabel", font=(family, 10, "bold"))
        style.configure("Card.TLabelframe", padding=12)

    def _build_header(self) -> None:
        bar = ttk.Frame(self, padding=(16, 12, 16, 8))
        bar.pack(fill="x")
        ttk.Label(bar, text="GitHub 加速器", style="Title.TLabel").pack(side="left")

    def _build_body(self) -> None:
        body = ttk.Frame(self, padding=(16, 0, 16, 14))
        body.pack(fill="both", expand=True)
        self._build_usage(body)
        self._build_boost(body)

    def _build_boost(self, parent: ttk.Frame) -> None:
        bg = ttk.Style(self).lookup("TFrame", "background") or "#f0f0f0"
        self.boost_canvas = tk.Canvas(
            parent, width=320, height=320, highlightthickness=0, bg=bg, cursor="hand2"
        )
        self.boost_canvas.pack(expand=True)

        canvas = self.boost_canvas
        cx = cy = 160
        self._halo_id = canvas.create_oval(cx - 152, cy - 152, cx + 152, cy + 152,
                                           outline="", fill="#eff6ff")
        self._ring_id = canvas.create_oval(cx - 128, cy - 128, cx + 128, cy + 128,
                                           outline="", fill="#dbeafe")
        self._disc_id = canvas.create_oval(cx - 108, cy - 108, cx + 108, cy + 108,
                                           outline="", fill="#2563eb")
        self._title_id = canvas.create_text(cx, cy - 10, text="一键加速", fill="white",
                                            font=(_font()[0], 22, "bold"))
        self._sub_id = canvas.create_text(cx, cy + 26, text="点击启动", fill="#dbeafe",
                                          font=(_font()[0], 9))
        canvas.bind("<Button-1>", self._on_boost_click)
        canvas.bind("<Motion>", self._on_boost_motion)
        canvas.bind("<Leave>", self._on_boost_leave)
        self._set_boost_state("idle")

    def _set_boost_state(self, state: str) -> None:
        self._boost_state = state
        style = BOOST_STYLE[state]
        canvas = getattr(self, "boost_canvas", None)
        if canvas is not None:
            disc = BOOST_HOVER.get(state, style["disc"]) if self._boost_hover else style["disc"]
            canvas.itemconfigure(self._halo_id, fill=style["halo"])
            canvas.itemconfigure(self._ring_id, fill=style["ring"])
            canvas.itemconfigure(self._disc_id, fill=disc)
            canvas.itemconfigure(self._title_id, text=style["title"])
            canvas.itemconfigure(self._sub_id, text=style["sub"])

    def _on_boost_click(self, event: tk.Event) -> None:
        if (event.x - 160) ** 2 + (event.y - 160) ** 2 > 108 ** 2:
            return
        if self._boost_state in ("starting", "stopping"):
            return
        if self._boost_state == "running":
            self._stop_boost()
        else:
            self._start_boost()

    def _on_boost_motion(self, event: tk.Event) -> None:
        inside = (event.x - 160) ** 2 + (event.y - 160) ** 2 <= 108 ** 2
        if inside != self._boost_hover:
            self._boost_hover = inside
            self._set_boost_state(self._boost_state)

    def _on_boost_leave(self, _event: tk.Event) -> None:
        if self._boost_hover:
            self._boost_hover = False
            self._set_boost_state(self._boost_state)

    def _proxy_url(self) -> str:
        if self.proxy is not None:
            return f"http://127.0.0.1:{self.proxy.port}"
        return f"http://127.0.0.1:{self._active_port}"

    def _start_boost(self) -> None:
        if not self.syscfg.available:
            messagebox.showwarning(
                "暂不支持",
                "自动配置系统代理目前只支持 Windows。",
            )
            return

        if self.proxy and self.proxy.is_alive():
            self._boost_pending = True
            self._apply_system_proxy(self._proxy_url())
            return

        port = pick_port()
        self._active_port = port or config.DEFAULT_PORT

        self._set_boost_state("starting")
        self._boost_pending = True
        self._usage_mark = (0, 0, 0)
        self._usage_server = None

        self.proxy = ProxyRunner(port, self.bus)
        self.proxy.start()

    def _stop_boost(self) -> None:
        self._set_boost_state("stopping")
        self._restore_system_proxy()
        self._restore_git_proxy()
        runner = self.proxy
        if runner is not None and runner.is_alive():
            runner.stop()
            self.after(STOP_WATCHDOG_MS, self._stop_watchdog)
        else:
            self.proxy = None
            self._set_boost_state("idle")

    def _stop_watchdog(self) -> None:
        if self._boost_state != "stopping":
            return
        self._settle_usage()
        runner, self.proxy = self.proxy, None
        self._set_boost_state("idle")
        if runner is not None and runner.is_alive():
            messagebox.showwarning(
                "停止超时",
                "代理线程没有在预期时间内退出，界面已复位。\n"
                "如果仍然无法上网，请重新点一次「一键加速」再停止。",
            )

    def _apply_system_proxy(self, url: str) -> None:
        server = url[len("http://"):] if url.startswith("http://") else url
        pac_url = f"http://{server}{syscfg.PAC_PATH}"
        try:
            before = self.syscfg.enable_pac(pac_url)
        except Exception as exc:
            self._boost_pending = False
            self._set_boost_state("error")
            messagebox.showerror("设置系统代理失败", str(exc))
            return

        syscfg.save_proxy_backup(before, server, mode=syscfg.MODE_PAC, pac_url=pac_url)
        self._boost_pending = False
        self._set_boost_state("running")

        port = 0
        tail = server.rsplit(":", 1)
        if len(tail) == 2 and tail[1].isdigit():
            port = int(tail[1])
        if port:
            self._apply_git_proxy(port)

    def _restore_system_proxy(self) -> bool:
        if not self.syscfg.has_snapshot():
            return False
        try:
            self.syscfg.restore()
            syscfg.clear_proxy_backup()
            return True
        except Exception:
            return False

    def _check_stale_proxy(self) -> None:
        if not self.syscfg.available:
            return
        backup = syscfg.load_proxy_backup()
        if not backup:
            return
        if syscfg.pid_alive(int(backup.get("pid") or 0)):
            return

        try:
            snapshot = syscfg.Snapshot.from_dict(backup.get("snapshot") or {})
            current = self.syscfg.current()
            if backup.get("mode") == syscfg.MODE_PAC:
                ours = (current.auto_config_url or "") == (backup.get("pac_url") or "")
            else:
                ours = (current.server or "") == (backup.get("server") or "")
            if not ours:
                syscfg.clear_proxy_backup()
                return
            self.syscfg.restore(snapshot)
            syscfg.clear_proxy_backup()
            messagebox.showinfo(
                "已自动修复",
                "上次程序异常退出，系统代理还指向本地端口。\n"
                "这会让浏览器无法上网，已为你还原到原来的设置。",
            )
        except Exception:
            pass

    def _build_usage(self, parent: ttk.Frame) -> None:
        box = ttk.LabelFrame(parent, text="用量信息", style="Card.TLabelframe")
        box.pack(side="bottom", fill="x")

        figures = ttk.Frame(box)
        figures.pack(fill="x")
        for index, (key, label) in enumerate((("requests", "请求数"), ("traffic", "流量"))):
            figures.columnconfigure(index, weight=1)
            cell = ttk.Frame(figures)
            cell.grid(row=0, column=index, sticky="nsew")
            var = tk.StringVar(value="0")
            ttk.Label(
                cell, textvariable=var, font=(_font()[0], 18, "bold"), anchor="center"
            ).pack(fill="x")
            ttk.Label(cell, text=label, style="Sub.TLabel", anchor="center").pack(fill="x")
            self.usage_vars[key] = var

        self._refresh_usage()

    def _apply_git_proxy(self, port: int) -> None:
        if self._git_snapshot is not None:
            if syscfg.git_points_to(port):
                return
            self._restore_git_proxy()
        if not syscfg.git_available():
            return
        try:
            snap = syscfg.apply_git(port)
        except syscfg.GitError:
            return
        self._git_snapshot = snap
        syscfg.save_git_backup(snap, port)

    def _restore_git_proxy(self) -> None:
        if self._git_snapshot is None:
            return
        snap, self._git_snapshot = self._git_snapshot, None
        try:
            syscfg.restore_git(snap)
        except Exception:
            pass
        finally:
            syscfg.clear_git_backup()

    def _check_stale_git_proxy(self) -> None:
        if not syscfg.git_available():
            return
        backup = syscfg.load_git_backup()
        if not backup:
            return
        if syscfg.pid_alive(int(backup.get("pid") or 0)):
            return

        port = int(backup.get("port") or 0)
        if not port or not syscfg.git_points_to(port):
            syscfg.clear_git_backup()
            return
        try:
            syscfg.restore_git(backup.get("snapshot") or {})
            syscfg.clear_git_backup()
        except Exception:
            pass

    def _on_proxy_state(self, payload) -> None:
        state, detail, uid = payload
        if self.proxy is not None and uid != self.proxy.uid:
            return
        if state == "running":
            if self._boost_pending and self._boost_state == "starting":
                self._apply_system_proxy(detail)
        elif state == "error":
            self._boost_pending = False
            self._set_boost_state("error")
            messagebox.showerror("代理启动失败", detail)
        elif state == "stopped":
            self._settle_usage()
            self.proxy = None
            self._restore_system_proxy()
            self._restore_git_proxy()
            self._boost_pending = False
            self._set_boost_state("idle")

    def _on_warmup(self, payload) -> None:
        done, total = payload
        if self._boost_state != "starting":
            return
        canvas = getattr(self, "boost_canvas", None)
        if canvas is not None:
            canvas.itemconfigure(self._sub_id, text=f"优选 {done}/{total}")

    def _refresh_usage(self) -> None:
        if not self.usage_vars:
            return
        self.usage_vars["requests"].set(f"{self.usage.requests:,}")
        self.usage_vars["traffic"].set(format_bytes(self.usage.total_bytes))

    def _track_usage(self, server) -> None:
        stats = server.stats
        if server is not self._usage_server:
            self._usage_server = server
            self._usage_mark = (0, 0, 0)
        current = (stats.requests, stats.bytes_up, stats.bytes_down)
        mark = self._usage_mark
        if any(cur < old for cur, old in zip(current, mark)):
            self._usage_mark = current
            return
        delta = tuple(cur - old for cur, old in zip(current, mark))
        if not any(delta):
            return
        self._usage_mark = current
        self.usage.add(delta[0], delta[1], delta[2])
        self._refresh_usage()

    def _settle_usage(self) -> None:
        server = self.proxy.server if self.proxy is not None else None
        if server is not None:
            self._track_usage(server)
        self.usage.save(force=True)

    def _drain(self) -> None:
        try:
            for _ in range(200):
                kind, payload = self.bus.get_nowait()
                if kind == "proxy_state":
                    self._on_proxy_state(payload)
                elif kind == "warmup":
                    self._on_warmup(payload)
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _tick(self) -> None:
        server = self.proxy.server if self.proxy else None
        if server is not None:
            self._track_usage(server)
        self.after(1000, self._tick)

    def _on_close(self) -> None:
        if self.proxy and self.proxy.is_alive():
            if not messagebox.askokcancel("退出", "代理仍在运行，退出会停止代理。继续？"):
                return
            self._restore_system_proxy()
            self._restore_git_proxy()
            self.proxy.stop()
            self.proxy.join(timeout=3)
        else:
            self._restore_system_proxy()
            self._restore_git_proxy()
        self._settle_usage()
        self.destroy()


def main() -> int:
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    selftest = "--selftest" in sys.argv
    app = GhxApp()
    if selftest:
        app.after(1500, app.destroy)
    app.mainloop()
    if selftest:
        print("GUI SELFTEST OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
