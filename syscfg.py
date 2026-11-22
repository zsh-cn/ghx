from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass

import config

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
VALUE_ENABLE = "ProxyEnable"
VALUE_SERVER = "ProxyServer"
VALUE_OVERRIDE = "ProxyOverride"
VALUE_AUTOCONFIG = "AutoConfigURL"
DEFAULT_OVERRIDE = "<local>"

MODE_MANUAL = "manual"
MODE_PAC = "pac"
PAC_PATH = "/proxy.pac"

_INTERNET_OPTION_REFRESH = 37
_INTERNET_OPTION_SETTINGS_CHANGED = 39

PROXY_BACKUP = config.HOME_DIR / "system_proxy_backup.json"


def supported() -> bool:
    return sys.platform == "win32"


class WinRegBackend:
    def __init__(self, path: str = REG_PATH) -> None:
        self.path = path

    def read(self) -> dict[str, object]:
        import winreg

        out: dict[str, object] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.path) as key:
                for name in (VALUE_ENABLE, VALUE_SERVER, VALUE_OVERRIDE, VALUE_AUTOCONFIG):
                    try:
                        out[name] = winreg.QueryValueEx(key, name)[0]
                    except FileNotFoundError:
                        out[name] = None
        except FileNotFoundError:
            out = {name: None for name in
                   (VALUE_ENABLE, VALUE_SERVER, VALUE_OVERRIDE, VALUE_AUTOCONFIG)}
        return out

    def write(self, values: dict[str, object]) -> None:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, self.path, 0, winreg.KEY_SET_VALUE
        ) as key:
            for name, value in values.items():
                if value is None:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
                elif name == VALUE_ENABLE:
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
                else:
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))


@dataclass
class Snapshot:
    enabled: int
    server: str | None
    override: str | None
    auto_config_url: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "server": self.server,
            "override": self.override,
            "auto_config_url": self.auto_config_url,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        return cls(
            enabled=int(data.get("enabled") or 0),
            server=data.get("server"),
            override=data.get("override"),
            auto_config_url=data.get("auto_config_url"),
        )


def notify_change() -> None:
    if not supported():
        return
    try:
        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


class SystemProxy:
    def __init__(self) -> None:
        self.backend: WinRegBackend | None = WinRegBackend() if supported() else None
        self._snapshot: Snapshot | None = None

    @property
    def available(self) -> bool:
        return self.backend is not None

    def current(self) -> Snapshot:
        if self.backend is None:
            raise RuntimeError("当前平台不支持自动配置系统代理")
        raw = self.backend.read()
        enabled = raw.get(VALUE_ENABLE) or 0
        server = raw.get(VALUE_SERVER)
        override = raw.get(VALUE_OVERRIDE)
        auto = raw.get(VALUE_AUTOCONFIG)
        return Snapshot(
            enabled=int(enabled),
            server=str(server) if server else None,
            override=str(override) if override else None,
            auto_config_url=str(auto) if auto else None,
        )

    def has_snapshot(self) -> bool:
        return self._snapshot is not None

    def enable(self, server: str) -> Snapshot:
        if self.backend is None:
            raise RuntimeError("当前平台不支持自动配置系统代理")
        before = self.current()
        self._snapshot = before
        self.backend.write(
            {
                VALUE_ENABLE: 1,
                VALUE_SERVER: server,
                VALUE_OVERRIDE: DEFAULT_OVERRIDE,
                VALUE_AUTOCONFIG: None,
            }
        )
        notify_change()
        return before

    def enable_pac(self, pac_url: str) -> Snapshot:
        if self.backend is None:
            raise RuntimeError("当前平台不支持自动配置系统代理")
        before = self.current()
        self._snapshot = before
        self.backend.write(
            {
                VALUE_ENABLE: 0,
                VALUE_SERVER: None,
                VALUE_OVERRIDE: None,
                VALUE_AUTOCONFIG: pac_url,
            }
        )
        notify_change()
        return before

    def restore(self, snapshot: Snapshot | None = None) -> bool:
        snap = snapshot or self._snapshot
        if self.backend is None or snap is None:
            return False
        self.backend.write(
            {
                VALUE_ENABLE: snap.enabled,
                VALUE_SERVER: snap.server,
                VALUE_OVERRIDE: snap.override,
                VALUE_AUTOCONFIG: snap.auto_config_url,
            }
        )
        notify_change()
        self._snapshot = None
        return True


def save_proxy_backup(
    snapshot: Snapshot,
    server: str,
    *,
    mode: str = MODE_MANUAL,
    pac_url: str | None = None,
) -> None:
    payload = {
        "snapshot": snapshot.as_dict(),
        "server": server,
        "mode": mode,
        "pac_url": pac_url,
        "pid": os.getpid(),
        "at": time.time(),
    }
    _write_json(PROXY_BACKUP, payload)


def load_proxy_backup() -> dict | None:
    return _read_backup(PROXY_BACKUP)


def clear_proxy_backup() -> None:
    try:
        os.remove(PROXY_BACKUP)
    except OSError:
        pass


GIT_SCOPED_KEYS: dict[str, str] = {
    "http.https://github.com/.proxy": "http://127.0.0.1:{port}",
    "https.https://github.com/.proxy": "http://127.0.0.1:{port}",
    "http.https://codeload.github.com/.proxy": "http://127.0.0.1:{port}",
    "https.https://codeload.github.com/.proxy": "http://127.0.0.1:{port}",
}

GIT_BACKUP = config.HOME_DIR / "git_proxy_backup.json"


class GitError(RuntimeError):
    pass


def _git_run(args: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except FileNotFoundError as exc:
        raise GitError("未找到 git，请先安装 Git 并确保在 PATH 中") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git 命令超时") from exc
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip()


def git_available() -> bool:
    try:
        ok, _ = _git_run(["--version"])
        return ok
    except GitError:
        return False


def git_snapshot() -> dict[str, str | None]:
    snap: dict[str, str | None] = {}
    for key in GIT_SCOPED_KEYS:
        ok, out = _git_run(["config", "--global", "--get", key])
        snap[key] = out.strip() if ok and out.strip() else None
    return snap


def apply_git(port: int) -> dict[str, str | None]:
    snap = git_snapshot()
    value = f"http://127.0.0.1:{port}"
    for key in GIT_SCOPED_KEYS:
        ok, out = _git_run(["config", "--global", key, value])
        if not ok:
            raise GitError(f"设置 {key} 失败: {out}")
    return snap


def restore_git(snap: dict[str, str | None]) -> None:
    for key, value in snap.items():
        if value is None:
            _git_run(["config", "--global", "--unset-all", key])
        else:
            _git_run(["config", "--global", key, value])


def git_points_to(port: int) -> bool:
    ok, out = _git_run(["config", "--global", "--get", "http.https://github.com/.proxy"])
    return ok and out == f"http://127.0.0.1:{port}"


def save_git_backup(snap: dict, port: int) -> None:
    payload = {
        "snapshot": snap,
        "port": port,
        "pid": os.getpid(),
        "at": time.time(),
    }
    _write_json(GIT_BACKUP, payload)


def load_git_backup() -> dict | None:
    return _read_backup(GIT_BACKUP)


def clear_git_backup() -> None:
    try:
        os.remove(GIT_BACKUP)
    except OSError:
        pass


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _write_json(path, payload: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass


def _read_backup(path) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) and "snapshot" in data else None
