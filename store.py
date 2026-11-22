from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import config

CACHE_VERSION = 2


@dataclass(slots=True)
class CacheEntry:
    domain: str
    ip: str
    latency_ms: float
    candidates: list[str]
    updated: float

    def age(self) -> float:
        return max(0.0, time.time() - self.updated)

    def is_fresh(self, ttl: float = config.CACHE_TTL) -> bool:
        return bool(self.ip) and self.age() < ttl


class Cache:
    def __init__(self) -> None:
        self.path = config.CACHE_FILE
        self._entries: dict[str, CacheEntry] = {}
        self._blocked: dict[str, float] = {}
        self._dirty = False
        self.load()

    def load(self) -> None:
        self._entries.clear()
        self._blocked.clear()
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if payload.get("version") != CACHE_VERSION:
            return
        for domain, stamp in (payload.get("blocked") or {}).items():
            try:
                self._blocked[str(domain).lower()] = float(stamp)
            except (TypeError, ValueError):
                continue
        for domain, raw in (payload.get("entries") or {}).items():
            if not isinstance(raw, dict) or not raw.get("ip"):
                continue
            try:
                self._entries[domain] = CacheEntry(
                    domain=domain,
                    ip=str(raw["ip"]),
                    latency_ms=float(raw.get("latency_ms") or 0.0),
                    candidates=[str(c) for c in raw.get("candidates") or []],
                    updated=float(raw.get("updated") or 0.0),
                )
            except (TypeError, ValueError):
                continue

    def save(self) -> None:
        if not self._dirty:
            return
        payload = {
            "version": CACHE_VERSION,
            "saved_at": time.time(),
            "blocked": self._blocked,
            "entries": {
                domain: {
                    "ip": entry.ip,
                    "latency_ms": round(entry.latency_ms, 1),
                    "candidates": entry.candidates,
                    "updated": entry.updated,
                }
                for domain, entry in self._entries.items()
            },
        }
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError:
            pass

    def get(self, domain: str) -> CacheEntry | None:
        return self._entries.get(domain.lower())

    def fresh(self, domain: str, ttl: float = config.CACHE_TTL) -> CacheEntry | None:
        entry = self.get(domain)
        return entry if entry and entry.is_fresh(ttl) else None

    def put(
        self,
        domain: str,
        ip: str,
        latency_ms: float,
        candidates: list[str] | None = None,
    ) -> CacheEntry:
        entry = CacheEntry(
            domain=domain.lower(),
            ip=ip,
            latency_ms=latency_ms,
            candidates=list(candidates or [ip]),
            updated=time.time(),
        )
        self._entries[entry.domain] = entry
        self._dirty = True
        return entry

    def snapshot(self) -> dict[str, CacheEntry]:
        return dict(self._entries)

    def evict_ip(self, domain: str, ip: str) -> None:
        entry = self._entries.get(domain.lower())
        if entry is None or not ip:
            return
        changed = False
        if ip in entry.candidates:
            entry.candidates.remove(ip)
            changed = True
        if entry.ip == ip:
            nxt = next((c for c in entry.candidates if c != ip), "")
            if nxt:
                entry.ip = nxt
                changed = True
        if changed:
            self._dirty = True
            self.save()

    def mark_blocked(self, domain: str) -> None:
        self._blocked[domain.lower()] = time.time()
        self._dirty = True
        self.save()

    def clear_blocked(self, domain: str) -> None:
        if self._blocked.pop(domain.lower(), None) is not None:
            self._dirty = True
            self.save()

    def blocked(self, domain: str, ttl: float) -> bool:
        stamp = self._blocked.get(domain.lower())
        return stamp is not None and (time.time() - stamp) < ttl


USAGE_VERSION = 1
USAGE_SAVE_INTERVAL = 5.0


class Usage:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else config.USAGE_FILE
        self.requests = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.since = 0.0
        self.updated = 0.0
        self._dirty = False
        self._last_save = 0.0
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if not isinstance(data, dict):
            return
        try:
            self.requests = max(0, int(data.get("requests") or 0))
            self.bytes_up = max(0, int(data.get("bytes_up") or 0))
            self.bytes_down = max(0, int(data.get("bytes_down") or 0))
            self.since = float(data.get("since") or 0.0)
            self.updated = float(data.get("updated") or 0.0)
        except (TypeError, ValueError):
            self.requests = self.bytes_up = self.bytes_down = 0
            self.since = self.updated = 0.0

    def save(self, *, force: bool = False) -> None:
        if not self._dirty:
            return
        now = time.time()
        if not force and now - self._last_save < USAGE_SAVE_INTERVAL:
            return
        payload = {
            "version": USAGE_VERSION,
            "requests": self.requests,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "since": self.since,
            "updated": now,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
            self.updated = now
            self._last_save = now
            self._dirty = False
        except OSError:
            pass

    def add(self, requests: int = 0, bytes_up: int = 0, bytes_down: int = 0) -> None:
        requests = max(0, int(requests))
        bytes_up = max(0, int(bytes_up))
        bytes_down = max(0, int(bytes_down))
        if not (requests or bytes_up or bytes_down):
            return
        if self.since <= 0:
            self.since = time.time()
        self.requests += requests
        self.bytes_up += bytes_up
        self.bytes_down += bytes_down
        self._dirty = True
        self.save()

    @property
    def total_bytes(self) -> int:
        return self.bytes_up + self.bytes_down
