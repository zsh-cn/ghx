from __future__ import annotations

import os
from pathlib import Path

VERSION = "1.1.0"


def _state_home() -> Path:
    override = os.environ.get("GHX_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".ghx"


HOME_DIR = _state_home()
CACHE_FILE = HOME_DIR / "cache.json"
USAGE_FILE = HOME_DIR / "usage.json"

CACHE_TTL = 6 * 3600
PROBE_TIMEOUT = 4.0
PROBE_SAMPLES = 2
PROBE_CONCURRENCY = 64
DEFAULT_PORT = 7801
MAX_HEADER = 64 * 1024

DOMAIN_GROUPS: dict[str, list[str]] = {
    "网页": [
        "github.com",
        "gist.github.com",
        "api.github.com",
    ],
    "静态资源": [
        "github.githubassets.com",
        "collector.github.com",
        "avatars.githubusercontent.com",
        "camo.githubusercontent.com",
        "favicons.githubusercontent.com",
    ],
    "下载": [
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "media.githubusercontent.com",
        "user-images.githubusercontent.com",
        "private-user-images.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    ],
}

GITHUB_SUFFIXES = (
    ".github.com",
    ".githubusercontent.com",
    ".githubassets.com",
    ".github.io",
    ".github.dev",
    ".ghcr.io",
    ".githubapp.com",
    ".githubcopilot.com",
)

CORE_DOMAINS: tuple[str, ...] = (
    "github.com",
    "api.github.com",
    "github.githubassets.com",
    "avatars.githubusercontent.com",
    "camo.githubusercontent.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "user-images.githubusercontent.com",
    "release-assets.githubusercontent.com",
)

_CORE_SET = frozenset(CORE_DOMAINS)


def is_core_domain(host: str) -> bool:
    return (host or "").lower().strip(".") in _CORE_SET


_ROOT_HOSTS = frozenset(
    ("github.com", "githubusercontent.com", "githubassets.com", "github.io",
     "ghcr.io", "github.dev", "githubapp.com", "githubcopilot.com")
)


def builtin_domains() -> list[str]:
    seen: dict[str, None] = {}
    for domains in DOMAIN_GROUPS.values():
        for d in domains:
            seen.setdefault(d, None)
    return list(seen)


def core_domains() -> list[str]:
    return [d for d in builtin_domains() if d in _CORE_SET]


def is_github_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    if host in _ROOT_HOSTS:
        return True
    return host.endswith(GITHUB_SUFFIXES)
