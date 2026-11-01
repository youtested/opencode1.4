"""Repo map: a compact, ranked outline of the project for the system prompt.

Reuses the symbol index + resolved graph that ``find_symbols`` already builds
(no new scraping): files are ranked by how much the rest of the codebase
depends on them, and each file lists its most-referenced symbols. The result is
bounded by a token budget and cached per graph fingerprint, so repeat turns are
free until the code actually changes.

Two entry points, and the split is the whole point:

- ``render_repo_map(..., blocking=True)`` builds/refreshes the index. Used by
  the startup warm and by tests.
- ``render_repo_map(..., blocking=False)`` — what the SEND PATH calls — only
  reads an index that is already warm (``IndexEngine.peek``), never walks the
  tree. If the background warm hasn't finished yet it returns the last known
  text — from memory, or from the small file the previous process left in the
  cache dir — and asks for a warm, so the very first message is never held up
  by an index build.

The map is query-independent on purpose: the same text every turn keeps the
prompt prefix stable, which is what provider-side prefix caching needs.
"""

from __future__ import annotations

import threading
from pathlib import Path

from ..util.log import swallow
from ..util.truncate import CHARS_PER_TOKEN

# Render cache: (root, fingerprint, budget) -> text. Bounded, never raises.
_CACHE: dict[tuple, str] = {}
_CACHE_MAX = 8
# Last good text per root, so a cold index degrades to the previous map rather
# than to nothing.
_LAST: dict[str, str] = {}
# What the last text on disk was, so an unchanged map is not rewritten on
# every render (a save per turn would be a needless write on a phone).
_LOADED: dict[str, str] = {}
# Roots with a warm thread already in flight (no duplicate builds).
_WARMING: set[str] = set()
_WARM_LOCK = threading.Lock()

_TOP_FILES = 40
_TOP_SYMBOLS_PER_FILE = 6
# Kinds that are noise in an outline: imports and locals rarely guide a reader.
_SKIP_KINDS = {"import", "variable"}


def _symbols_by_file(graph) -> dict[str, list[tuple[int, int, str]]]:
    """file -> [(in_degree, line, name)], highest-degree first within a file."""
    by_file: dict[str, list[tuple[int, int, str]]] = {}
    for nid, meta in graph.nodes.items():
        if meta.get("kind") in _SKIP_KINDS:
            continue
        file = meta.get("file") or ""
        if not file:
            continue
        indeg = len(graph.inn.get(nid, ()))
        by_file.setdefault(file, []).append((indeg, meta.get("line", 0), meta.get("name", "")))
    return by_file


def _render(graph, budget_tokens: int) -> str:
    by_file = _symbols_by_file(graph)
    if not by_file:
        return ""
    rows = []
    for file, syms in by_file.items():
        syms.sort(key=lambda t: (-t[0], t[1], t[2]))
        importers = len(graph.mod_in.get("@" + file, ()))
        hot = sum(min(s[0], 25) for s in syms[:_TOP_SYMBOLS_PER_FILE])
        rows.append((importers * 3 + hot, file, syms))
    rows.sort(key=lambda r: (-r[0], r[1]))
    stats = graph.stats()
    # Account in CHARACTERS, not per-line tokens: flooring each line separately
    # loses the remainder every time, so 40 cheap lines undercounted the real
    # total by ~20%. Budget = tokens * CHARS_PER_TOKEN is exact.
    char_budget = budget_tokens * CHARS_PER_TOKEN
    header = (
        f"{stats['nodes']} symbols, {stats['call_edges']} call edges, "
        f"{stats['modules']} modules across {len(by_file)} files"
    )
    used = len(header)
    lines = [header]
    for _score, file, syms in rows[:_TOP_FILES]:
        names: list[str] = []
        seen: set[str] = set()
        for _d, _ln, name in syms:
            if name and name not in seen:
                seen.add(name)
                names.append(name)
            if len(names) >= _TOP_SYMBOLS_PER_FILE:
                break
        if not names:
            continue
        line = f"{file}: " + ", ".join(names)
        cost = len(line) + 1
        if used + cost > char_budget:
            break
        lines.append(line)
        used += cost
    return "\n".join(lines)


def _root_path(root) -> Path | None:
    try:
        # Path("") resolves to the CWD, so an empty root must be rejected
        # outright — otherwise a caller with no worktree gets a map of whatever
        # directory the process happens to be sitting in.
        if root is None or not str(root).strip():
            return None
        return Path(root).resolve()
    except Exception:
        return None


def _last_path(root_path: Path) -> Path | None:
    """Where the last rendered text for `root_path` is parked between runs."""
    try:
        import hashlib

        from ..globals import Path as GPath

        cache = GPath.cache
        if cache is None:
            return None
        digest = hashlib.sha1(str(root_path).encode("utf-8", "replace")).hexdigest()[:16]
        return Path(cache) / "repomap" / f"{digest}.txt"
    except Exception:
        return None


def _save_last(root_path: Path, text: str) -> None:
    """Persist the rendered text so the NEXT process has a map on turn 1
    instead of an empty block while its index warms in the background."""
    path = _last_path(root_path)
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
    except Exception as _oc_exc:
        swallow(_oc_exc, "opencode_py/index/repomap.py:_save_last")


def _load_last(root_path: Path) -> str:
    """Last map written by a previous process, or '' — one small file read."""
    path = _last_path(root_path)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _render_from_files(files, root_path: Path, budget_tokens: int) -> str:
    """Shared render + cache step for both the warm and the warm-less paths."""
    try:
        from .graph import graph_for

        graph = graph_for(files, str(root_path))
    except Exception:
        return ""
    key = (str(root_path), graph.fingerprint, int(budget_tokens))
    hit = _CACHE.get(key)
    if hit is not None:
        _LAST[str(root_path)] = hit
        return hit
    try:
        text = _render(graph, int(budget_tokens))
    except Exception:
        text = ""
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)), None)
    _CACHE[key] = text
    if text:
        _LAST[str(root_path)] = text
        if text != _LOADED.get(str(root_path)):
            _save_last(root_path, text)
            _LOADED[str(root_path)] = text
    return text


def render_repo_map(root, budget_tokens: int = 1200, *, blocking: bool = True) -> str:
    """Ranked outline of the project at ``root``, or '' when unavailable.

    ``blocking=True`` (warm/tests) builds the index if needed. ``blocking=False``
    is the send path: it reads only an already-warm index and returns the last
    known text otherwise (in-memory, else the text this repo rendered last run),
    so a first message never waits on a cold build.

    Never raises: a broken index degrades to an empty block, never a failed
    turn. Cached per graph fingerprint, so an unchanged repo costs one dict
    lookup after the first render.
    """
    if budget_tokens <= 0:
        return ""
    root_path = _root_path(root)
    if root_path is None:
        return ""
    try:
        from .engine import _ENGINE
    except Exception:
        return ""
    if blocking:
        try:
            files = _ENGINE.ensure(root_path)
        except Exception:
            return ""
        return _render_from_files(files, root_path, budget_tokens) if files else ""
    # Send path: no walk, no parse. Warm already? render. Otherwise keep the
    # previous map visible and let a background thread fill it in.
    files = _ENGINE.peek(root_path)
    if files:
        return _render_from_files(files, root_path, budget_tokens)
    request_warm(root_path)
    # A brand-new process has nothing in memory yet, but the map this repo
    # rendered last time is on disk: a single small read buys turn 1 a real
    # map instead of an empty block while the index warms. Replaced by the
    # fresh render as soon as the background warm lands.
    key = str(root_path)
    text = _LAST.get(key)
    if text is None:
        text = _load_last(root_path)
        if text:
            _LAST[key] = text
            _LOADED[key] = text
    return text


def warm(root) -> None:
    """Best-effort: build the index + graph now so the first real prompt finds
    them hot instead of paying a cold build on the send path."""
    root_path = _root_path(root)
    if root_path is None:
        return
    try:
        from .engine import _ENGINE

        files = _ENGINE.ensure(root_path)
        if files:
            _render_from_files(files, root_path, 1200)
    except Exception as _oc_exc:
        swallow(_oc_exc, "opencode_py/index/repomap.py:185")


def request_warm(root) -> None:
    """Start ONE background warm for `root` (no-op if one is already running)."""
    root_path = _root_path(root)
    if root_path is None:
        return
    key = str(root_path)
    with _WARM_LOCK:
        if key in _WARMING:
            return
        _WARMING.add(key)

    def _run() -> None:
        try:
            warm(root_path)
        finally:
            with _WARM_LOCK:
                _WARMING.discard(key)

    try:
        threading.Thread(target=_run, daemon=True).start()
    except Exception:
        with _WARM_LOCK:
            _WARMING.discard(key)
