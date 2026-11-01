"""Autotest: the harness runs the tests an edit just touched, and feeds back.

The loop already refuses an edit that breaks SYNTAX (``tools/verify.py``). This
closes the other half: an edit that parses but breaks BEHAVIOUR. The harness —
never the model — runs the affected tests after every mutating tool step, so
"done" cannot be claimed while they are red.

Three rules keep the cost sane without losing detection:

1. **File-level selection through the real import graph.** Never by symbol or
   test name: a renamed helper breaks callers that never mention it by name.
2. **Green-cache keyed by the import closure.** A test file whose whole
   transitive import set is untouched since it last passed cannot have changed
   its outcome, so it is skipped. Exact, not a guess.
3. **Parallel runs are always confirmed serially when red.** A flaky parallel
   failure can never be reported as a real one, so speed costs no accuracy.

Everything here is pure and never raises: a broken project degrades to "no
autotest", never to a failed turn.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path

from ..util.log import swallow

# Caps. The file cap is what stops a one-line edit to a load-bearing module
# (config.py is imported by 45 test files) from becoming a two-minute run.
DEFAULT_MAX_FILES = 12
DEFAULT_TIMEOUT = 120
DEFAULT_WORKERS = 2
MAX_CLOSURE = 400

# Message caps: autotest output lands in the provider request, so it must stay
# small enough that a failing test never costs more than the fix is worth.
MAX_MSG_CHARS = 4000
MAX_FAIL_LINES = 8

_TEST_DIR_HINTS = ("tests/", "test/", "spec/")
_TEST_NAME_RE = re.compile(r"(^|/)(test_.*|.*_test)\.py$")
_COUNT_RE = re.compile(r"(\d+) (passed|failed|error|errors|skipped|xfailed|xpassed|deselected)")
_FAILED_ID_RE = re.compile(r"^FAILED (\S+?)(?: - .*)?$", re.MULTILINE)
_DURATION_RE = re.compile(r"in ([0-9.]+)s")

# Scanning a test file costs ~10ms on a phone; the same files are scanned again
# on every edit in a turn, so the text is cached by (mtime, size) and the scan
# drops to a regex over memory. Bounded so a long session cannot grow it.
_SCAN_CACHE: dict[str, tuple[tuple[int, int], str]] = {}
_SCAN_CACHE_MAX = 512


def _scan_text(path: Path) -> str:
    key = str(path)
    try:
        st = path.stat()
        stamp = (int(st.st_mtime_ns), int(st.st_size))
    except OSError:
        return ""
    hit = _SCAN_CACHE.get(key)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if len(_SCAN_CACHE) >= _SCAN_CACHE_MAX:
        _SCAN_CACHE.clear()
    _SCAN_CACHE[key] = (stamp, text)
    return text


def is_test_path(rel: str) -> bool:
    """True when `rel` looks like a Python test file (posix relative path)."""
    p = str(rel or "").replace("\\", "/")
    if not p:
        return False
    return bool(_TEST_NAME_RE.search(p)) or (
        p.endswith(".py") and any(h in p for h in _TEST_DIR_HINTS)
    )


def _rel(root: Path, path: str) -> str | None:
    """Path relative to `root` (posix), or None when it lives outside it."""
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except Exception:
        return None


def normalize(root, changed) -> list[str]:
    """Absolute or relative paths -> sorted, de-duped posix paths under root."""
    out: list[str] = []
    for p in changed or ():
        try:
            rel = _rel(root, p)
        except Exception:
            rel = None
        if not rel:
            continue
        if rel.endswith(".py") and rel not in out:
            out.append(rel)
    return sorted(out)


def _index_files(root: Path):
    """The warm symbol index for `root`, or None. Never builds one."""
    try:
        from ..index.engine import _ENGINE

        return _ENGINE.peek(root)
    except Exception:
        return None


def closure_of(root: Path, test_rel: str, files=None) -> set[str]:
    """Every module `test_rel` transitively imports, or an empty set.

    Empty means "unknown" (cold index), and every caller treats unknown as
    "cannot skip" — the conservative direction.
    """
    try:
        from ..index.graph import graph_for

        files = files if files is not None else _index_files(root)
        if not files:
            return set()
        g = graph_for(files)
        seen: set[str] = set()
        stack = [f"@{test_rel}"]
        while stack and len(seen) < MAX_CLOSURE:
            node = stack.pop()
            for nxt in g.mod_out.get(node, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                stack.append(nxt)
    except Exception:
        return set()
    return {s[1:] for s in seen if isinstance(s, str) and s.startswith("@")}


def _test_files_on_disk(root: Path) -> list[str]:
    """Fallback discovery: the project's test files, cheapest form."""
    out: list[str] = []
    for base in ("tests", "test"):
        d = Path(root) / base
        if not d.is_dir():
            continue
        try:
            for p in sorted(d.rglob("test_*.py")):
                rel = p.relative_to(Path(root)).as_posix()
                if rel not in out:
                    out.append(rel)
        except Exception as _oc_exc:
            swallow(_oc_exc, "opencode_py/agent/autotest.py:_test_files_on_disk")
    return out


def _grep_importers(root: Path, changed: list[str], available: list[str]) -> list[str]:
    """Cold-index fallback: test files whose text IMPORTS a changed module.

    Matching is on the full dotted path (or a `from package import leaf`), never
    on the bare stem: "edit" as a substring also matches "edited", "editor" and
    every comment that says the word, which selected a dozen unrelated files.
    """
    patterns = []
    for rel in changed:
        mod = rel[:-3].replace("/", ".")
        if not mod:
            continue
        if "." in mod:
            pkg, leaf = mod.rsplit(".", 1)
            patterns.append(re.compile(
                rf"(?:^|[^\w.]){re.escape(mod)}\b"
                rf"|from\s+{re.escape(pkg)}\s+import\s+[^\n]*\b{re.escape(leaf)}\b"
            ))
        else:
            patterns.append(re.compile(rf"^\s*import\s+{re.escape(mod)}\s*$", re.MULTILINE))
    if not patterns:
        return []
    hits: list[str] = []
    for rel in available:
        text = _scan_text(Path(root) / rel)
        if text and any(p.search(text) for p in patterns):
            hits.append(rel)
    return hits


def select_tests(
    root,
    changed,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    green: dict | None = None,
) -> list[str]:
    """Test files that exercise `changed`, capped and closure-filtered.

    `green` maps test_rel -> closure snapshot that last passed; entries whose
    closure does not intersect `changed` are skipped (they cannot have moved).
    """
    try:
        root_p = Path(root).resolve()
        changed_rel = normalize(root_p, changed)
        if not changed_rel:
            return []
        files = _index_files(root_p)
        picked: list[str] = []

        for rel in changed_rel:
            if is_test_path(rel) and rel not in picked:
                picked.append(rel)

        source = [r for r in changed_rel if not is_test_path(r)]
        if source:
            # UNION, never "graph else grep". The graph resolves imports through
            # the index and is exact for `from pkg.mod import x`, but it misses
            # package-level `from opencode_py import session` — those tests were
            # silently skipped, which is under-selection and lost detection.
            # Both signals together can only over-select, which costs seconds;
            # under-selecting costs correctness.
            importers: list[str] = []
            if files:
                try:
                    from ..index.graph import graph_for

                    g = graph_for(files)
                    for rel in source:
                        for holder in g.mod_in.get(f"@{rel}", ()):
                            candidate = holder[1:] if holder.startswith("@") else holder
                            if is_test_path(candidate) and candidate not in importers:
                                importers.append(candidate)
                except Exception as _oc_exc:
                    swallow(_oc_exc, "opencode_py/agent/autotest.py:select/importers")
            for rel in _grep_importers(root_p, source, _test_files_on_disk(root_p)):
                if rel not in importers:
                    importers.append(rel)
            for rel in importers:
                if rel not in picked:
                    picked.append(rel)

        if green:
            touched = set(changed_rel)
            keep: list[str] = []
            for rel in picked:
                snapshot = green.get(rel)
                # An EMPTY snapshot means "we never learned the closure" (no
                # warm index). Treating that as "nothing it imports changed"
                # would skip every test forever after the first green run.
                if snapshot and not (set(snapshot) & touched):
                    continue
                keep.append(rel)
            picked = keep

        # Stable, deterministic order so a repeated run is byte-for-byte the
        # same command (and the provider prefix cache keeps hitting). Files whose
        # NAME matches the changed module come first: when the cap bites on a
        # load-bearing module, `test_config.py` is a far better guess than the
        # alphabetically-first importer.
        stems = [Path(r).stem for r in changed_rel]
        pref = tuple(f"test_{s}" for s in stems) + tuple(f"{s}_test" for s in stems)

        def _rank(rel: str) -> tuple[int, str]:
            base = Path(rel).name
            return (0 if base.startswith(pref) else 1, rel)

        return sorted(picked, key=_rank)[: max(1, int(max_files or DEFAULT_MAX_FILES))]
    except Exception:
        return []


def _parse(output: str) -> dict:
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for n, what in _COUNT_RE.findall(output or ""):
        # The regex only captures digits, so no try/except is needed here — and
        # a silent except is what the error-visibility guard exists to catch.
        k = int(n) if n.isdigit() else 0
        if what == "passed":
            counts["passed"] = max(counts["passed"], k)
        elif what == "failed":
            counts["failed"] = max(counts["failed"], k)
        elif what in ("error", "errors"):
            counts["errors"] = max(counts["errors"], k)
        elif what == "skipped":
            counts["skipped"] = max(counts["skipped"], k)
    ids = [m.group(1) for m in _FAILED_ID_RE.finditer(output or "")]
    dur = _DURATION_RE.search(output or "")
    return {
        **counts,
        "failed_ids": ids,
        "seconds": float(dur.group(1)) if dur else 0.0,
        "total": counts["passed"] + counts["failed"] + counts["errors"],
    }


def _command(files: list[str], *, command: str, maxfail: int) -> str:
    if command.strip():
        return command.strip()
    exe = sys.executable or "python3"
    parts = [exe, "-m", "pytest", *files,
             "-q", "--no-header", "--tb=short", "-p", "no:cacheprovider"]
    if maxfail and maxfail > 0:
        parts.append(f"--maxfail={int(maxfail)}")
    return " ".join(shlex.quote(p) for p in parts)


def _run_one(cmd: str, *, root: Path, timeout: int, interrupt) -> dict:
    from ..tools.bash import _bash

    res = _bash(cmd, timeout=timeout, workdir=str(root), is_interrupted=interrupt)
    out = str(res.get("output") or "")
    parsed = _parse(out)
    parsed["output"] = out
    parsed["exit_code"] = int(res.get("exit_code") or 0)
    parsed["error"] = bool(res.get("error"))
    return parsed


def _split(files: list[str], n: int) -> list[list[str]]:
    """Round-robin the files into `n` batches, order preserved."""
    n = max(1, min(int(n or 1), len(files) or 1))
    batches: list[list[str]] = [[] for _ in range(n)]
    for i, f in enumerate(files):
        batches[i % n].append(f)
    return [b for b in batches if b]


def _merge(results) -> dict:
    """Combine per-process results into one verdict with honest totals."""
    merged = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0,
              "failed_ids": [], "seconds": 0.0, "output": "", "exit_code": 0,
              "error": False, "total": 0}
    for one in results or ():
        for k in ("passed", "failed", "errors", "skipped", "total"):
            merged[k] += int(one.get(k) or 0)
        merged["failed_ids"].extend(one.get("failed_ids") or [])
        merged["seconds"] = max(merged["seconds"], float(one.get("seconds") or 0))
        merged["exit_code"] = int(one.get("exit_code") or 0) or merged["exit_code"]
        merged["error"] = merged["error"] or bool(one.get("error"))
        out = str(one.get("output") or "").strip()
        if out:
            merged["output"] = (merged["output"] + "\n" + out).strip()
    return merged


def run_tests(
    root,
    files,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    interrupt=None,
    command: str = "",
    workers: int = DEFAULT_WORKERS,
    maxfail: int = 0,
) -> dict:
    """Run the selected tests. Red results are always confirmed serially.

    Parallelism is only ever a speed-up of a GREEN result: if a split run
    reports failures, the failing files are re-run alone (one process) before a
    single failure reaches the model, so a port clash or shared fixture can
    never masquerade as a real regression.
    """
    root_p = Path(root).resolve()
    files = [str(f) for f in (files or ())]
    if not files and not command.strip():
        return {"ok": True, "skipped": True, "output": "", "passed": 0,
                "failed": 0, "errors": 0, "failed_ids": [], "seconds": 0.0,
                "total": 0}
    try:
        workers = max(1, min(int(workers or 1), max(1, (os.cpu_count() or 1) // 2)))
    except Exception:
        workers = 1
    if workers < 2 or len(files) < 2 or command.strip():
        res = _run_one(_command(files, command=command, maxfail=maxfail),
                       root=root_p, timeout=timeout, interrupt=interrupt)
    else:
        import threading

        # One file per process. Batches are kept separate so a red batch can be
        # re-run alone without losing the pass counts of the batches that were
        # never in doubt.
        batches = _split(files, min(workers, len(files)))
        results: list[dict | None] = [None] * len(batches)

        def _work(i: int, batch: list[str]) -> None:
            results[i] = _run_one(_command(batch, command="", maxfail=maxfail),
                                  root=root_p, timeout=timeout, interrupt=interrupt)

        threads = [threading.Thread(target=_work, args=(i, b), daemon=True)
                   for i, b in enumerate(batches)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=max(5, timeout + 30))

        done = [r for r in results if r is not None]
        res = _merge(done)
        if res.get("failed") or res.get("errors"):
            # Confirm only the batches that failed, serially: a shared port or a
            # contended fixture can lose a race under parallelism, and a flaky
            # false red would be worse than no autotest at all.
            for i, r in enumerate(results):
                if r is not None and (r.get("failed") or r.get("errors")):
                    results[i] = _run_one(
                        _command(batches[i], command="", maxfail=maxfail),
                        root=root_p, timeout=timeout, interrupt=interrupt)
            res = _merge([r for r in results if r is not None])
    res["ok"] = not (res.get("failed") or res.get("errors")) and res.get("exit_code", 0) == 0
    return res


def format_result(res: dict, files, *, edited_tests=(), exhausted: int = 0,
                  broken: bool = False) -> str:
    """One compact message for the model: green is one line, red is actionable."""
    files = list(files or ())
    shown = ", ".join(files[:6]) + (" …" if len(files) > 6 else "")
    head = f"({shown})" if shown else ""
    note = ""
    if edited_tests:
        note = ("\nYou edited a test file in this step (" + ", ".join(
            list(edited_tests)[:3]) + ") — make it pass by fixing the code, "
            "not by weakening the test.")
    passed = int(res.get("passed") or 0)
    failed = int(res.get("failed") or 0) + int(res.get("errors") or 0)
    secs = float(res.get("seconds") or 0.0)
    if broken:
        # A timeout, a collection error or an empty selection is an
        # INFRASTRUCTURE result, never a green one: it says nothing about the
        # code, so it must not be reported as "all passing" (the old path read
        # "0 failed" as success).
        body = ["[autotest] the tests could not be run (timeout, collection "
                "error, or nothing collected). This is not a result about your "
                "change; carry on."]
        tail = str(res.get("output") or "").strip().splitlines()[-3:]
        body.extend(tail)
        return "\n".join(body)[:MAX_MSG_CHARS]
    if not failed:
        line = f"[autotest] {passed} passed"
        if secs:
            line += f" in {secs:.1f}s"
        return (line + (f" {head}" if head else "") + ".").strip() + note
    if exhausted:
        line = f"[autotest] stopped after {exhausted} fix attempts — still failing"
    else:
        total = int(res.get("total") or (passed + failed))
        line = (f"[autotest] {failed} of {total} tests failed in the files you "
                f"just edited. Fix them; the run repeats automatically")
    if secs:
        line += f" ({secs:.1f}s)"
    body = [line + "."]
    ids = list(res.get("failed_ids") or [])[:MAX_FAIL_LINES]
    for fid in ids:
        body.append(f"FAILED {fid}")
    if not ids:
        tail = str(res.get("output") or "").strip().splitlines()[-MAX_FAIL_LINES:]
        body.extend(tail)
    text = "\n".join(body) + note
    return text[:MAX_MSG_CHARS]
