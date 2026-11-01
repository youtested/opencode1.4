"""Permission engine: ask / allow / deny with pattern rules.

Mirrors opencode: rule = {permission, pattern, action}; LAST matching rule wins;
default action is "ask". Patterns: * -> .*, ? -> ., anchored, "/" normalization.
Headless default: auto-approve unless the rule denies (opencode --auto) OR a mode
is explicitly set to always-ask.
"""

from __future__ import annotations

from .util.log import swallow
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

# how many identical tool calls with identical input before it's a "doom loop"
DOOM_LOOP_THRESHOLD = 3
# cap on remembered "always allow" patterns (LRU-evicted, newest wins)
MAX_APPROVED_PATTERNS = 256
# compiled wildcard-regex cache: match() rebuilt the regex per rule per input
_MATCH_CACHE: dict[str, Any] = {}
_MATCH_CACHE_MAX = 512
_MATCH_CACHE_LOCK = threading.Lock()
# inputs longer than this are prefix-checked (a rule either matches or fails
# within the head; giant tool outputs never need full-regex scans)
MAX_MATCH_INPUT = 32 * 1024


def _match_one(pattern: str, value: str) -> bool:
    """One anchored wildcard match (pattern and value already normalized)."""
    # trailing ' *' matches "tool" or "tool <anything>"
    if pattern.endswith(" *"):
        base = pattern[:-2]
        base = re.escape(base).replace(r"\*", ".*").replace(r"\?", ".")
        regex = "^" + base + "( .*)?$"
    else:
        escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        regex = "^" + escaped + "$"
    try:
        rx = _MATCH_CACHE.get(regex)
        if rx is None:
            rx = re.compile(regex)
            with _MATCH_CACHE_LOCK:
                if len(_MATCH_CACHE) >= _MATCH_CACHE_MAX:
                    _MATCH_CACHE.clear()
                _MATCH_CACHE[regex] = rx
        return rx.match(value) is not None
    except re.error:
        return False


@dataclass
class Rule:
    permission: str
    pattern: str
    action: str  # allow | ask | deny


@dataclass
class PermissionEngine:
    rules: list[Rule] = field(default_factory=list)
    mode: str = "auto"  # auto | ask | deny
    # callback(user-facing description, always_patterns) -> "once"|"always"|"reject"
    ask_callback: Callable[[str, list[str]], str] | None = None
    _approved_patterns: list[str] = field(default_factory=list)
    _last_calls: list[tuple[str, str]] = field(default_factory=list)
    # Parent and parallel sub-agents share one engine: guard the mutable
    # ledgers so concurrent evaluate/ask/reset can't interleave into false
    # doom-loop detections or lost approvals. Never held across the modal
    # callback (siblings must keep streaming while one dialog is open).
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        *,
        mode: str = "auto",
        ask_callback: Callable[[str, list[str]], str] | None = None,
    ) -> "PermissionEngine":
        rules: list[Rule] = []
        for perm, value in config.items():
            if perm == "_comment":
                continue
            if isinstance(value, str):
                rules.append(Rule(permission=perm, pattern="*", action=value))
            elif isinstance(value, dict):
                for pattern, action in value.items():
                    if isinstance(action, str):
                        rules.append(Rule(permission=perm, pattern=pattern, action=action))
        engine = cls(rules=rules, mode=mode, ask_callback=ask_callback)
        engine.apply_defaults()
        return engine

    def apply_defaults(self) -> None:
        """opencode defaults: * allow, doom_loop ask, question deny."""
        defaults: dict[str, Any] = {
            "*": "allow",
            "doom_loop": "ask",
            "question": "deny",
            "plan_enter": "deny",
            "plan_exit": "deny",
            "read": {"*": "allow", "*.env": "ask", "*.env.*": "ask", "*.env.example": "allow"},
        }
        for perm, value in defaults.items():
            if self._has_permission(perm):
                continue
            if isinstance(value, str):
                self.rules.append(Rule(permission=perm, pattern="*", action=value))
            else:
                for pattern, action in value.items():
                    self.rules.append(Rule(permission=perm, pattern=pattern, action=action))

    def _has_permission(self, perm: str) -> bool:
        return any(r.permission == perm for r in self.rules)

    # -- pattern matching -------------------------------------------------
    @staticmethod
    def match(pattern: str, value: str, *, tail: bool = False) -> bool:
        """Wildcard match: * -> .*, ? -> ., anchored. '/' normalized.

        ``tail=True`` also tests the END of an over-long input. A deny rule
        whose match sits at the end of a 200 KB command (bash accepts this long,
        this window is 32 KB) used to be never evaluated at all. Allow rules
        stay head-only, so a remembered approval can never be widened from the
        tail of the command it is compared against.
        """
        pattern = pattern.replace("\\", "/")
        value = value.replace("\\", "/")
        if len(value) > MAX_MATCH_INPUT:
            if _match_one(pattern, value[:MAX_MATCH_INPUT]):
                return True
            return tail and _match_one(pattern, value[-MAX_MATCH_INPUT:])
        return _match_one(pattern, value)

    def evaluate(self, permission: str, input_value: str = "") -> str:
        """Return the action for a permission+input: allow | ask | deny."""
        if self.mode == "fully_auto":
            # fully_auto: the model does everything with zero popups. Only an
            # explicit deny rule can still block (deny always wins); every ask
            # (incl. *.env, external_directory, doom_loop) becomes allow. The
            # doom-loop ledger is deliberately left untouched, as before.
            return _apply_mode(self.mode, self._find_action(permission, input_value))
        # doom loop detection (bash tools repeat with identical input)
        if permission in ("bash", "write", "edit"):
            with self._lock:
                self._last_calls.append((permission, input_value))
                if len(self._last_calls) > DOOM_LOOP_THRESHOLD:
                    self._last_calls.pop(0)
                recent = list(self._last_calls[-DOOM_LOOP_THRESHOLD:])
            if len(recent) == DOOM_LOOP_THRESHOLD and len({c for c in recent}) == 1:
                r = self._find_action("doom_loop", input_value)
                if r != "allow":
                    return r

        return _apply_mode(self.mode, self._find_action(permission, input_value))

    def _find_action(self, permission: str, input_value: str) -> str:
        return self._resolve(permission, input_value)[0]

    def _resolve(self, permission: str, input_value: str) -> tuple[str, str | None]:
        """(action, winning pattern). One match order shared by every caller."""
        # check explicit rules (last match wins), then "*" rule, then "ask"
        explicit = [r for r in self.rules if r.permission == permission]
        for r in reversed(explicit):
            # deny/ask rules also look at the tail of an over-long input; allow
            # rules stay head-only so an approval can never be widened.
            if self.match(r.pattern, input_value, tail=r.action in ("deny", "ask")):
                return r.action, r.pattern
        wildcard = [r for r in self.rules if r.permission == "*"]
        for r in reversed(wildcard):
            if self.match(r.pattern, input_value, tail=r.action in ("deny", "ask")):
                return r.action, r.pattern
        return "ask", None

    def explain(self, permission: str, input_value: str = "") -> tuple[str, str, str | None]:
        """(verdict, configured action, winning pattern) with NO side effects.

        ``evaluate`` appends to the doom-loop ledger, so the /permissions
        viewer must never call it: merely opening the screen would push three
        identical entries and make the engine think it is stuck in a loop.
        """
        action, source = self._resolve(permission, input_value)
        return _apply_mode(self.mode, action), action, source

    def approved_patterns(self) -> list[str]:
        """Session "always allow" exemptions, oldest first.

        Public read access so the UI never reaches into the private ledger.
        Parent and sub-agents share this engine, so this is the one piece of
        permission state a user can otherwise neither see nor revoke.
        """
        with self._lock:
            return list(self._approved_patterns)

    def clear_approved(self, pattern: str | None = None) -> int:
        """Forget one exemption (or all when pattern is None). Returns count."""
        with self._lock:
            if pattern is None:
                n = len(self._approved_patterns)
                self._approved_patterns.clear()
                return n
            if pattern in self._approved_patterns:
                self._approved_patterns.remove(pattern)
                return 1
            return 0

    def doom_window(self) -> list[tuple[str, str]]:
        """Recent (permission, input) pairs used for doom-loop detection."""
        with self._lock:
            return list(self._last_calls)

    def adopt_from(self, other: "PermissionEngine") -> None:
        """Carry `other`'s ledgers across a rules rebuild.

        Rebuilding hands the loop a brand-new engine whose ledgers start empty;
        without this every rule edit would silently revoke the "always allow"
        exemptions the user already granted.
        """
        with self._lock:
            self._approved_patterns = list(other.approved_patterns())
            self._last_calls = list(other.doom_window())

    def ask(self, description: str, always_patterns: list[str] | None = None) -> bool:
        """Interactively ask the user; returns True if allowed."""
        always_patterns = always_patterns or []
        # if an always-allow pattern already approved, skip. Approved entries are
        # exact "permission input" strings; check literal equality FIRST so a
        # user-supplied command containing wildcard characters ("rm /*") can't
        # accidentally approve a broader pattern via the glob matcher below.
        with self._lock:
            approved_snapshot = list(self._approved_patterns)
        for approved in approved_snapshot:
            if any(p == approved for p in always_patterns):
                return True
            # The remembered approval is the PATTERN, the new request is the
            # VALUE — never the other way round. Matching `match(p, approved)`
            # treated the *request* as a glob, so one approved literal
            # ("bash rm src/a.py") authorised a later wildcard request
            # ("bash rm *"): one "yes" unlocked everything that glob reached.
            if any(self.match(approved, p) for p in always_patterns):
                return True
        if self.ask_callback is None:
            return True
        reply = self.ask_callback(description, always_patterns)
        if reply == "always":
            with self._lock:
                for p in always_patterns:
                    # don't store megabyte-sized tool inputs as approval patterns
                    if len(p) > 512:
                        continue
                    if p in self._approved_patterns:
                        # refresh LRU position by re-appending (dedup first)
                        self._approved_patterns.remove(p)
                    self._approved_patterns.append(p)
                # bounded memory: evict the oldest "always allow" approvals so a
                # long session's approval list never grows without limit.
                while len(self._approved_patterns) > MAX_APPROVED_PATTERNS:
                    self._approved_patterns.pop(0)
            return True
        return reply == "once"

    def reset_doom_tracking(self) -> None:
        with self._lock:
            self._last_calls = []


def _apply_mode(mode: str, action: str) -> str:
    """Resolve a configured action through the current mode.

    One function, deliberately: ``evaluate`` (enforcement) and ``explain``
    (the /permissions viewer) both route through here, so the screen can never
    disagree with what the engine actually does.
    """
    if action != "ask":
        return action
    if mode == "deny":
        return "deny"
    if mode in ("auto", "fully_auto"):
        return "allow"  # headless default: auto-approve (unless denied)
    return "ask"


BUILTIN_AGENTS: dict[str, str] = {
    "build": "Full tools — edits files, runs commands, does the work.",
    "plan": "Read-only — makes a plan, changes nothing.",
    "explore": "Read-only — answers questions about the code.",
}

READONLY_TOOLS = ("edit", "write", "apply_patch", "bash")


def agent_spec(cfg: Any, agent: str) -> dict[str, Any]:
    """The stored spec for a custom agent ({} for builtins/unknown)."""
    try:
        agents = getattr(cfg, "agents", None) or {}
        spec = agents.get(agent)
        return dict(spec) if isinstance(spec, dict) else {}
    except Exception:
        return {}




def agent_description(cfg: Any, agent: str) -> str:
    """One-line description for the picker (builtins fixed, customs stored)."""
    if agent in BUILTIN_AGENTS:
        return BUILTIN_AGENTS[agent]
    return str(agent_spec(cfg, agent).get("description") or "Custom agent.")


def agent_readonly(cfg: Any, agent: str) -> bool:
    """True when the agent may not mutate (plan/explore, or a custom with readonly)."""
    if agent in ("plan", "explore"):
        return True
    if agent == "build":
        return False
    spec = agent_spec(cfg, agent)
    if spec.get("readonly") is True:
        return True
    # a custom that denies every mutating tool is read-only in effect
    try:
        tools = spec.get("tools")
        if isinstance(tools, dict) and tools:
            denied = {
                t for t, v in tools.items()
                if (v == "deny" if isinstance(v, str)
                    else isinstance(v, dict) and v.get("*") == "deny"
                    and len(v) == 1)
            }
            if all(t in denied for t in READONLY_TOOLS):
                return True
    except Exception as _oc_exc:
        swallow(_oc_exc, "permission.py:251")
        pass
    return False


def list_agents(cfg: Any) -> list[tuple[str, str, bool]]:
    """Every agent: (name, description, is_custom). Builtins first, then
    customs alphabetically — the picker order.

    Never raises (TUI pickers call this on every open); a non-dict agents
    value is treated as no customs — from_dict already rejects it, and the
    headless /agent command reports the config error explicitly.
    """
    out = [(name, BUILTIN_AGENTS[name], False) for name in BUILTIN_AGENTS]
    agents = getattr(cfg, "agents", None) or {}
    if not isinstance(agents, dict):
        return out
    try:
        for name in sorted(agents):
            if name in BUILTIN_AGENTS:
                continue
            out.append((str(name), agent_description(cfg, str(name)), True))
    except Exception as _oc_exc:
        swallow(_oc_exc, "permission.py:273")
        pass
    return out


def agents_config_error(cfg: Any) -> str | None:
    """Human-readable config error when agents is malformed, else None."""
    agents = getattr(cfg, "agents", None)
    if agents is None:
        return None
    if not isinstance(agents, dict):
        return f"agents must be a dict of agent specs, got {type(agents).__name__}"
    return None


def agent_effective_tools(
    cfg: Any, agent: str, registry: Any = None,
) -> list[str]:
    """All tool names for the permission editor (new tools appear
    automatically). ALWAYS the full list — out-of-scope tools simply
    show as deny (see agent_tool_action); nothing is ever hidden, for
    present and future agents alike. Sorted for stable display.
    """
    try:
        names = list(registry.names()) if registry is not None else []
    except Exception:
        names = []
    if not names:
        try:
            from .tools import TOOL_NAMES as _NAMES

            names = list(_NAMES)
        except Exception:
            names = []
    return sorted(names)


def agent_md_dir(agent: str) -> Any:
    """Real directory for one agent's .md files:
    `<config>/agents/<agent>/` (e.g. `~/.config/opencode_py/agents/build/`).
    Created on write; never raises."""
    from pathlib import Path as _P

    from .globals import Path as _G

    try:
        base = _G.config
    except Exception:
        base = _P.home() / ".config" / "opencode_py"
    safe = "".join(c if (c.isalnum() or c in "-_") else "-" for c in str(agent or "build"))
    return base / "agents" / (safe or "build")


def agent_md_path(agent: str, name: str) -> Any:
    """Real file path for one stored .md file. Never raises."""
    from pathlib import Path as _P

    safe = _P(str(name or "notes.md")).name or "notes.md"
    if not safe.lower().endswith(".md"):
        safe += ".md"
    return agent_md_dir(agent) / safe




def short_display_path(path: str, limit: int = 60) -> str:
    """Home-shortened path, middle-truncated (`~/.../agents/build/x.md`)
    when longer than limit. Display only — the real path is untouched."""
    try:
        import os as _os

        s = str(path)
        h = _os.path.expanduser("~")
        if s.startswith(h):
            s = "~" + s[len(h):]
        if len(s) <= limit:
            return s
        head, sep, tail = s.partition("/agents/")
        if sep and tail:
            keep = limit - len(head) - len("/.../agents/") - 12
            if keep > 8:
                return head + "/.../agents/" + tail[-keep:]
        if len(s) > limit:
            return s[:12] + "..." + s[-(limit - 15):]
        return s
    except Exception:
        return str(path)


_MD_MIGRATED: set[str] = set()

# Combined agent-md cache (fix 3 hot spot): agent_combined_md re-globbed +
# re-read every agent .md file on EVERY system-prompt build (~2.5ms steady,
# 2.1s spikes). Keyed by per-file (mtime_ns, size) stamps so edits
# invalidate exactly; legacy config entries join the key. Bounded + never
# raises, mirroring the skill _CACHE idiom.
_MD_COMBINED_CACHE: dict[tuple, str] = {}
_MD_COMBINED_CACHE_MAX = 32


def md_entries_for_agent(spec: dict[str, Any] | None) -> list[tuple[str, str]]:
    """(filename, content) pairs stored for one agent. Never raises."""
    try:
        raw = (spec or {}).get("md")
        if isinstance(raw, dict):
            out = [(str(k), str(v)) for k, v in raw.items() if str(k).strip()]
            return sorted(out, key=lambda kv: kv[0].lower())
        if isinstance(raw, list):
            out = []
            for item in raw:
                if isinstance(item, dict) and item.get("name"):
                    out.append((str(item["name"]), str(item.get("content", ""))))
                elif isinstance(item, str) and item.strip():
                    out.append((item.strip(), ""))
            return sorted(out, key=lambda kv: kv[0].lower())
    except Exception as _oc_exc:
        swallow(_oc_exc, "permission.py:388")
        pass
    return []


def md_entries_for_agent_cfg(cfg: Any, agent: str) -> list[tuple[str, str]]:
    """(filename, content) pairs stored for one agent (builtins included).

    Reads REAL files from `<config>/agents/<agent>/`, with a one-time
    migration of legacy config-embedded entries (`agents.<name>.md`).
    Never raises.
    """
    try:
        legacy = md_entries_for_agent(agent_spec(cfg, agent))
    except Exception:
        legacy = []
    out: dict[str, str] = {}
    # 1. legacy config entries (migrated to files on first read).
    # Keys normalized through agent_md_path so "guide" and "guide.md"
    # collapse to one row (bug 3: unnormalized keys duplicated rows).
    for fname, content in legacy:
        try:
            key = str(agent_md_path(agent, str(fname)).name)
        except Exception:
            key = str(fname)
        out[key] = str(content)
    # 2. real files win over same-named legacy entries
    try:
        d = agent_md_dir(agent)
        if d.is_dir():
            for p in sorted(d.glob("*.md")):
                try:
                    if p.is_file():
                        out[p.name] = p.read_text(encoding="utf-8", errors="replace")[:100_000]
                except OSError as _oc_exc:
                    swallow(_oc_exc, "opencode_py/permission.py:426")
                    continue
    except Exception as _oc_exc:
        swallow(_oc_exc, "permission.py:424")
        pass
    # bug 4: the "one-time" migration ran disk IO on EVERY list call
    # (agent_md_groups calls this per agent per refresh). Guard per-agent
    # per-process so files are flushed once; disk remains authoritative.
    if legacy and agent not in _MD_MIGRATED:
        _MD_MIGRATED.add(agent)
        try:
            for fname, content in legacy:
                fp = agent_md_path(agent, fname)
                if not fp.exists():
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_text(str(content), encoding="utf-8")
        except Exception as _oc_exc:
            swallow(_oc_exc, "permission.py:437")
            pass
    return sorted(out.items(), key=lambda kv: kv[0].lower())


SHARED_AGENT = "shared"
SHARED_FILE = "AGENT.md"


def shared_md_dir() -> Any:
    """Real directory for the shared file: `<config>/agents/` (the parent
    of every per-agent dir). Created on write; never raises."""
    return agent_md_dir("__shared__").parent


def shared_md_path() -> Any:
    """Real file path of the shared AGENT.md. Never raises."""
    return shared_md_dir() / SHARED_FILE


def shared_md_text(cfg: Any = None) -> str:
    """The shared AGENT.md content (disk file wins, legacy config `md`
    under a `shared` agent spec migrates once). Never raises."""
    try:
        fp = shared_md_path()
        if fp.is_file():
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")[:100_000]
            except OSError:
                text = ""
            if text.strip():
                return text
    except Exception as _oc_exc:
        swallow(_oc_exc, "permission.py:469")
        pass
    if cfg is not None:
        try:
            for n, c in md_entries_for_agent_cfg(cfg, SHARED_AGENT):
                if str(n).lower() == SHARED_FILE.lower() and str(c).strip():
                    return str(c)
            for n, c in md_entries_for_agent_cfg(cfg, SHARED_AGENT):
                if str(c).strip():
                    return str(c)
        except Exception as _oc_exc:
            swallow(_oc_exc, "permission.py:479")
            pass
    return ""


def agent_md_groups(cfg: Any) -> list[tuple[str, list[tuple[str, str]]]]:
    """Shared group first, then all agents in Agents-popup order
    (builtins first, then customs alphabetically)."""
    groups: list[tuple[str, list[tuple[str, str]]]] = []
    try:
        text = shared_md_text(cfg)
    except Exception:
        text = ""
    groups.append((SHARED_AGENT, [(SHARED_FILE, text)] if text.strip() else []))
    for name, _desc, _custom in list_agents(cfg):
        if name == SHARED_AGENT:
            continue
        groups.append((name, md_entries_for_agent_cfg(cfg, name)))
    return groups


def agent_combined_md(cfg: Any, agent: str) -> str:
    """Shared AGENT.md FIRST, then the agent's own files — joined for prompt
    injection. So build gets shared+workflow, plan gets shared+rules, and
    every future agent gets shared+its own automatically."""
    try:
        stamp = agent_combined_md_stamp(cfg, agent)
        hit = _MD_COMBINED_CACHE.get(stamp)
        if hit is not None:
            return hit
    except Exception:
        stamp = None
    parts: list[str] = []
    try:
        shared = shared_md_text(cfg)
    except Exception:
        shared = ""
    if shared.strip():
        parts.append(shared)
    parts.extend(c for _n, c in md_entries_for_agent_cfg(cfg, agent) if c.strip())
    text = "\n\n".join(parts)
    if stamp is not None:
        try:
            if len(_MD_COMBINED_CACHE) >= _MD_COMBINED_CACHE_MAX:
                _MD_COMBINED_CACHE.pop(next(iter(_MD_COMBINED_CACHE)), None)
            _MD_COMBINED_CACHE[stamp] = text
        except Exception as _oc_exc:
            swallow(_oc_exc, "permission.py:525")
            pass
    return text


def agent_combined_md_stamp(cfg: Any, agent: str) -> tuple:
    """Cache key for agent_combined_md: per-file stamps + legacy entries.

    Fast path only: dir file stamps + the raw agent specs fingerprinted
    directly (no TUI import, no md_entries walk — that import chain spiked
    1600ms once and costs ~1.3ms steady). The spec fingerprint covers the
    exact legacy entries md_entries_for_agent_cfg would migrate, so any
    content change invalidates exactly. Never raises.
    """
    try:
        stamps: list[tuple] = []
        for place in (agent_md_dir(agent), shared_md_dir()):
            try:
                d = place
                if d.is_dir():
                    for p in sorted(d.glob("*.md")):
                        try:
                            if p.is_file():
                                st = p.stat()
                                stamps.append((str(p), int(st.st_mtime_ns), int(st.st_size)))
                        except OSError as _oc_exc:
                            swallow(_oc_exc, "opencode_py/permission.py:559")
                            continue
            except Exception as _oc_exc:
                swallow(_oc_exc, "permission.py:552")
                continue
        try:
            import json as _j

            legacy: list[tuple] = []
            for spec_name in (agent, SHARED_AGENT):
                try:
                    spec = agent_spec(cfg, spec_name) or {}
                    legacy.append((str(spec_name), _j.dumps(spec, sort_keys=True, default=str)))
                except Exception as _oc_exc:
                    swallow(_oc_exc, "permission.py:562")
                    continue
            stamps.append(("legacy", tuple(legacy)))
        except Exception as _oc_exc:
            swallow(_oc_exc, "permission.py:565")
            pass
        return (str(agent), tuple(stamps))
    except Exception:
        return (str(agent), (), str(id(cfg)))

def default_permissions(agent: str = "build") -> dict[str, Any]:
    """Mirror opencode's per-agent permission configs."""
    base: dict[str, Any] = {
        "*": "allow",
        "external_directory": {"*": "ask"},
        "read": {"*": "allow", "*.env": "ask", "*.env.*": "ask", "*.env.example": "allow"},
    }
    if agent == "build":
        base["question"] = "allow"
        base["plan_enter"] = "allow"
        base["browser"] = "allow"
        base["phone"] = "allow"
        base["webreach"] = "allow"
        base["attach"] = "allow"
    elif agent == "plan":
        base["question"] = "allow"
        base["plan_exit"] = "allow"
        base["task"] = {"general": "deny"}
        # plan agent is read-only: deny every mutating tool (defense-in-depth;
        # the loop also filters these from the model's tool schemas)
        base["edit"] = {"*": "deny"}
        base["write"] = {"*": "deny"}
        base["bash"] = {"*": "deny"}
        base["apply_patch"] = {"*": "deny"}
        # browser: read-only actions only (status/tabs/snapshot/screenshot).
        # NOTE: "*" goes FIRST so the specific allow rules (checked last,
        # last-match-wins) override it; mutating actions fall to deny.
        base["browser"] = {
            "*": "deny",
            "status *": "allow",
            "tabs *": "allow",
            "snapshot *": "allow",
            "screenshot *": "allow",
        }
        # binary: reading/inspecting is safe, writing bytes is a mutation
        base["binary"] = {"*": "allow", "patch *": "deny", "dump *": "deny"}
        base["phone"] = {
            "*": "deny",
            "status *": "allow",
            "screen *": "allow",
            "ui *": "allow",
            "focused *": "allow",
            "app_list *": "allow",
        }
    elif agent == "explore":
        # explore agent is a pure retrieval agent: same read-only walls as
        # plan, and it may only spawn further READ-ONLY sub-agents — never
        # build/general, which could mutate files.
        base["task"] = {"*": "deny", "plan": "allow", "explore": "allow"}
        base["edit"] = {"*": "deny"}
        base["write"] = {"*": "deny"}
        base["bash"] = {"*": "deny"}
        base["apply_patch"] = {"*": "deny"}
        base["browser"] = {
            "*": "deny",
            "status *": "allow",
            "tabs *": "allow",
            "snapshot *": "allow",
            "screenshot *": "allow",
        }
        base["phone"] = {
            "*": "deny",
            "status *": "allow",
            "screen *": "allow",
            "ui *": "allow",
            "focused *": "allow",
            "app_list *": "allow",
        }
    return base


def merge_permissions(
    user: dict[str, Any], agent: str = "build", cfg: Any = None,
) -> dict[str, Any]:
    """Merge user config permission over the agent defaults.

    Per-agent specs in cfg.agents layer their own per-tool rules on top —
    for custom agents AND builtins with stored overrides (the permission
    editor writes agents.<any>.tools): builtin defaults -> spec rules ->
    user global rules, so an agent's editor choices always win for it.
    """
    defaults = default_permissions(agent)
    if cfg is not None:
        try:
            spec = agent_spec(cfg, agent)
            tools = spec.get("tools")
            if isinstance(tools, dict):
                for perm, value in tools.items():
                    if isinstance(value, dict) and isinstance(defaults.get(perm), dict):
                        d = dict(defaults[perm])
                        d.update(value)
                        defaults[perm] = d
                    else:
                        defaults[perm] = value
            if spec.get("readonly") is True:
                for tool in READONLY_TOOLS:
                    defaults[tool] = {"*": "deny"}
                # binary is a reader too: keep inspection, drop the byte patcher
                defaults["binary"] = {"*": "allow", "patch *": "deny", "dump *": "deny"}
        except Exception as _oc_exc:
            swallow(_oc_exc, "permission.py:664")
            pass
    merged = dict(defaults)
    for perm, value in user.items():
        if isinstance(value, dict) and isinstance(merged.get(perm), dict):
            d = dict(merged[perm])
            d.update(value)
            merged[perm] = d
        else:
            merged[perm] = value
    return merged


# -- view model: one description of "what can the agent do right now" --------
# Shared by the /permissions popup (Rich markup) and the headless command
# (plain text). Both render these rows, so the two views cannot disagree.

VALID_ACTIONS = ("allow", "ask", "deny")

RULE_SOURCE_DEFAULT = "default"
RULE_SOURCE_AGENT = "agent"
RULE_SOURCE_USER = "you"
RULE_SOURCE_CATCHALL = "via *"

# The four mutators are why anyone opens a permissions screen. A default install
# never names them — the "*" catch-all covers them — which left bash/edit/write/
# apply_patch invisible exactly when they matter most. Always list them,
# resolved against the catch-all so the reason is on screen too.
ALWAYS_SHOWN_TOOLS = ("bash", "edit", "write", "apply_patch")

# Shown when it actually matters: on the mode row, and right after you press m.
# Not printed permanently — a permanent sentence is noise, but silence after a
# change leaves you guessing what you just switched to.
MODE_MEANING = {
    "auto": "runs freely and never asks — only an explicit deny rule stops it",
    "ask": "asks you first before anything not already allowed",
    "deny": "blocks anything you have not explicitly allowed",
    "fully_auto": "runs everything freely and shows no popups at all",
}


@dataclass
class PermRow:
    """One effective permission rule, ready to render."""

    tool: str
    pattern: str  # "*" for a whole-tool rule
    action: str  # what the rule literally says
    verdict: str  # what the current mode actually makes of it
    source: str  # RULE_SOURCE_* — which layer set it
    shadowed: bool = False  # unreachable: a later "*" for this tool always wins

    @property
    def invalid(self) -> bool:
        """A mistyped action: the engine would never match it, so it lies."""
        return self.action not in VALID_ACTIONS


def _rule_source(tool: str, pattern: str, user: dict[str, Any], spec: dict[str, Any]) -> str:
    """Which layer actually set this exact rule."""
    for layer, name in ((user, RULE_SOURCE_USER), (spec, RULE_SOURCE_AGENT)):
        if tool not in layer:
            continue
        value = layer[tool]
        # a scalar rule replaces the whole tool; a dict merges key by key
        if not isinstance(value, dict) or pattern in value:
            return name
    return RULE_SOURCE_DEFAULT


def _shadowed_patterns(value: Any) -> dict[str, bool]:
    """Flag patterns a later "*" for the same tool makes unreachable.

    ponytail: only the provable case. Whether an arbitrary glob is subsumed by
    a later pattern is not decidable cheaply, so this stays narrow instead of
    guessing and mislabelling a live rule.
    """
    if not isinstance(value, dict):
        return {}
    keys = [str(k) for k in value]
    out: dict[str, bool] = {}
    catch_all: int | None = None
    for i in range(len(keys) - 1, -1, -1):
        if keys[i] == "*":
            catch_all = i
        out[keys[i]] = catch_all is not None and catch_all > i
    return out


def effective_permission_rows(
    mode: str,
    agent: str = "build",
    user_permission: dict[str, Any] | None = None,
    cfg: Any = None,
) -> list[PermRow]:
    """Every rule in force, for the given mode and agent.

    The merge itself is delegated to :func:`merge_permissions` rather than
    reimplemented, so this view cannot drift from what the engine is handed.
    """
    user = {k: v for k, v in (user_permission or {}).items() if k != "_comment"}
    merged = merge_permissions(dict(user), agent or "build", cfg)

    spec: dict[str, Any] = {}
    if cfg is not None:
        try:
            tools = agent_spec(cfg, agent).get("tools")
            if isinstance(tools, dict):
                spec = tools
        except Exception as _oc_exc:
            swallow(_oc_exc, "permission.py:effective_permission_rows")

    rows: list[PermRow] = []
    for tool in sorted(merged):
        value = merged[tool]
        shadowed = _shadowed_patterns(value)
        patterns = value if isinstance(value, dict) else {"*": value}
        for pattern in patterns:
            key = str(pattern)
            action = str(patterns[pattern])
            rows.append(PermRow(
                tool=tool,
                pattern=key,
                action=action,
                verdict=_apply_mode(mode, action),
                source=_rule_source(tool, key, user, spec),
                shadowed=shadowed.get(key, False),
            ))

    # name the mutators even when nothing configures them, so the screen never
    # omits the most dangerous tools just because a catch-all happens to cover
    covered = merged.get("*")
    if isinstance(covered, dict):
        inherited = str(covered.get("*", "ask"))
    elif isinstance(covered, str):
        inherited = covered
    else:
        inherited = "ask"
    for tool in ALWAYS_SHOWN_TOOLS:
        if tool not in merged:
            rows.append(PermRow(
                tool=tool,
                pattern="*",
                action=inherited,
                verdict=_apply_mode(mode, inherited),
                source=RULE_SOURCE_CATCHALL,
            ))
    return rows


def would_ask_in(rows: list[PermRow]) -> list[str]:
    """Rules that would prompt you in ``ask`` mode, as "tool pattern" strings.

    The popup shows this per row instead of as a summary line: in ``auto`` each
    affected row reads "ask → allowed in auto", which says the same thing next
    to the rule it applies to.
    """
    return [f"{r.tool} {r.pattern}".strip() for r in rows if r.action == "ask"]


# -- grouping: what can the agent do, in the order a human worries about it --
# Riskiest first. Names come from the live registry in tools.TOOL_NAMES; a tool
# added later simply lands in "Everything else" rather than being invented into
# a group it may not belong to.

_COMMAND_GROUP = "Commands & file changes"
_READ_GROUP = "Reading your code"
_NET_GROUP = "Internet & device"
_SESSION_GROUP = "Session & planning"
_META_GROUP = "Agent behaviour"
_REST_GROUP = "Everything else"
_CATCHALL_GROUP = "Fallback for unlisted tools"

_TOOL_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # the four mutators — exactly what a readonly agent loses
    (_COMMAND_GROUP, ("bash", "edit", "write", "apply_patch")),
    (_READ_GROUP, ("read", "glob", "grep", "find_symbols", "lsp", "ide",
                   "summarize_file", "history_search", "binary")),
    (_NET_GROUP, ("webfetch", "webfetch_many", "websearch", "webreach",
                  "browser", "phone", "screen_view", "device", "speak",
                  "attach")),
    (_SESSION_GROUP, ("task", "question", "skill", "todowrite", "background_task",
                      "verify", "quick_calc")),
    # not tools at all: pseudo-permissions the engine resolves on its own
    (_META_GROUP, ("external_directory", "doom_loop", "plan_enter", "plan_exit")),
    (_REST_GROUP, None),  # None = anything the groups above did not claim
    # the catch-all is not a tool; it governs every tool with no rule of its
    # own, so it reads as a footnote rather than the first line of the list
    (_CATCHALL_GROUP, ("*",)),
)


def group_permission_rows(
    rows: list[PermRow],
) -> list[tuple[str, list[PermRow]]]:
    """Bucket rows into capability groups, riskiest first, empty groups dropped.

    Only TOOLS are reordered. Patterns inside one tool keep their true dict
    order, because evaluation is last-match-wins over that exact order:
    reordering them would make the screen contradict the engine. Within a
    group, your own rules come first — that is what you opened the screen for.
    """
    by_tool: dict[str, list[PermRow]] = {}
    for row in rows:
        by_tool.setdefault(row.tool, []).append(row)

    claimed: set[str] = set()
    out: list[tuple[str, list[PermRow]]] = []
    for title, names in _TOOL_GROUPS:
        # the catch-all is not a tool: exclude it from the "unclaimed" bucket so
        # it cannot be listed twice, and let its own group take it below
        tools = ([t for t in by_tool if t not in claimed and t != "*"]
                 if names is None else [t for t in names if t in by_tool])
        if not tools:
            continue
        claimed.update(tools)
        tools.sort(key=lambda t: (by_tool[t][0].source != RULE_SOURCE_USER, t))
        out.append((title, [r for t in tools for r in by_tool[t]]))
    return out
