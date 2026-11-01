"""Permissions popup: what can the agent do right now — and change it.

Shows the live permission MODE plus every rule in force: the agent defaults,
any per-agent overrides, and your own rules. Each row says which layer set it
and, crucially, what the current mode ACTUALLY makes of it. That last part is
not decoration: in the default ``auto`` mode every ``ask`` resolves to
``allow``, so a screen that printed only the written action would render
green everywhere and tell the user nothing. Rules the current mode would
silently auto-approve are called out inline, and one line lists what would
prompt you if you switched to ``ask``.

Rules are flat (one row per tool+pattern, no header rows) so cycling a pattern
edits that key alone; cycling a dict-valued tool's ``*`` key merges into it and
leaves its sibling patterns intact.

Persisting is the CALLER's job: the popup owns no config logic and only calls
back (on_rule_change / on_mode_change / on_clear_approved), exactly like
AgentPermissionEditor. Never raises.
"""

from __future__ import annotations

from ..util.log import swallow
from typing import Any, Callable
import re

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.events import Key
from textual.screen import ModalScreen
from textual.widgets import Input, OptionList, Static
from textual.widgets.option_list import Option

from .theme import active_theme
from ..permission import (
    MODE_MEANING, RULE_SOURCE_USER, effective_permission_rows,
    group_permission_rows,
)

# inherit -> ask -> deny -> allow -> inherit. Starting at "inherit" is how a
# restriction gets ADDED; returning to it REMOVES the user's key so the rule
# falls back to the agent default. Cycling only among the three actions would
# make an edit impossible to undo.
_NEXT = {"inherit": "ask", "ask": "deny", "deny": "allow", "allow": "inherit"}
_PREV = {"inherit": "allow", "allow": "deny", "deny": "ask", "ask": "inherit"}

_MODES = ("auto", "ask", "deny", "fully_auto")

_SEP = "\x1f"  # row-id separator; tool and pattern never contain it

# ids that are decoration: shown, but not something Enter should act on.
# Group headings are matched by prefix because there is one per group.
_DECOR = (
    "__counts__",
    "__spacer1__", "__spacer2__", "__spacer3__",
    "__apprhead__", "__apprnone__", "__filterline__",
)


def _is_decor(oid: str) -> bool:
    """Section headings and spacer lines: visible, but Enter does nothing."""
    return oid in _DECOR or oid.startswith("__group__")


def _action_color(theme: Any, action: str) -> str:
    action = str(action or "").strip().lower()
    if action == "allow":
        return theme.c("success")
    if action == "deny":
        return theme.c("error")
    if action == "ask":
        return theme.c("warning")
    return theme.c("text_muted")


def _plain(markup: str) -> str:
    """Rich markup -> readable text, for substring filtering."""
    return re.sub(r"\[/?[^\]]*\]", "", str(markup))


def user_action(user: dict[str, Any], tool: str, pattern: str) -> str | None:
    """The action the USER set for this exact key, or None when inherited."""
    if tool not in user:
        return None
    value = user[tool]
    if isinstance(value, dict):
        return str(value[pattern]) if pattern in value else None
    return str(value) if pattern == "*" else None


class PermissionsPopup(ModalScreen[None]):
    """View and edit the effective permission rules. Esc closes."""

    BINDINGS = [
        Binding("left", "step_prev", "Prev", show=False),
        Binding("right", "step_next", "Next", show=False),
    ]

    CSS = """
    PermissionsPopup {
        align: center middle;
    }
    #perm-hint {
        color: $text-muted;
        height: auto;
        max-height: 14;
        margin-top: 1;
    }
    # border: none is load-bearing. Textual's default OptionList border is
    # "tall", which draws half-block spikes down both sides and turns accent
    # (orange) when focused — an inner box inside the popup's round border.
    # #session-list carries the same reset in app.py.
    #perm-list {
        height: auto;
        max-height: 30;
        background: transparent;
        border: none;
        padding: 0;
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 0;
    }
    #perm-input {
        display: none;
        height: 3;
    }
    #perm-input.-on {
        display: block;
    }
    """

    def __init__(
        self,
        mode: str = "auto",
        agent: str = "build",
        user_permission: dict[str, Any] | None = None,
        cfg: Any = None,
        engine: Any = None,
        on_rule_change: Callable[[str, str, str | None], None] | None = None,
        on_mode_change: Callable[[str], None] | None = None,
        on_clear_approved: Callable[[str | None], None] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._mode = mode
        self._agent = agent
        self._user_permission = dict(user_permission or {})
        self._cfg = cfg
        self._engine = engine
        self._on_rule_change = on_rule_change
        self._on_mode_change = on_mode_change
        self._on_clear_approved = on_clear_approved
        self._filter = ""
        self._filtering = False
        self._help = False
        self._editing = False  # an Input has focus: swallow every shortcut
        self._input_kind = ""  # "test" | "pattern"

    # -- data ---------------------------------------------------------------
    def _approved(self) -> list[str]:
        """Session "always allow" exemptions, via the public accessor."""
        getter = getattr(getattr(self._engine, "permission", None),
                         "approved_patterns", None)
        if getter is None:
            return []
        try:
            return list(getter())
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:_approved")
            return []

    def _user(self) -> dict[str, Any]:
        """Live user rules; the cfg is the live object the caller mutates."""
        return dict(getattr(self._cfg, "permission", None) or self._user_permission)

    def _current_mode(self) -> str:
        return str(getattr(self._cfg, "permission_mode", None) or self._mode)

    # -- rendering ----------------------------------------------------------
    def _all_rows(self) -> list[tuple[str, str]]:
        theme = active_theme()
        muted, text, accent = theme.c("text_muted"), theme.c("text"), theme.c("accent")
        err = theme.c("error")
        mode, agent, user = self._current_mode(), self._agent, self._user()
        rows = effective_permission_rows(mode, agent, user, self._cfg)
        mine = sum(1 for r in rows if r.source == RULE_SOURCE_USER)
        approved = self._approved()

        out: list[tuple[str, str]] = [
            ("__mode__", f"[{accent}]{escape(agent)}[/] [{muted}]mode:[/] "
                         f"[{accent}]{escape(mode)}[/]  ⏎/m to change"),
            ("__counts__",
             f"[{muted}]{len(rows)} rules · {mine} yours · {len(approved)} "
             f"always-allowed[/]"),
        ]
        out.append(("__spacer1__", " "))

        # always-allowed sits high: it is invisible session state, and the whole
        # reason it matters is that nothing else on screen reveals it
        out.append(("__apprhead__",
                    f"[{muted}]Always-allowed this session:[/] "
                    f"[{accent}]{len(approved)}[/]"))
        if approved:
            for i, pat in enumerate(approved):
                out.append((f"__appr__{i}",
                            f"  [{muted}]{escape(pat)}[/]  [{accent}]x to revoke[/]"))
            out.append(("__apprclear__", f"  [{err}]X / ⏎ clear all[/]"))
        else:
            out.append(("__apprnone__", f"  [{muted}]nothing saved yet[/]"))
        out.append(("__spacer2__", " "))

        # id must be unique per row: Textual rejects duplicate option ids, and
        # there is one heading per group, so a shared "__group__" would crash
        for gi, (title, grouped) in enumerate(group_permission_rows(rows)):
            denies = sum(1 for r in grouped if r.action == "deny")
            mark = f"  [{err}]{denies} denied[/]" if denies else ""
            out.append((f"__group__{gi}__{title}",
                        f"[{accent}]{escape(title.upper())}[/]{mark}"))
            for row in grouped:
                name = row.tool if row.pattern == "*" else f"{row.tool} {row.pattern}"
                own = user_action(user, row.tool, row.pattern)
                who = RULE_SOURCE_USER if own else row.source
                col = accent if own else muted
                body = muted if row.shadowed else text
                if row.invalid:
                    action, acol = f"{row.action} (invalid)", err
                else:
                    action, acol = row.action, _action_color(theme, row.action)
                note = (f" [{muted}]→ {row.verdict} in {escape(mode)}[/]"
                        if row.action == "ask" and row.verdict != "ask" else "")
                shadow = f" [{muted}]shadowed by *[/]" if row.shadowed else ""
                out.append((
                    f"__rule__{row.tool}{_SEP}{row.pattern}",
                    f"[{body}]{escape('  ' + name)}[/]  [{acol}]{escape(action)}[/]"
                    f"{note}  [{col}]{escape(who)}[/]{shadow}",
                ))

        if self._filter:
            out.append(("__spacer3__", " "))
            out.append(("__filterline__",
                        f"[{accent}]filter:[/] [{accent}]{escape(self._filter)}[/]"))
        return out

    def _options(self) -> list[Option]:
        rows = self._all_rows()
        if self._filter:
            q = self._filter.lower()
            rows = [(rid, txt) for rid, txt in rows if q in _plain(txt).lower()]
        return [Option(txt, id=rid, disabled=_is_decor(rid)) for rid, txt in rows]

    def _rebuild_keep_focus(self) -> None:
        keep: str | None = None
        try:
            lst = self.query_one("#perm-list", OptionList)
            opt = lst.highlighted_option
            keep = str(getattr(opt, "id", "") or "") if opt is not None else None
        except Exception:
            keep = None
        try:
            lst = self.query_one("#perm-list", OptionList)
            lst.clear_options()
            lst.add_options(self._options())
            if keep is not None:
                for i in range(lst.option_count):
                    try:
                        if str(lst.get_option_at_index(i).id or "") == keep:
                            lst.highlighted = i
                            break
                    except Exception as _oc_exc:
                        swallow(_oc_exc, "tui/permissions_popup.py:188")
                        continue
            lst.focus()
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:191")
        self._render_hint()

    def _describe_selection(self) -> str:
        """One plain sentence about whatever the cursor is on, plus what the
        keys do HERE. Context beats a static key legend: the same key means
        different things on a rule than on an approval."""
        oid = self._highlighted_id()
        if oid == "__mode__":
            mode = self._current_mode()
            return (f"MODE is {mode} — {MODE_MEANING.get(mode, '')}. "
                    f"⏎/m switches to the next one.")
        if oid.startswith("__group__"):
            return "group heading — just a label, use ↑/↓ to move on"
        if oid == "__apprclear__":
            return "⏎ or X forgets EVERY always-allowed entry from this session"
        if oid == "__apprhead__":
            return ("things you said 'always allow' to earlier this session — "
                    "they never ask again until you restart or press x")
        if oid.startswith("__appr__"):
            return ("⏎ or x takes this permission away, so the agent will ASK "
                    "again next time")
        parsed = self._parse_rule(oid)
        if parsed is None:
            return "information only — use ↑/↓ to move"
        tool, pattern = parsed
        rows = {r.pattern: r for r in effective_permission_rows(
            self._current_mode(), self._agent, self._user(), self._cfg)
            if r.tool == tool}
        row = rows.get(pattern)
        if row is None:
            return f"{tool} {pattern} — no rule"
        mine = user_action(self._user(), tool, pattern)
        where = "YOUR rule" if mine else f"from {row.source}"
        acts = ""
        if row.invalid:
            acts = f" — '{row.action}' is not a real action, so it never matches"
        elif row.action == "ask" and row.verdict != "ask":
            acts = (f" — {row.action}, but {self._current_mode()} mode turns that "
                    f"into {row.verdict}, so it will NOT stop and ask")
        elif row.action == "ask":
            acts = " — it WILL stop and ask you"
        elif row.action == "deny":
            acts = " — it is blocked"
        elif row.action == "allow":
            acts = " — it just happens, no prompt"
        if mine:
            return (f"{tool} {pattern}: {mine} ({where}){acts}. "
                    f"⏎/→ steps it on, ← back, x deletes your rule")
        return (f"{tool} {pattern}: {row.action} ({where}){acts}. "
                f"⏎ adds a rule of your own (ask → deny → allow)")

    def _render_hint(self) -> None:
        try:
            theme = active_theme()
            muted, accent = theme.c("text_muted"), theme.c("accent")
            if self._editing:
                lines = ["Enter to run · Esc to cancel"]
            elif self._help:
                lines = [
                    "KEYS",
                    "  ↑/↓  move between lines          ⏎ or →  change this line",
                    "  ←  change it backwards           m  switch the permission mode",
                    "  x  delete this rule / revoke     n  add a new pattern here",
                    "  t  test a command safely         a  jump to always-allowed",
                    "  /  filter the list               ?  close this help",
                    "  Esc  clear filter, then close",
                    "",
                    "Each rule line cycles: no rule of yours → ask → deny → allow → none.",
                    "Cycling back to 'none' removes your rule and restores the default.",
                    "The first line is the MODE: it decides whether anything asks you.",
                    "Group headings are just labels. 'via *' means no rule of its own, so",
                    "the * fallback at the bottom decides it.",
                ]
            else:
                lines = [
                    self._describe_selection(),
                    "⏎ change · m mode · t test · n new · a approvals · x delete "
                    "· / filter · ? help",
                ]
            self.query_one("#perm-hint", Static).update(
                "".join(f"[{accent}]•[/] [{muted}]{line}[/]\n"
                        for line in lines).rstrip("\n")
            )
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:_render_hint")

    def compose(self) -> ComposeResult:
        with Vertical(classes="cmd-popup session-popup"):
            yield Static("  Permissions  ", classes="cmd-popup-title")
            yield OptionList(*self._options(), id="perm-list")
            yield Input(placeholder="", id="perm-input")
            yield Static("", classes="cmd-popup-usage", id="perm-hint")

    def on_mount(self) -> None:
        try:
            self.query_one("#perm-list", OptionList).focus()
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:on_mount")
        self._render_hint()

    # -- selection ----------------------------------------------------------
    def _highlighted_id(self) -> str:
        try:
            lst = self.query_one("#perm-list", OptionList)
            opt = lst.highlighted_option
            return str(getattr(opt, "id", "") or "") if opt is not None else ""
        except Exception:
            return ""

    @staticmethod
    def _parse_rule(oid: str) -> tuple[str, str] | None:
        if not oid.startswith("__rule__"):
            return None
        body = oid[len("__rule__"):]
        tool, sep, pattern = body.partition(_SEP)
        return (tool, pattern) if (tool or sep) else None

    def _parse_approval(self, oid: str) -> str | None:
        """The approved PATTERN for an approval row, or None."""
        if not oid.startswith("__appr__"):
            return None
        try:
            i = int(oid[len("__appr__"):])
        except ValueError:
            return None
        approved = self._approved()
        return approved[i] if 0 <= i < len(approved) else None

    # -- mutations ----------------------------------------------------------
    def _cycle_rule(self, tool: str, pattern: str, forward: bool = True) -> None:
        current = user_action(self._user(), tool, pattern) or "inherit"
        table = _NEXT if forward else _PREV
        nxt = table.get(str(current).lower(), "ask")
        if self._on_rule_change is not None:
            try:
                self._on_rule_change(tool, pattern, None if nxt == "inherit" else nxt)
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/permissions_popup.py:_cycle_rule")
        self._refresh()

    def _delete_rule(self) -> None:
        parsed = self._parse_rule(self._highlighted_id())
        if parsed is None:
            return
        tool, pattern = parsed
        if user_action(self._user(), tool, pattern) is None:
            self.notify("Inherited — there is no rule of yours to remove",
                        severity="information")
            return
        if self._on_rule_change is not None:
            try:
                self._on_rule_change(tool, pattern, None)
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/permissions_popup.py:_delete_rule")
        self._refresh()

    def _cycle_mode(self, forward: bool = True) -> None:
        try:
            i = _MODES.index(self._current_mode())
        except ValueError:
            i = 0
        nxt = _MODES[(i + (1 if forward else -1)) % len(_MODES)]
        if self._on_mode_change is not None:
            try:
                self._on_mode_change(nxt)
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/permissions_popup.py:_cycle_mode")
        self._refresh()
        # say what the new mode DOES, right when it changes — a permanent
        # sentence above the list was noise, silence here would be confusing
        self._notify(f"Mode is now {nxt} — it {MODE_MEANING.get(nxt, '')}",
                     severity="warning" if nxt in ("ask", "deny") else "information")

    def _clear_approved(self, pattern: str | None) -> None:
        if self._on_clear_approved is not None:
            try:
                self._on_clear_approved(pattern)
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/permissions_popup.py:_clear_approved")
        self._refresh()

    def _refresh(self) -> None:
        self._user_permission = self._user()
        self._rebuild_keep_focus()

    def _notify(self, msg: str, severity: str = "information") -> None:
        try:
            self.app.notify(msg, severity=severity)
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:_notify")

    # -- input box ----------------------------------------------------------
    def _open_input(self, kind: str, placeholder: str) -> None:
        self._editing, self._input_kind = True, kind
        try:
            box = self.query_one("#perm-input", Input)
            box.placeholder = placeholder
            box.value = ""
            box.add_class("-on")
            box.focus()
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:_open_input")
        self._render_hint()

    def _close_input(self) -> None:
        self._editing, self._input_kind = False, ""
        try:
            box = self.query_one("#perm-input", Input)
            box.remove_class("-on")
            box.value = ""
            self.query_one("#perm-list", OptionList).focus()
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:_close_input")
        self._render_hint()

    def _submit_input(self, text: str) -> None:
        value = (text or "").strip()
        kind = self._input_kind
        self._close_input()
        if not value:
            return
        if kind == "test":
            self._explain(value)
            return
        parsed = self._parse_rule(self._highlighted_id())
        if parsed is None:
            self.notify("Put the cursor on a rule first, then press n",
                        severity="warning")
            return
        if self._on_rule_change is not None:
            try:
                self._on_rule_change(parsed[0], value, "allow")
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/permissions_popup.py:_submit_input")
        self._refresh()

    def _explain(self, command: str) -> None:
        """Run one command through the LIVE engine and report the verdict."""
        explain = getattr(getattr(self._engine, "permission", None), "explain", None)
        if explain is None:
            self.notify("No live engine here — rules are listed but cannot be tested",
                        severity="warning")
            return
        head, _, rest = command.partition(" ")
        verdict, action, source = explain(head, rest)
        src = f" via rule {source}" if source else " (nothing matched → would ask)"
        # say it the same way the table does: in auto an ask really does
        # resolve to allow, and a bare "allow" would hide that
        shown = verdict if verdict == action else f"{action} → {verdict}"
        self.notify(f"{command}  →  {shown}{src}", severity=(
            "error" if verdict == "deny"
            else "warning" if verdict == "ask" else "information"
        ))

    # -- events -------------------------------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit_input(event.value)
        event.stop()

    def on_option_list_option_highlighted(self, event: Any) -> None:
        # the footer explains whatever is under the cursor, so it has to be
        # rebuilt every time the cursor moves
        event.stop()
        self._render_hint()

    def on_option_list_option_selected(self, event: Any) -> None:
        event.stop()
        oid = self._highlighted_id()
        if oid == "__mode__":
            self._cycle_mode(True)
            return
        if oid == "__apprclear__":
            self._clear_approved(None)
            return
        pattern = self._parse_approval(oid)
        if pattern is not None:
            self._clear_approved(pattern)
            return
        parsed = self._parse_rule(oid)
        if parsed is not None:
            self._cycle_rule(parsed[0], parsed[1], True)

    def on_key(self, event: Key) -> None:
        if self._editing:
            if event.key == "escape":
                self._close_input()
            event.stop()
            return
        key = event.key
        if key == "escape":
            if self._filtering or self._filter:
                self._filtering, self._filter = False, ""
                self._rebuild_keep_focus()
            else:
                self.dismiss(None)
            event.stop()
        elif key in ("left", "right"):
            parsed = self._parse_rule(self._highlighted_id())
            if parsed is not None:
                self._cycle_rule(parsed[0], parsed[1], forward=(key == "right"))
            elif key == "right" and self._highlighted_id() == "__mode__":
                self._cycle_mode(True)
            event.stop()
        elif key == "backspace":
            if self._filtering:
                self._filter = self._filter[:-1]
                self._rebuild_keep_focus()
            event.stop()
        else:
            # Punctuation arrives NAMED, not as the character: "/" is
            # event.key == "slash" and "?" is "question_mark", while event.key
            # is only ever the single character for letters. Gating on
            # len(event.key) == 1 therefore silently killed both / and ?.
            ch = getattr(event, "character", None)
            if ch and ch.isprintable() and ch != " ":
                self._keypress(ch)
                event.stop()

    def _keypress(self, key: str) -> None:
        if self._filtering:
            self._filter += key
            self._rebuild_keep_focus()
            return
        k = key.lower()
        if k == "/":
            self._filtering = True
            self._help = False
            self._rebuild_keep_focus()
        elif k == "?":
            self._help = not self._help
            self._render_hint()
        elif k == "m":
            self._cycle_mode(True)
        elif k == "t":
            self._open_input("test", "type a command to check — e.g. bash rm -rf x (this does NOT run it)")
        elif k == "n":
            self._open_input("pattern", "pattern to allow for this tool — e.g. *git status*")
        elif k == "a":
            self._jump_approved()
        elif k == "x":
            pattern = self._parse_approval(self._highlighted_id())
            if self._highlighted_id() == "__apprclear__":
                self._clear_approved(None)
            elif pattern is not None:
                self._clear_approved(pattern)
            else:
                self._delete_rule()

    def _jump_approved(self) -> None:
        try:
            lst = self.query_one("#perm-list", OptionList)
            for i in range(lst.option_count):
                oid = str(lst.get_option_at_index(i).id or "")
                if oid.startswith("__appr__") and self._parse_approval(oid):
                    lst.highlighted = i
                    return
            self.notify("Nothing has been always-allowed this session")
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/permissions_popup.py:_jump_approved")

    def action_step_prev(self) -> None:
        parsed = self._parse_rule(self._highlighted_id())
        if parsed is not None:
            self._cycle_rule(parsed[0], parsed[1], forward=False)

    def action_step_next(self) -> None:
        parsed = self._parse_rule(self._highlighted_id())
        if parsed is not None:
            self._cycle_rule(parsed[0], parsed[1], forward=True)