"""Checks for the /permissions view model and the popup's edit path.

The load-bearing cases: the mode matrix must match what evaluate() has always
done, explain() must be side-effect free, and editing a rule must NOT revoke
the "always allow" exemptions a rules rebuild would otherwise throw away.
"""

from types import SimpleNamespace

import pytest

from opencode_py.permission import (
    PermissionEngine, _apply_mode, effective_permission_rows, would_ask_in,
)
from opencode_py.config import Config


def test_apply_mode_matches_original_evaluate_branching():
    """The extracted _apply_mode must reproduce the pre-refactor behaviour."""
    def original(mode: str, action: str) -> str:
        if mode == "fully_auto":
            return "deny" if action == "deny" else "allow"
        if action == "ask":
            if mode == "deny":
                return "deny"
            if mode == "auto":
                return "allow"
            return "ask"
        return action

    for mode in ("auto", "ask", "deny", "fully_auto"):
        for action in ("allow", "ask", "deny"):
            assert _apply_mode(mode, action) == original(mode, action), (mode, action)


def test_explain_is_side_effect_free():
    """Opening the viewer must not feed the doom-loop ledger."""
    eng = PermissionEngine.from_config({"bash": {"*": "allow", "rm *": "deny"}})
    for _ in range(10):
        eng.explain("bash", "rm -rf /")
    assert eng._last_calls == []


def test_explain_reports_the_winning_pattern():
    eng = PermissionEngine.from_config(
        {"read": {"*": "allow", "*.env": "ask"}}, mode="ask")
    verdict, action, source = eng.explain("read", "cfg/.env")
    assert (verdict, action, source) == ("ask", "ask", "*.env")
    # auto swallows the ask, and says so
    eng.mode = "auto"
    assert eng.explain("read", "cfg/.env")[0] == "allow"


def test_rows_attribute_each_rule_to_its_layer():
    cfg = Config()
    cfg.agents = {"build": {"tools": {"webfetch": "deny"}}}
    cfg.permission = {"bash": "ask"}
    rows = effective_permission_rows("auto", "build", cfg.permission, cfg)
    src = {(r.tool, r.pattern): r.source for r in rows}
    assert src[("bash", "*")] == "you"
    assert src[("webfetch", "*")] == "agent"
    assert src[("phone", "*")] == "default"


def test_agent_rules_are_visible_when_cfg_is_supplied():
    """The gap that made the screen lie: without cfg, agent rules vanished."""
    cfg = Config()
    cfg.agents = {"build": {"tools": {"webfetch": "deny"}}}
    user = {"bash": "ask"}
    with_cfg = {r.tool for r in effective_permission_rows("auto", "build", user, cfg)}
    without = {r.tool for r in effective_permission_rows("auto", "build", user, None)}
    assert "webfetch" in with_cfg
    assert "webfetch" not in without


def test_comment_key_never_renders_as_a_rule():
    rows = effective_permission_rows("auto", "build", {"_comment": "hi"}, None)
    assert not any(r.tool == "_comment" for r in rows)


def test_mistyped_action_is_flagged_not_silently_shown():
    rows = effective_permission_rows("auto", "build", {"typo": {"*": "alow"}}, None)
    bad = [r for r in rows if r.tool == "typo"]
    assert bad and bad[0].invalid


def test_shadowed_rule_is_marked_only_when_really_unreachable():
    # a later "*" makes every earlier pattern for that tool dead
    rows = {(r.tool, r.pattern): r.shadowed
            for r in effective_permission_rows(
                "auto", "build", {"bash": {"rm *": "deny", "*": "allow"}}, None)}
    assert rows[("bash", "rm *")] is True
    # without the later catch-all nothing is shadowed
    rows2 = {(r.tool, r.pattern): r.shadowed
             for r in effective_permission_rows(
                 "auto", "build", {"bash": {"rm *": "deny"}}, None)}
    assert rows2[("bash", "rm *")] is False


def test_would_ask_in_survives_an_all_green_default_install():
    """The default install is all-green under `auto`, so every ask rule must
    announce that it is being auto-approved away. The popup does this per row
    ("ask → allowed in auto") rather than as a summary line, so assert on the
    rendered text — that is what the user actually reads."""
    from opencode_py.tui.permissions_popup import _plain

    rows = effective_permission_rows("auto", "build", {}, None)
    assert all(r.verdict == "allow" for r in rows if r.action == "ask")
    assert "read *.env" in would_ask_in(rows)

    screen = _screen()
    screen._cfg.permission_mode = "auto"
    text = [_plain(t) for _i, t in screen._all_rows()]
    annotated = [t for t in text if "ask" in t and "→ allow in auto" in t]
    assert annotated, "no row explained that auto swallows the ask"
    assert any("read *.env" in t for t in annotated)


def test_adopt_from_preserves_both_ledgers():
    old = PermissionEngine.from_config({"*": "allow"})
    old.ask_callback = lambda d, p: "always"
    old.ask("d", ["git status"])
    old._last_calls.append(("bash", "ls"))
    fresh = PermissionEngine.from_config({"*": "deny"})
    fresh.adopt_from(old)
    assert fresh.approved_patterns() == ["git status"]
    assert fresh.doom_window() == [("bash", "ls")]


# -- the popup's edit path (persistence stubbed out) --------------------------

def _host_with_engine(approved=()):
    from opencode_py.tui.settings import SettingsMixin

    class FakeEngine:
        """Hashable on purpose: _live_engines de-dupes with dict.fromkeys,
        exactly as _apply_runtime_settings already does."""

        def __init__(self, agent):
            self.agent = agent
            self.permission = PermissionEngine.from_config({"*": "allow"})
            self.permission.ask_callback = lambda d, p: "always"
            for pat in approved:
                self.permission.ask("d", [pat])

    class Host(SettingsMixin):
        def __init__(self):
            self.cfg = Config()
            self.notes = []
            self.saves = 0
            self._engines = {"s1": FakeEngine("build")}
            self._main_engine = None

        def notify(self, msg, severity="information"):
            self.notes.append((msg, severity))

        def _persist_permission(self):
            self.saves += 1
            return None

    return Host()


def test_cycling_a_rule_persists_and_keeps_always_allow():
    host = _host_with_engine(approved=["git status"])
    host._apply_permission_rule("bash", "*", "deny")
    assert host.cfg.permission == {"bash": "deny"}
    assert host.saves == 1
    # the engine was rebuilt with the new rules...
    eng = host._engines["s1"].permission
    assert eng.explain("bash", "ls")[0] == "deny"
    # ...but the user's always-allow exemption survived the rebuild
    assert eng.approved_patterns() == ["git status"]


def test_editing_one_pattern_keeps_its_siblings():
    host = _host_with_engine()
    host.cfg.permission = {"read": {"*.env": "ask"}}
    host._apply_permission_rule("read", "*.secret", "deny")
    # only the new key was added to the user's dict
    assert host.cfg.permission == {"read": {"*.env": "ask", "*.secret": "deny"}}
    # and the agent default's other patterns are still enforced
    eng = host._engines["s1"].permission
    assert eng.explain("read", "app.example")[0] == "allow"


def test_removing_the_last_pattern_drops_the_tool_entirely():
    host = _host_with_engine()
    host.cfg.permission = {"read": {"*.env": "ask"}}
    host._apply_permission_rule("read", "*.env", None)
    assert host.cfg.permission == {}


def test_adding_a_pattern_to_a_scalar_rule_promotes_it_to_a_dict():
    host = _host_with_engine()
    host.cfg.permission = {"bash": "deny"}
    host._apply_permission_rule("bash", "*git status*", "allow")
    assert host.cfg.permission == {"bash": {"*": "deny", "*git status*": "allow"}}


def test_unknown_action_is_refused_and_not_saved():
    host = _host_with_engine()
    host._apply_permission_rule("bash", "*", "yolo")
    assert host.cfg.permission in (None, {})
    assert host.saves == 0
    assert host.notes and host.notes[0][1] == "error"


def test_changing_mode_persists_without_rebuilding_engines():
    host = _host_with_engine(approved=["git status"])
    before = host._engines["s1"].permission
    host._apply_permission_mode("ask")
    assert host.cfg.permission_mode == "ask"
    assert host.saves == 1
    assert host._engines["s1"].permission is before  # same object, memory intact
    assert before.approved_patterns() == ["git status"]


def test_revoking_one_always_allow_leaves_the_others():
    host = _host_with_engine(approved=["git status", "ls -la"])
    host._clear_permission_approvals("git status")
    assert host._engines["s1"].permission.approved_patterns() == ["ls -la"]
    host._clear_permission_approvals(None)
    assert host._engines["s1"].permission.approved_patterns() == []


def test_popup_rows_render_without_a_running_app():
    from opencode_py.tui.permissions_popup import PermissionsPopup

    cfg = Config()
    cfg.permission = {"bash": "ask"}
    screen = PermissionsPopup.__new__(PermissionsPopup)
    screen._cfg, screen._mode, screen._agent = cfg, "auto", "build"
    screen._user_permission, screen._engine = {}, None
    screen._filter, screen._filtering = "", False
    screen._editing, screen._input_kind = False, ""
    rows = screen._all_rows()
    ids = [rid for rid, _txt in rows]
    assert ids[0] == "__mode__"
    assert any(i.startswith("__rule__bash") for i in ids)
    assert "__apprhead__" in ids and "__apprnone__" in ids


def _screen(perm=None, appr=()):
    """A PermissionsPopup wired to a real PermissionEngine, with no App."""
    from opencode_py.tui.permissions_popup import PermissionsPopup

    cfg = Config()
    cfg.permission = dict(perm or {})
    engine_perm = PermissionEngine.from_config({"*": "allow"})
    engine_perm.ask_callback = lambda d, p: "always"
    for pat in appr:
        engine_perm.ask("d", [pat])

    screen = PermissionsPopup.__new__(PermissionsPopup)
    screen._cfg, screen._mode, screen._agent = cfg, "auto", "build"
    screen._engine = SimpleNamespace(permission=engine_perm)
    screen._user_permission = {}
    screen._filter, screen._filtering = "", False
    screen._editing, screen._input_kind = False, ""
    screen._help = False
    screen.calls = []
    # mirrors the real contract: the caller owns persistence and mutates cfg,
    # and the popup re-reads cfg after every callback
    def _rule_change(tool, pattern, action):
        screen.calls.append((tool, pattern, action))
        perm = dict(screen._cfg.permission or {})
        cur = perm.get(tool)
        if action is None:
            if isinstance(cur, dict):
                cur = dict(cur)
                cur.pop(pattern, None)
                if cur:
                    perm[tool] = cur
                else:
                    perm.pop(tool, None)
            else:
                perm.pop(tool, None)
        elif isinstance(cur, dict):
            cur = dict(cur)
            cur[pattern] = action
            perm[tool] = cur
        elif pattern == "*":
            perm[tool] = action
        else:
            perm[tool] = {"*": cur, pattern: action} if isinstance(cur, str) \
                else {pattern: action}
        screen._cfg.permission = perm

    screen._on_rule_change = _rule_change
    screen._on_mode_change = lambda m: screen.calls.append(("mode", m))
    screen._on_clear_approved = lambda p: screen.calls.append(("clear", p))
    screen.notes = []
    screen.notify = lambda msg, severity="information": screen.notes.append(msg)
    return screen


def test_cycling_walks_a_full_loop_and_returns_to_inherit():
    """inherit -> ask -> deny -> allow -> inherit, with inherit meaning DELETE.

    Without the fourth state an edit could never be undone.
    """
    screen = _screen()
    seen = []
    for _ in range(4):
        screen._cycle_rule("bash", "*")
        seen.append(screen.calls[-1][2])
    assert seen == ["ask", "deny", "allow", None]


def test_cycling_a_pattern_the_user_already_set_resumes_from_that_value():
    screen = _screen(perm={"bash": "deny"})
    screen._cycle_rule("bash", "*")
    assert screen.calls[-1][2] == "allow"


def test_removing_an_inherited_rule_is_refused():
    """A default rule is not yours to delete; x must say so, not call back."""
    screen = _screen()
    screen._highlighted_id = lambda: "__rule__bash\x1f*"
    screen._delete_rule()
    assert screen.calls == []
    assert screen.notes and "Inherited" in screen.notes[0]


def test_revoking_one_always_allow_passes_the_pattern_through():
    screen = _screen(appr=["ls -la", "git push"])
    assert screen._approved() == ["ls -la", "git push"]
    screen._clear_approved("ls -la")
    assert screen.calls[-1] == ("clear", "ls -la")


def test_approval_row_index_cannot_read_out_of_range():
    screen = _screen(appr=["ls -la"])
    assert screen._parse_approval("__appr__0") == "ls -la"
    assert screen._parse_approval("__appr__9") is None
    assert screen._parse_approval("__appr__head") is None
    assert screen._parse_approval("__mode__") is None


def test_rule_row_ids_survive_tools_with_patterns():
    screen = _screen()
    parsed = screen._parse_rule("__rule__read\x1f*.env.*")
    assert parsed == ("read", "*.env.*")
    assert screen._parse_rule("__mode__") is None


def test_mode_cycles_forward_and_wraps():
    screen = _screen()
    screen._cfg.permission_mode = "auto"
    screen._cycle_mode(True)
    assert screen.calls[-1] == ("mode", "ask")
    screen._cfg.permission_mode = "fully_auto"
    screen._cycle_mode(True)
    assert screen.calls[-1] == ("mode", "auto")


def _failing_host():
    host = _host_with_engine()
    host._persist_permission = lambda: "Save failed: disk full"
    return host


def test_a_failed_save_rolls_the_rules_back():
    """Otherwise the popup re-reads cfg and shows a rule that is neither
    enforced nor on disk."""
    host = _failing_host()
    host._apply_permission_rule("bash", "*", "deny")
    assert not host.cfg.permission
    assert host.notes and host.notes[0][1] == "error"


def test_a_failed_save_rolls_the_mode_back():
    host = _failing_host()
    host._apply_permission_mode("deny")
    assert host.cfg.permission_mode == "auto"
    assert host.notes and host.notes[0][1] == "error"


def test_a_failed_save_leaves_the_engines_alone():
    host = _failing_host()
    before = host._engines["s1"].permission
    host._apply_permission_rule("bash", "*", "deny")
    assert host._engines["s1"].permission is before
    assert before.explain("bash", "ls")[0] == "allow"  # still allowed, as before


# -- grouping ------------------------------------------------------------------

def test_groups_are_ordered_by_risk():
    from opencode_py.permission import group_permission_rows

    rows = effective_permission_rows("auto", "build", {}, None)
    titles = [t for t, _ in group_permission_rows(rows)]
    assert titles[0] == "Commands & file changes"
    assert titles.index("Commands & file changes") < titles.index("Reading your code")
    # the catch-all is a footnote, never the first thing on screen
    assert titles[-1] == "Fallback for unlisted tools"


def test_the_catch_all_is_listed_exactly_once():
    from opencode_py.permission import group_permission_rows

    rows = effective_permission_rows("auto", "build", {}, None)
    starred = [r for r in rows if r.tool == "*"]
    assert starred, "the default '*' rule should be present"
    in_groups = [r for _t, grouped in group_permission_rows(rows) for r in grouped
                 if r.tool == "*"]
    assert len(in_groups) == len(starred) == 1


def test_an_unknown_tool_is_not_invented_into_a_group():
    from opencode_py.permission import group_permission_rows

    rows = effective_permission_rows("auto", "build", {"my_custom_tool": "ask"}, None)
    grouped = dict(group_permission_rows(rows))
    assert "my_custom_tool" in [r.tool for r in grouped["Everything else"]]


def test_your_own_rules_lead_their_group():
    from opencode_py.permission import group_permission_rows

    rows = effective_permission_rows(
        "auto", "build", {"webreach": "deny", "bash": "ask"}, None)
    grouped = dict(group_permission_rows(rows))
    web = [r.tool for r in grouped["Internet & device"]]
    assert web[0] == "webreach"  # yours, before the four defaults


def test_pattern_order_within_a_tool_is_never_reordered():
    """Evaluation is last-match-wins over dict order, so the display must not
    reshuffle a tool's patterns — that would contradict the engine."""
    from opencode_py.permission import group_permission_rows

    rows = effective_permission_rows(
        "auto", "build", {"read": {"*.env.*": "ask", "*.env.example": "allow"}}, None)
    # '*' and '*.env' come from the agent default; the user's two keys merge
    # into their existing slots rather than being appended
    listed = [r.pattern for r in rows if r.tool == "read"]
    assert listed == ["*", "*.env", "*.env.*", "*.env.example"]
    grouped = [r.pattern for _t, g in group_permission_rows(rows) for r in g
               if r.tool == "read"]
    assert grouped == listed
    # and the engine agrees with the order shown
    eng = PermissionEngine.from_config(
        {"read": {"*.env.*": "ask", "*.env.example": "allow"}}, mode="ask")
    assert eng.explain("read", "app/.env.example")[0] == "allow"


def test_empty_groups_are_dropped():
    from opencode_py.permission import group_permission_rows

    rows = effective_permission_rows("auto", "build", {"bash": "ask"}, None)
    titles = [t for t, _ in group_permission_rows(rows)]
    # no custom tools configured, so the unclaimed bucket has nothing in it
    assert "Everything else" not in titles


def test_every_row_id_is_unique_and_a_real_optionlist_accepts_it():
    """Regression: each group heading used the same id "__group__", and
    Textual raises DuplicateID on the second one — the popup crashed on open.

    Membership checks could never have caught this; the ids have to be built
    for real.
    """
    from textual.widgets import OptionList

    screen = _screen(perm={"bash": "ask"}, appr=["ls -la"])
    ids = [rid for rid, _txt in screen._all_rows()]
    assert len(ids) == len(set(ids)), "duplicate row id would crash OptionList"
    # more than one group, which is what made the shared id fatal
    assert sum(1 for i in ids if i.startswith("__group__")) > 1
    OptionList(*screen._options())  # raises DuplicateID if ids collide


def test_the_footer_explains_the_line_under_the_cursor():
    """Bare key letters were not self-explanatory; the footer has to say what
    this line is and what the keys do to it."""
    from opencode_py.tui.permissions_popup import _plain

    screen = _screen(perm={"bash": {"*": "deny"}}, appr=["ls -la"])
    screen._cfg.permission_mode = "auto"

    screen._highlighted_id = lambda: "__mode__"
    assert "runs freely and never asks" in screen._describe_selection()

    screen._highlighted_id = lambda: "__rule__bash\x1f*"
    text = _plain(screen._describe_selection())
    assert "YOUR rule" in text and "blocked" in text
    assert "x deletes your rule" in text

    screen._highlighted_id = lambda: "__rule__read\x1f*.env"
    text = _plain(screen._describe_selection())
    # the whole point of the screen: this ask will NOT stop the agent
    assert "NOT stop and ask" in text

    screen._highlighted_id = lambda: "__apprclear__"
    assert "EVERY" in screen._describe_selection()


def test_help_toggle_shows_every_key():
    screen = _screen()
    assert screen._help is False
    screen._keypress("?")
    assert screen._help is True
    screen._keypress("?")
    assert screen._help is False


@pytest.mark.asyncio
async def test_punctuation_keys_reach_the_handler():
    """Regression: "/" and "?" arrive NAMED (event.key == "slash" /
    "question_mark"), never as a 1-char key, so the old len(key) == 1 guard
    silently disabled both the filter and the help toggle."""
    from textual.app import App
    from textual.widgets import OptionList

    from opencode_py.tui.permissions_popup import PermissionsPopup

    cfg = Config()
    cfg.permission_mode = "auto"

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(PermissionsPopup(
                mode="auto", agent="build", user_permission={}, cfg=cfg))

    app = Harness()
    async with app.run_test(size=(92, 60)) as pilot:
        await pilot.pause()
        screen = app.screen
        await pilot.press("question_mark")
        await pilot.pause()
        assert screen._help is True, "? did not toggle help"
        await pilot.press("question_mark")
        await pilot.pause()
        assert screen._help is False

        await pilot.press("slash")
        await pilot.pause()
        assert screen._filtering, "/ did not start filtering"
        before = screen.query_one("#perm-list", OptionList).option_count
        for ch in "bash":
            await pilot.press(ch)
        await pilot.pause()
        assert screen._filter == "bash"
        after = screen.query_one("#perm-list", OptionList).option_count
        assert after < before, "filter did not narrow the list"


@pytest.mark.asyncio
async def test_the_footer_follows_the_cursor():
    from textual.app import App
    from textual.widgets import OptionList

    from opencode_py.tui.permissions_popup import PermissionsPopup

    cfg = Config()
    cfg.permission_mode = "auto"

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(PermissionsPopup(
                mode="auto", agent="build",
                user_permission={"bash": {"*": "deny"}}, cfg=cfg))

    app = Harness()
    async with app.run_test(size=(92, 60)) as pilot:
        await pilot.pause()
        screen = app.screen
        lst = screen.query_one("#perm-list", OptionList)
        ids = [str(lst.get_option_at_index(i).id or "") for i in range(lst.option_count)]

        lst.highlighted = ids.index("__rule__bash\x1f*")
        await pilot.pause()
        assert "YOUR rule" in screen._describe_selection()

        lst.highlighted = ids.index("__rule__read\x1f*.env")
        await pilot.pause()
        assert "NOT stop and ask" in screen._describe_selection()


def test_group_headings_are_not_actionable_but_rules_are():
    from opencode_py.tui.permissions_popup import _is_decor

    assert _is_decor("__group__0__Reading your code")
    assert _is_decor("__counts__")
    assert _is_decor("__apprhead__") and _is_decor("__apprnone__")
    assert not _is_decor("__rule__bash\x1f*")
    assert not _is_decor("__mode__")
    assert not _is_decor("__appr__0")


# -- the real screen -----------------------------------------------------------
# The DuplicateID crash only happened inside compose(), so these drive an
# actual Textual app rather than poking the row builder.

def _harness(cfg, **kwargs):
    from textual.app import App

    from opencode_py.tui.permissions_popup import PermissionsPopup

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(PermissionsPopup(
                mode="auto", agent="build", user_permission={}, cfg=cfg, **kwargs))

    return Harness


@pytest.mark.asyncio
async def test_the_popup_opens_for_real_and_lists_every_group():
    from textual.widgets import OptionList

    app = _harness(Config())()
    async with app.run_test(size=(92, 44)) as pilot:
        await pilot.pause()
        lst = app.screen.query_one("#perm-list", OptionList)
        ids = [str(lst.get_option_at_index(i).id or "")
               for i in range(lst.option_count)]
        assert len(ids) > 5
        assert len(ids) == len(set(ids))
        assert sum(1 for i in ids if i.startswith("__group__")) > 1
        await pilot.press("down")
        await pilot.press("down")
        await pilot.pause()
        assert app.screen.query_one("#perm-list", OptionList).option_count == len(ids)


@pytest.mark.asyncio
async def test_pressing_enter_on_a_rule_edits_it_end_to_end():
    from textual.widgets import OptionList

    cfg = Config()
    seen: list = []
    app = _harness(
        cfg, on_rule_change=lambda tool, pat, act: seen.append((tool, pat, act)),
    )()
    async with app.run_test(size=(92, 44)) as pilot:
        await pilot.pause()
        lst = app.screen.query_one("#perm-list", OptionList)
        rule = next(i for i in range(lst.option_count)
                    if str(lst.get_option_at_index(i).id or "").startswith("__rule__bash"))
        lst.highlighted = rule
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    assert seen, "Enter on a rule row must call back the caller"
    tool, pattern, action = seen[0]
    assert tool == "bash"
    # first stop from "inherit" is "ask"
    assert action == "ask"


def test_the_mutators_are_always_listed_even_with_no_rule_of_their_own():
    """A default install governs bash/edit/write/apply_patch through the "*"
    catch-all. Without this they were the most dangerous tools and the only
    ones missing from the screen."""
    from opencode_py.permission import ALWAYS_SHOWN_TOOLS, RULE_SOURCE_CATCHALL

    rows = effective_permission_rows("auto", "build", {}, None)
    by_tool = {r.tool: r for r in rows}
    for tool in ALWAYS_SHOWN_TOOLS:
        assert tool in by_tool, f"{tool} vanished from the permissions screen"
        assert by_tool[tool].source == RULE_SOURCE_CATCHALL
        # the catch-all allows everything by default, so these really do pass
        assert by_tool[tool].action == "allow"


def test_an_explicit_mutator_rule_is_not_overwritten_by_the_catchall():
    from opencode_py.permission import ALWAYS_SHOWN_TOOLS

    rows = effective_permission_rows(
        "auto", "build", {"bash": {"*": "deny", "*git status*": "allow"}}, None)
    bash = [r for r in rows if r.tool == "bash"]
    assert [r.action for r in bash] == ["deny", "allow"]
    for tool in ALWAYS_SHOWN_TOOLS:
        if tool != "bash":
            assert len([r for r in rows if r.tool == tool]) == 1