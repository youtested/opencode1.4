"""Autotest: the harness runs the tests an edit touched, and feeds back.

Two layers are covered here:

- the pure module (`agent/autotest.py`): selection, the closure-green cache,
  running, parsing and formatting, all against throwaway projects;
- the loop wiring: that a red run reaches the transcript, that a green one does
  not, and that every skip path (read-only agent, `bash` already running tests,
  `task`, permission `ask`, exhausted budget) stays out of the way.

The loop tests drive real pytest in a temp project for the red/green cases and
stub `run_tests` where the point is the gate, so the suite stays fast.
"""

import pytest

from opencode_py.agent import autotest as A
from opencode_py.config import Config

# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A tiny project: pkg/mod.py plus one test that imports it."""
    root = tmp_path / "proj"
    (root / "pkg").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (root / "pkg" / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests" / "test_mod.py").write_text(
        "from pkg.mod import VALUE\n\n\ndef test_value():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    # conftest at the root makes pytest put the root on sys.path, so
    # `from pkg.mod import ...` resolves without installing anything.
    (root / "conftest.py").write_text("", encoding="utf-8")
    monkeypatch.chdir(root)
    A._SCAN_CACHE.clear()
    return root


@pytest.fixture
def passing_project(project):
    # After the edit the value moves 1 -> 5, so this stays green.
    (project / "tests" / "test_mod.py").write_text(
        "from pkg.mod import VALUE\n\n\ndef test_value():\n    assert VALUE >= 1\n",
        encoding="utf-8",
    )
    return project


# --- selection ---------------------------------------------------------------


def test_is_test_path():
    assert A.is_test_path("tests/test_x.py")
    assert A.is_test_path("pkg/test_deep.py")
    assert A.is_test_path("pkg/x_test.py")
    assert not A.is_test_path("pkg/mod.py")
    assert not A.is_test_path("tests/data.json")


def test_normalize_drops_non_python_and_outside_paths(project):
    (project / "notes.md").write_text("x", encoding="utf-8")
    got = A.normalize(project, [
        project / "pkg" / "mod.py",
        "pkg/other.py",
        project / "notes.md",
        "/etc/passwd",
    ])
    assert got == ["pkg/mod.py", "pkg/other.py"]


def test_selects_only_the_importer(project):
    (project / "tests" / "test_unrelated.py").write_text(
        "def test_nothing():\n    assert True\n", encoding="utf-8")
    got = A.select_tests(project, ["pkg/mod.py"])
    assert got == ["tests/test_mod.py"]


def test_bare_word_mentions_are_not_imports(project):
    """A comment saying "mod" is not an import — the old substring match would
    have dragged this file into every run."""
    (project / "tests" / "test_chatty.py").write_text(
        "# this file talks about pkg/mod.py and mod and edited things\n"
        "def test_nothing():\n    assert True\n",
        encoding="utf-8",
    )
    assert A.select_tests(project, ["pkg/mod.py"]) == ["tests/test_mod.py"]


def test_package_level_import_is_detected(project):
    """`from pkg import mod` loses the submodule in the symbol index, so the
    text scan has to cover it or those tests are silently skipped."""
    (project / "tests" / "test_pkg_level.py").write_text(
        "from pkg import mod\n\n\ndef test_value():\n    assert mod.VALUE == 1\n",
        encoding="utf-8",
    )
    got = A.select_tests(project, ["pkg/mod.py"])
    assert "tests/test_pkg_level.py" in got


def test_cap_is_respected_and_prefers_matching_name(project):
    for name in ("test_aaa.py", "test_zzz.py"):
        (project / "tests" / name).write_text(
            "from pkg.mod import VALUE\n\ndef test_x():\n    assert VALUE == 1\n",
            encoding="utf-8")
    got = A.select_tests(project, ["pkg/mod.py"], max_files=1)
    assert got == ["tests/test_mod.py"]


def test_edited_test_file_selects_itself(project):
    assert A.select_tests(project, ["tests/test_mod.py"]) == ["tests/test_mod.py"]


def test_green_cache_skips_untouched_closure(project):
    green = {"tests/test_mod.py": {"pkg/mod.py"}}
    assert A.select_tests(project, ["pkg/other.py"], green=green) == []


def test_green_cache_reruns_when_closure_is_touched(project):
    green = {"tests/test_mod.py": {"pkg/mod.py"}}
    assert A.select_tests(project, ["pkg/mod.py"], green=green) == ["tests/test_mod.py"]


def test_nothing_changed_selects_nothing(project):
    assert A.select_tests(project, []) == []
    assert A.select_tests(project, ["pkg/never_imported.py"]) == []


# --- running -----------------------------------------------------------------


def test_run_tests_reports_a_failure_with_its_node_id(project):
    (project / "pkg" / "mod.py").write_text("VALUE = 2\n", encoding="utf-8")
    res = A.run_tests(project, ["tests/test_mod.py"], timeout=90, workers=1)
    assert res["ok"] is False
    assert res["failed"] == 1
    assert any("test_mod.py::test_value" in fid for fid in res["failed_ids"])
    assert res["passed"] == 0


def test_run_tests_reports_a_pass(passing_project):
    res = A.run_tests(passing_project, ["tests/test_mod.py"], timeout=90, workers=1)
    assert res["ok"] is True
    assert res["passed"] == 1
    assert res["failed"] == 0


def test_run_tests_never_raises_on_a_missing_root(tmp_path):
    res = A.run_tests(tmp_path / "nope", ["tests/test_mod.py"], timeout=30, workers=1)
    assert res["ok"] is False
    assert "output" in res


def test_run_tests_with_no_files_and_no_command_is_a_noop(project):
    res = A.run_tests(project, [], timeout=30)
    assert res.get("skipped") is True


def test_custom_test_command_is_used_verbatim(project):
    (project / "check.sh").write_text("echo custom-command-ran\n", encoding="utf-8")
    res = A.run_tests(project, [], timeout=60, command="sh check.sh")
    assert "custom-command-ran" in res["output"]
    assert res["ok"] is True


def test_parallel_and_serial_agree(project):
    (project / "pkg" / "mod.py").write_text("VALUE = 2\n", encoding="utf-8")
    (project / "tests" / "test_second.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8")
    files = ["tests/test_mod.py", "tests/test_second.py"]
    serial = A.run_tests(project, files, timeout=90, workers=1)
    parallel = A.run_tests(project, files, timeout=90, workers=2)
    assert parallel["ok"] == serial["ok"] is False
    assert parallel["failed"] == serial["failed"] == 1
    assert parallel["passed"] == serial["passed"] == 1


# --- parsing and formatting --------------------------------------------------


def test_parse_counts_and_ids():
    out = ("FAILED tests/a.py::test_x - AssertionError: no\n"
           "FAILED tests/a.py::test_y\n"
           "2 failed, 144 passed, 3 skipped in 5.61s\n")
    got = A._parse(out)
    assert got["failed"] == 2 and got["passed"] == 144 and got["skipped"] == 3
    assert got["failed_ids"] == ["tests/a.py::test_x", "tests/a.py::test_y"]
    assert got["seconds"] == pytest.approx(5.61)


def test_format_pass_is_one_line():
    text = A.format_result(
        {"passed": 146, "failed": 0, "errors": 0, "seconds": 11.2, "total": 146},
        ["tests/test_a.py", "tests/test_b.py"])
    assert text.count("\n") == 0
    assert "146 passed" in text and "11.2s" in text


def test_format_failure_shows_ids():
    res = {"passed": 144, "failed": 2, "errors": 0, "seconds": 5.6, "total": 146,
           "failed_ids": ["tests/test_a.py::test_x", "tests/test_a.py::test_y"]}
    text = A.format_result(res, ["tests/test_a.py"])
    assert "2 of 146" in text
    assert "FAILED tests/test_a.py::test_x" in text
    assert "FAILED tests/test_a.py::test_y" in text


def test_format_failure_is_capped():
    res = {"passed": 0, "failed": 40, "errors": 0, "seconds": 1.0, "total": 40,
           "failed_ids": [f"tests/test_a.py::test_{i}" for i in range(40)]}
    assert len(A.format_result(res, ["tests/test_a.py"])) <= A.MAX_MSG_CHARS


def test_format_exhausted_and_edited_test_warning():
    res = {"passed": 0, "failed": 1, "errors": 0, "seconds": 1.0, "total": 1,
           "failed_ids": ["tests/test_a.py::test_x"]}
    text = A.format_result(res, ["tests/test_a.py"], edited_tests=["tests/test_a.py"],
                           exhausted=3)
    assert "stopped after 3 fix attempts" in text
    assert "weakening the test" in text


def test_command_is_deterministic(project):
    one = A._command(["tests/b.py", "tests/a.py"], command="", maxfail=0)
    two = A._command(["tests/b.py", "tests/a.py"], command="", maxfail=0)
    assert one == two and "no:cacheprovider" in one
    assert "--maxfail=3" in A._command(["tests/a.py"], command="", maxfail=3)


# --- config ------------------------------------------------------------------


def test_config_defaults_are_on():
    cfg = Config()
    assert cfg.autotest is True
    assert cfg.autotest_max_attempts == 3
    assert cfg.autotest_timeout >= 5
    assert cfg.autotest_max_files >= 1
    assert cfg.test_command == ""


def test_config_overrides_and_floors():
    cfg = Config.from_dict({
        "autotest": False, "autotest_max_attempts": 0, "autotest_timeout": 1,
        "autotest_max_files": 0, "test_command": "npm test",
    })
    assert cfg.autotest is False
    assert cfg.autotest_max_attempts == 0
    assert cfg.autotest_timeout >= 5      # floor, not 1
    assert cfg.autotest_max_files >= 1    # floor, not 0
    assert cfg.test_command == "npm test"


def test_config_alias_and_roundtrip():
    cfg = Config.from_dict({"auto_test": False})
    assert cfg.autotest is False
    keys = cfg.as_dict()
    for k in ("autotest", "autotest_max_attempts", "autotest_timeout",
              "autotest_max_files", "autotest_workers", "test_command"):
        assert k in keys


# --- prompt ------------------------------------------------------------------


def test_prompt_block_follows_the_switch(tmp_path):
    from opencode_py.agent.system import build_system_prompt, clear_prompt_cache

    clear_prompt_cache()
    on = build_system_prompt(directory=tmp_path, worktree=tmp_path,
                             provider_id="p", model_id="m", cfg=Config())
    off = build_system_prompt(directory=tmp_path, worktree=tmp_path,
                              provider_id="p", model_id="m",
                              cfg=Config(autotest=False))
    assert "[autotest]" in on
    assert "[autotest]" not in off
    clear_prompt_cache()


# --- loop wiring -------------------------------------------------------------


def _history_text(loop) -> str:
    return "\n".join(str(m.get("content") or "") for m in loop.get_history())


@pytest.fixture
def loop_factory(monkeypatch):
    created = []

    def make(root, cfg=None):
        from opencode_py.agent.loop import AgentLoop
        from opencode_py.tools import build_registry

        cfg = cfg or Config()
        lp = AgentLoop(cfg=cfg, registry=build_registry(cfg), directory=root,
                       provider=None, agent="build")
        monkeypatch.setattr(lp, "worktree", root, raising=False)
        created.append(lp)
        return lp

    yield make


def _touch(project, content="VALUE = 2\n"):
    """Write pkg/mod.py through the real write path, so verify.track sees it."""
    from opencode_py.tools import write as write_mod
    from opencode_py.tools.verify import mark_edits

    before = mark_edits()
    # force=True: `write` refuses to overwrite different content by design, and
    # an edit is exactly that.
    out = write_mod._write(str(project / "pkg" / "mod.py"), content, force=True)
    assert not out.get("error"), out
    return before


def test_red_run_reaches_the_transcript(project, loop_factory):
    loop = loop_factory(project)
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    text = _history_text(loop)
    assert "[autotest]" in text
    assert "failed" in text
    assert "test_mod.py::test_value" in text
    assert loop._at_failed == 1


def test_green_run_is_one_quiet_line(passing_project, loop_factory):
    loop = loop_factory(passing_project)
    before = _touch(passing_project, "VALUE = 5\n")
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    text = _history_text(loop)
    assert "[autotest]" in text and "passed" in text and "failed" not in text
    assert loop._at_failed == 0
    # The closure cache is only filled when the symbol index is warm; without
    # one, an empty snapshot would claim "nothing affects this test".
    assert isinstance(loop._at_green, dict)


def test_disabled_config_runs_nothing(project, loop_factory):
    loop = loop_factory(project, Config(autotest=False))
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    assert "[autotest]" not in _history_text(loop)


def test_read_only_agent_runs_nothing(project, loop_factory):
    loop = loop_factory(project)
    loop.agent = "plan"
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    assert "[autotest]" not in _history_text(loop)


def test_bash_that_already_ran_tests_suppresses_the_hook(project, loop_factory):
    loop = loop_factory(project)
    before = _touch(project)
    loop._autotest_after_step(
        before, [("c1", "bash", {"command": "python -m pytest tests/ -q"})])
    assert "[autotest]" not in _history_text(loop)


def test_task_step_suppresses_the_hook(project, loop_factory):
    loop = loop_factory(project)
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "task", {"prompt": "x"})])
    assert "[autotest]" not in _history_text(loop)


def test_permission_ask_means_no_hidden_run(project, loop_factory):
    loop = loop_factory(project)
    observed = []
    loop.permission.explain = lambda perm, cmd="": (observed.append(cmd), ("ask", "ask", None))[1]
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    assert observed, "permission was never consulted"
    assert "[autotest]" not in _history_text(loop)


def test_no_edit_means_no_run(project, loop_factory):
    loop = loop_factory(project)
    loop._autotest_after_step(0, [("c1", "read", {"filePath": "pkg/mod.py"})])
    assert "[autotest]" not in _history_text(loop)


def test_attempt_cap_ends_with_an_honest_message(project, loop_factory):
    loop = loop_factory(project, Config(autotest_max_attempts=1))
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    text = _history_text(loop)
    assert "stopped after 1 fix attempts" in text
    assert loop._at_failed == 0, "budget spent must release the turn"


def test_gate_blocks_a_done_claim_while_red(project, loop_factory):
    loop = loop_factory(project)
    loop._at_failed = 2
    assert loop._autotest_gate() is True
    assert "still failing" in _history_text(loop)
    loop._at_failed = 0
    assert loop._autotest_gate() is False


def test_gate_is_silent_when_the_budget_is_spent(project, loop_factory):
    loop = loop_factory(project, Config(autotest_max_attempts=1))
    loop._at_failed = 1
    loop._at_attempts = 1
    assert loop._autotest_gate() is False


def test_gate_stops_nudging(project, loop_factory):
    loop = loop_factory(project)
    loop._at_failed = 1
    assert loop._autotest_gate() is True
    assert loop._autotest_gate() is True
    assert loop._autotest_gate() is False


def test_reset_clears_turn_state(project, loop_factory):
    loop = loop_factory(project)
    loop._at_failed = 5
    loop._at_attempts = 2
    loop._at_nudges = 1
    loop._at_green = {"x": {"y"}}
    loop._autotest_reset()
    assert (loop._at_failed, loop._at_attempts, loop._at_nudges, loop._at_green) == (0, 0, 0, {})


# --- end to end through the step loop ----------------------------------------


class _FakeRotation:
    """Replays one scripted provider step per call (the loop's `stream` contract)."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def stream(self, messages, tools, on_event, on_notice=None, **kwargs):
        idx = min(self.calls, len(self.script) - 1)
        self.calls += 1
        self.script[idx](on_event)
        return "opencode", "test-model"


def _run_turn(project, monkeypatch, script, cfg=None):
    from opencode_py.agent import loop as loop_mod
    from opencode_py.tools import build_registry

    cfg = cfg or Config()
    cfg.provider = "opencode"
    cfg.model = "test-model"
    loop = loop_mod.AgentLoop(cfg=cfg, registry=build_registry(cfg), directory=project,
                              provider=_FakeRotation(script), agent="build")
    monkeypatch.setattr(loop, "worktree", project, raising=False)
    return loop, loop.run_turn("make the change")


def _text(loop) -> str:
    return "\n".join(str(m.get("content") or "") for m in loop.get_history())


def test_step_loop_tests_the_edit_and_blocks_a_false_done(project, monkeypatch):
    """The whole point: the model writes, breaks a test, says "done", and the
    loop refuses to end until it deals with it."""
    import json

    from opencode_py.agent import loop as loop_mod
    from opencode_py.providers.base import ProviderEvent, ToolCall

    tc = ToolCall(id="c1", name="write", arguments=json.dumps(
        {"filePath": "pkg/mod.py", "content": "VALUE = 2\n", "force": True}))
    script = [
        lambda on: on(ProviderEvent(kind="tool_call", tool_calls=[tc])),
        lambda on: on(ProviderEvent(kind="text_delta", text="done!")),
        lambda on: on(ProviderEvent(kind="text_delta", text="still working")),
        lambda on: on(ProviderEvent(kind="text_delta", text="done for real")),
    ]
    loop, result = _run_turn(project, monkeypatch, script)
    text = _text(loop)
    assert "[autotest]" in text, "the hook never reached the transcript"
    assert "failed" in text
    assert loop_mod.AUTOTEST_NUDGE_MSG in text, "the false 'done' was not challenged"
    assert result.text


def test_step_loop_lets_a_green_run_finish_normally(passing_project, monkeypatch):
    import json

    from opencode_py.agent import loop as loop_mod
    from opencode_py.providers.base import ProviderEvent, ToolCall

    tc = ToolCall(id="c1", name="write", arguments=json.dumps(
        {"filePath": "pkg/mod.py", "content": "VALUE = 5\n", "force": True}))
    script = [
        lambda on: on(ProviderEvent(kind="tool_call", tool_calls=[tc])),
        lambda on: on(ProviderEvent(kind="text_delta", text="done")),
    ]
    loop, result = _run_turn(passing_project, monkeypatch, script)
    text = _text(loop)
    assert "passed" in text and "[autotest]" in text
    assert loop_mod.AUTOTEST_NUDGE_MSG not in text
    assert result.text == "done"


def test_step_loop_stays_silent_when_no_test_covers_the_edit(project, monkeypatch):
    """A new module nothing imports must not trigger a run (or a message)."""
    import json

    from opencode_py.providers.base import ProviderEvent, ToolCall

    tc = ToolCall(id="c1", name="write", arguments=json.dumps(
        {"filePath": "pkg/brand_new.py", "content": "Z = 9\n"}))
    script = [
        lambda on: on(ProviderEvent(kind="tool_call", tool_calls=[tc])),
        lambda on: on(ProviderEvent(kind="text_delta", text="done")),
    ]
    loop, result = _run_turn(project, monkeypatch, script)
    assert "[autotest]" not in _text(loop)
    assert result.text == "done"


def test_a_timeout_is_never_reported_as_green(project, loop_factory, monkeypatch):
    """exit != 0 with no parsed failures must read as "couldn't run", not as
    "0 passed" — the false-green path."""
    loop = loop_factory(project)
    monkeypatch.setattr(A, "run_tests", lambda *a, **k: {
        "ok": False, "passed": 0, "failed": 0, "errors": 0, "total": 0,
        "seconds": 0.0, "exit_code": -9, "error": True,
        "output": "timed out after 120s", "failed_ids": [],
    })
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    text = _history_text(loop)
    assert "could not be run" in text
    assert "passed" not in text
    assert loop._at_failed == 0 and loop._at_attempts == 0, "must not count as a fix attempt"
    assert loop._at_broken is True
    assert loop._autotest_gate() is False


def test_broken_runner_is_not_retried_every_step(project, loop_factory, monkeypatch):
    loop = loop_factory(project)
    calls = []
    monkeypatch.setattr(A, "run_tests", lambda *a, **k: calls.append(1) or {
        "ok": False, "passed": 0, "failed": 0, "errors": 0, "total": 0,
        "seconds": 0.0, "exit_code": -9, "error": True, "output": "boom",
        "failed_ids": [],
    })
    before = _touch(project)
    loop._autotest_after_step(before, [("c1", "write", {"filePath": "pkg/mod.py"})])
    before = _touch(project, "VALUE = 3\n")
    loop._autotest_after_step(before, [("c2", "write", {"filePath": "pkg/mod.py"})])
    assert len(calls) == 1, "a broken runner must not be retried all turn"


def test_editing_the_same_file_again_counts_as_new_work(project, loop_factory, monkeypatch):
    """Fixing a failure means writing the SAME file a second time. A set
    difference reports "nothing changed" there and the retry never gets tested."""
    loop = loop_factory(project)
    calls = []
    monkeypatch.setattr(A, "run_tests", lambda *a, **k: calls.append(1) or {
        "ok": True, "passed": 1, "failed": 0, "errors": 0, "total": 1,
        "seconds": 0.1, "exit_code": 0, "error": False, "output": "",
        "failed_ids": [],
    })
    first = _touch(project, "VALUE = 2\n")
    loop._autotest_after_step(first, [("c1", "write", {"filePath": "pkg/mod.py"})])
    second = _touch(project, "VALUE = 1\n")
    loop._autotest_after_step(second, [("c2", "write", {"filePath": "pkg/mod.py"})])
    assert len(calls) == 2
