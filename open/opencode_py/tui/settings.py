"""Settings, model and provider selection for the Textual TUI.

Split out of :mod:`opencode_py.tui.app` as a mixin; method bodies are unchanged.
"""
from __future__ import annotations

from ..util.log import swallow
from typing import Any
from .input_bar import InputBar, RotationLockToggled

class SettingsMixin:

    def action_settings(self) -> None:
        from .settings_screen import SettingsScreen

        self.push_screen(
            SettingsScreen(
                cfg=self.cfg,
                engine=self.engine,
                directory=self.directory,
                auth=self.auth,
                session=self.session,
                on_model_change=self._set_model,
                on_apply=self._apply_runtime_settings,
            ),
            self._on_settings_done,
        )


    def _open_permissions(self) -> None:
        """Effective permission rules: read them, and edit your own."""
        from .permissions_popup import PermissionsPopup

        engine = self._active_engine()
        # cfg is the persisted source of truth and is read FIRST. Reading the
        # engine first meant a user who saved "fully_auto" still saw "auto"
        # whenever the engine had not been stamped from cfg yet, because the
        # engine's own default is truthy and shadowed the saved value.
        mode = str(getattr(self.cfg, "permission_mode", "auto")
                   or getattr(getattr(engine, "permission", None), "mode", "auto"))
        agent = str(getattr(engine, "agent", None)
                    or getattr(self.cfg, "default_agent", "build"))
        self.push_screen(
            PermissionsPopup(
                mode=mode,
                agent=agent,
                user_permission=getattr(self.cfg, "permission", None) or {},
                cfg=self.cfg,
                engine=engine,
                on_rule_change=self._apply_permission_rule,
                on_mode_change=self._apply_permission_mode,
                on_clear_approved=self._clear_permission_approvals,
            ),
            None,
        )

    def _live_engines(self) -> list[Any]:
        """Every live engine (all sessions plus the main one), de-duplicated."""
        return list(dict.fromkeys(
            [e for e in self._engines.values() if e is not None]
            + ([self._main_engine] if self._main_engine is not None else [])
        ))

    def _persist_permission(self) -> str | None:
        """Write the user's permission rules + mode back to opencode.json.

        LOUD, like _persist_agents: returns an error string when the save
        fails OR the read-back disagrees, so no caller ever claims a save it
        cannot prove. merge_disk_agents=False, because saving rules must not
        resurrect an agent the user deleted.
        """
        from ..config import load_config, save_config

        try:
            raw = dict(getattr(self.cfg, "raw", None) or {})
            raw["permission"] = dict(getattr(self.cfg, "permission", None) or {})
            raw["permission_mode"] = str(
                getattr(self.cfg, "permission_mode", "auto") or "auto")
            self.cfg.raw = raw
            save_config(self.cfg, merge_disk_agents=False)
        except Exception as e:
            return f"Save failed: {e}"
        try:
            fresh = load_config()
        except Exception as e:
            return f"Save unverified: {e}"
        want = getattr(self.cfg, "permission", None) or {}
        have = getattr(fresh, "permission", None) or {}
        if have != want:
            return "Save unverified: permission rules differ on disk"
        return None

    def _apply_permission_rule(
        self, tool: str, pattern: str, action: str | None,
    ) -> None:
        """Set or clear ONE of the user's own rules, then persist and re-stamp.

        Editing a single pattern of a dict-valued tool merges just that key, so
        the tool's sibling patterns (e.g. read's *.env) survive untouched.
        """
        from ..permission import VALID_ACTIONS

        previous = dict(getattr(self.cfg, "permission", None) or {})
        perm = dict(previous)
        current = perm.get(tool)
        if action is None:
            if isinstance(current, dict):
                cur = dict(current)
                cur.pop(pattern, None)
                if cur:
                    perm[tool] = cur
                else:
                    perm.pop(tool, None)
            else:
                perm.pop(tool, None)
        else:
            value = str(action).lower()
            if value not in VALID_ACTIONS:
                self.notify(f"Unknown action {action!r}", severity="error")
                return
            if isinstance(current, dict):
                cur = dict(current)
                cur[pattern] = value
                perm[tool] = cur
            elif pattern == "*":
                perm[tool] = value
            else:
                # a bare scalar (or nothing) needs the "*" key before a
                # pattern can join it; merge_permissions merges the dict over
                # the agent default rather than replacing it
                base: dict[str, Any] = {"*": current} if isinstance(current, str) else {}
                base[pattern] = value
                perm[tool] = base
        self.cfg.permission = perm
        err = self._persist_permission()
        if err:
            # roll back: the popup re-reads cfg after every edit, so leaving a
            # failed save in memory would show a rule that is neither enforced
            # nor on disk
            self.cfg.permission = previous
            self.notify(err, severity="error")
            return
        self._rebuild_permission_engines()

    def _apply_permission_mode(self, mode: str) -> None:
        """Persist a new mode. No engine rebuild: stamping mode in place keeps
        every "always allow" and the doom-loop window intact."""
        value = str(mode or "auto").lower()
        if value not in ("auto", "ask", "deny", "fully_auto"):
            return
        previous = str(getattr(self.cfg, "permission_mode", "auto") or "auto")
        self.cfg.permission_mode = value
        err = self._persist_permission()
        if err:
            self.cfg.permission_mode = previous
            self.notify(err, severity="error")
            return
        # also re-syncs the question tool for fully_auto (zero popups)
        self._apply_runtime_settings()

    def _rebuild_permission_engines(self) -> None:
        """Re-derive every live engine's rules from cfg, carrying its ledgers.

        Without adopt_from a fresh engine would start with no approvals, and a
        rule edit would silently revoke the exemptions the user granted.
        """
        from ..permission import PermissionEngine, merge_permissions

        for engine in self._live_engines():
            old = getattr(engine, "permission", None)
            if old is None:
                continue
            try:
                eng_agent = str(getattr(engine, "agent", None)
                                or getattr(self.cfg, "default_agent", "build"))
                fresh = PermissionEngine.from_config(
                    merge_permissions(
                        getattr(self.cfg, "permission", None) or {}, eng_agent, self.cfg),
                    mode=str(getattr(self.cfg, "permission_mode", "auto") or "auto"),
                )
                fresh.adopt_from(old)
                fresh.ask_callback = old.ask_callback
                engine.permission = fresh
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/settings.py:_rebuild_permission_engines")

    def _clear_permission_approvals(self, pattern: str | None) -> None:
        """Revoke always-allow exemptions. Session state, never persisted."""
        cleared = 0
        for engine in self._live_engines():
            clear = getattr(getattr(engine, "permission", None), "clear_approved", None)
            if clear is None:
                continue
            try:
                cleared += clear(pattern)
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/settings.py:_clear_permission_approvals")
        if pattern:
            self.notify(f"Revoked: {pattern}" if cleared else "Already revoked")
        else:
            self.notify(f"Revoked {cleared} always-allow "
                        f"entr{'y' if cleared == 1 else 'ies'}")


    def _apply_runtime_settings(self) -> None:
        """Push startup-captured settings into the LIVE components.

        Before this, a Settings change only touched the config FILE: every
        live engine kept its construction-time provider/model/agent snapshot,
        so old/resumed sessions answered with the OLD model until restart.
        Now model/provider/agent/rotation-lane-0 follow the new pick on the
        very next turn — for every live engine AND every resumed session.
        The bash tool snapshots max_lines/max_bytes/timeout when its registry
        is built, and each rotation lane bakes its httpx timeout into the
        provider instance — both are refreshed here too."""
        from ..tools import bash as bash_mod

        engines = list(dict.fromkeys(
            [e for e in self._engines.values() if e is not None]
            + ([self._main_engine] if self._main_engine is not None else [])
        ))
        new_provider = str(getattr(self.cfg, "provider", "") or "")
        new_model = str(getattr(self.cfg, "model", "") or "")
        new_agent = str(getattr(self.cfg, "default_agent", "") or "")
        mode = getattr(self.cfg, "permission_mode", "auto")
        for engine in engines:
            perm = getattr(engine, "permission", None)
            if perm is not None and hasattr(perm, "mode"):
                try:
                    raw = str(mode or "auto").lower()
                    perm.mode = raw if raw in ("ask", "deny", "fully_auto") else "auto"
                except Exception as _oc_exc:
                    swallow(_oc_exc, "tui/settings.py:75")
                    pass
            # keep the question tool in sync: entering fully_auto installs the
            # auto-answer hook, leaving it restores the dialog bridge.
            try:
                reg = getattr(engine, "registry", None)
                qs = getattr(engine, "question_service", None)
                if reg is not None and qs is not None:
                    if getattr(perm, "mode", "") == "fully_auto":
                        def _fully_auto_ask(questions: list) -> list[list[str]]:
                            out: list[list[str]] = []
                            for q in questions:
                                opts = getattr(q, "options", None) or []
                                first = getattr(opts[0], "label", "") if opts else ""
                                out.append([first] if first else [])
                            return out
                        reg.question_asker = _fully_auto_ask
                    else:
                        reg.question_asker = qs.ask
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/settings.py:94")
                pass
        for engine in engines:
            # model/provider/agent follow the new pick NOW, not on restart.
            # The engine streams with its own snapshot (provider_id/model_id/
            # agent), so without this old sessions answer with the OLD model
            # forever. Rotation lanes rebuild from cfg at next-turn start and
            # put the new pick at lane 0.
            try:
                if new_provider:
                    engine.provider_id = new_provider
                if new_model:
                    engine.model_id = new_model
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/settings.py:107")
                pass
            try:
                sess_id = getattr(engine, "session_id", "") or ""
                sess = self._sessions.get(sess_id)
                if sess is not None:
                    if new_provider:
                        sess.provider = new_provider
                    if new_model:
                        sess.model = new_model
                    if new_agent and not getattr(sess, "parent_id", None):
                        sess.agent = new_agent
                        engine.agent = new_agent
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/settings.py:120")
                pass
            reg = getattr(engine, "registry", None)
            if reg is not None and hasattr(reg, "register"):
                try:
                    reg.register(
                        bash_mod.tool(
                            max_lines=self.cfg.tool_output_max_lines,
                            max_bytes=self.cfg.tool_output_max_bytes,
                            default_timeout=self.cfg.bash_default_timeout,
                            registry=reg,
                        )
                    )
                except Exception as _oc_exc:
                    swallow(_oc_exc, "tui/settings.py:133")
                    pass
            try:
                engine.mark_rotation_dirty()
            except Exception as _oc_exc:
                swallow(_oc_exc, "tui/settings.py:137")
                pass
        try:
            self._update_header()
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/settings.py:141")
            pass
        self.notify("Settings applied.")


    def _on_settings_done(self, result: Any) -> None:
        self.query_one(InputBar).focus()




    def _set_model(self, model: str) -> None:
        self.cfg.model = model
        # new pick follows everywhere NOW: every live engine + its session
        # record, so the next turn in ANY session (old or new) uses it.
        try:
            for engine in list(dict.fromkeys(
                [e for e in self._engines.values() if e is not None]
                + ([self._main_engine] if self._main_engine is not None else [])
            )):
                try:
                    engine.model_id = model
                    engine.mark_rotation_dirty()
                except Exception as _oc_exc:
                    swallow(_oc_exc, "tui/settings.py:164")
                    pass
                try:
                    sess_id = getattr(engine, "session_id", "") or ""
                    sess = self._sessions.get(sess_id)
                    if sess is not None:
                        sess.model = model
                except Exception as _oc_exc:
                    swallow(_oc_exc, "tui/settings.py:171")
                    pass
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/settings.py:173")
            pass
        self.notify(f"Model set to opencode/{model}")
        self._update_header()


    def on_rotation_lock_toggled(self, event: RotationLockToggled) -> None:
        """Clicking the model dot in the meta row pins/unpins the selected model."""
        engine = self._active_engine()
        engine.rotation_locked = not engine.rotation_locked
        self.cfg.rotation_lock = engine.rotation_locked
        if engine.rotation_locked:
            self.notify(
                f"Rotation locked — staying on {engine.model_id} "
                "(rate limits/hard errors will surface, not switch)"
            )
        else:
            self.notify("Rotation unlocked — will fail over to backup lanes on errors")
        try:
            from ..config import save_config

            save_config(self.cfg)
        except Exception as _oc_exc:
            swallow(_oc_exc, "tui/settings.py:195")
            pass
        self._update_header()
