from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Any

from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.core.security.panic_mode import PanicAction, PanicMode, PanicModeConfig
from src.core.security.security_profiles import SecurityProfileManager
from src.core.security.tray_service import TrayService, TrayState
from src.core.security.session_recovery import (
    SessionRecoveryManager,
    VaultSessionState,
    WindowState,
)


@dataclass
class Sprint7SecurityStatus:
    auto_lock_enabled: bool
    auto_lock_timeout_seconds: int
    tray_running: bool
    panic_hotkey: str
    security_profile: str
    vault_locked: bool


class Sprint7SecurityIntegration:
    def __init__(
        self,
        lock_vault: Callable[[], None],
        unlock_vault: Callable[[], None] | None = None,
        clear_clipboard: Callable[[], None] | None = None,
        wipe_memory: Callable[[], None] | None = None,
        close_sensitive_windows: Callable[[], None] | None = None,
        show_main_window: Callable[[], None] | None = None,
        open_settings: Callable[[], None] | None = None,
        exit_application: Callable[[], None] | None = None,
        quick_search: Callable[[str], list[dict]] | None = None,
        audit_log: Callable[[str, dict], None] | None = None,
        auto_lock_timeout_seconds: int = 300,
    ):
        self._vault_locked = True
        self._audit_log = audit_log

        self.profile_manager = SecurityProfileManager()
        self.session_recovery = SessionRecoveryManager(
            audit_log=audit_log,
        )

        self.activity_monitor = ActivityMonitor(
            lock_callback=self.lock_due_to_inactivity,
            config=AutoLockConfig(timeout_seconds=auto_lock_timeout_seconds),
        )

        self.panic_mode = PanicMode(
            config=PanicModeConfig(
                enabled_actions=[
                    PanicAction.LOCK_VAULT,
                    PanicAction.CLEAR_CLIPBOARD,
                    PanicAction.WIPE_MEMORY,
                    PanicAction.CLOSE_WINDOWS,
                ]
            ),
            lock_vault=lock_vault,
            clear_clipboard=clear_clipboard,
            wipe_memory=wipe_memory,
            close_windows=close_sensitive_windows,
            exit_application=exit_application,
            audit_log=audit_log,
        )

        self.tray_service = TrayService(
            lock_vault=lock_vault,
            unlock_vault=unlock_vault,
            show_main_window=show_main_window,
            quick_search=quick_search,
            clear_clipboard=clear_clipboard,
            activate_panic=lambda: self.activate_panic("tray_menu"),
            open_settings=open_settings,
            exit_application=exit_application,
        )

        self.lock_vault_callback = lock_vault
        self.unlock_vault_callback = unlock_vault

    def start(self) -> None:
        self.tray_service.start()
        self.activity_monitor.start()
        self._audit("sprint7_security_started", {"component": "gui_integration"})

    def stop(self) -> None:
        self.activity_monitor.stop()
        self.tray_service.stop()
        self._audit("sprint7_security_stopped", {"component": "gui_integration"})

    def mark_unlocked(self) -> None:
        self._vault_locked = False
        self.activity_monitor.resume_after_unlock()
        self.tray_service.set_state(TrayState.UNLOCKED)
        self._audit("vault_state_changed", {"locked": False})

    def mark_locked(self) -> None:
        self._vault_locked = True
        self.tray_service.set_state(TrayState.LOCKED)
        self._audit("vault_state_changed", {"locked": True})

    def record_user_activity(self, source: str = "gui") -> None:
        if not self._vault_locked:
            self.activity_monitor.record_activity(source)

    def record_keyboard_activity(self) -> None:
        self.record_user_activity("keyboard")

    def record_mouse_activity(self) -> None:
        self.record_user_activity("mouse")

    def record_focus_change(self) -> None:
        self.activity_monitor.record_focus_change()

    def lock_due_to_inactivity(self) -> None:
        if self._vault_locked:
            return

        self.lock_vault_callback()
        self.mark_locked()
        self._audit(
            "auto_lock_triggered",
            {
                "reason": "inactivity",
                "timeout_seconds": self.activity_monitor.config.timeout_seconds,
            },
        )

    def activate_panic(self, trigger: str = "hotkey"):
        event = self.panic_mode.activate(trigger=trigger)
        self.mark_locked()
        self.tray_service.notify_security_event("Panic mode activated")
        return event

    def handle_hotkey(self, hotkey: str):
        normalized = hotkey.strip().lower()

        if normalized in {"ctrl+shift+esc", "<control-shift-escape>", "panic"}:
            return self.activate_panic("hotkey")

        return None

    def minimize_to_tray(self) -> None:
        self.tray_service.minimize_to_tray()
        self._audit("window_minimized_to_tray", {})

    def restore_from_tray(self) -> None:
        self.tray_service.restore_from_tray()
        self._audit("window_restored_from_tray", {})

    def apply_security_profile(self, profile_name: str):
        profile = self.profile_manager.apply_profile(profile_name)

        self.activity_monitor.config.timeout_seconds = profile.auto_lock_timeout_seconds
        self.tray_service.set_clipboard_active(False)

        if profile.start_minimized_to_tray:
            self.minimize_to_tray()

        self._audit(
            "security_profile_applied",
            {
                "profile": profile.name.value,
                "auto_lock_timeout_seconds": profile.auto_lock_timeout_seconds,
            },
        )

        return profile

    def set_clipboard_active(self, active: bool) -> None:
        self.tray_service.set_clipboard_active(active)

    def status(self) -> Sprint7SecurityStatus:
        return Sprint7SecurityStatus(
            auto_lock_enabled=self.activity_monitor.config.enabled,
            auto_lock_timeout_seconds=self.activity_monitor.config.timeout_seconds,
            tray_running=self.tray_service.is_running(),
            panic_hotkey=self.panic_mode.config.hotkey,
            security_profile=self.profile_manager.current_profile.name.value,
            vault_locked=self._vault_locked,
        )

    def _audit(self, event_type: str, details: dict[str, Any]) -> None:
        if self._audit_log is None:
            return

        self._audit_log(event_type, details)
    def create_session_snapshot(
        self,
        selected_entry_ids: list[int] | None = None,
        search_query: str = "",
        table_scroll_position: float = 0.0,
        password_visibility_enabled: bool = False,
        window_geometry: str = "",
        window_visible: bool = True,
    ):
        state = VaultSessionState(
            selected_entry_ids=selected_entry_ids or [],
            search_query=search_query,
            table_scroll_position=table_scroll_position,
            password_visibility_enabled=password_visibility_enabled,
            active_security_profile=self.profile_manager.current_profile.name.value,
            window_state=WindowState(
                geometry=window_geometry,
                is_visible=window_visible,
                minimized_to_tray=self.tray_service.status.minimized_to_tray,
            ),
        )

        return self.session_recovery.create_snapshot(state)

    def resume_from_lock(self, master_password_verified: bool):
        restored = self.session_recovery.restore_snapshot(
            master_password_verified=master_password_verified,
        )
        self.activity_monitor.resume_after_unlock()
        self.mark_unlocked()
        return restored

    def recover_from_panic(self, master_password_verified: bool):
        restored = self.session_recovery.restore_snapshot(
            master_password_verified=master_password_verified,
        )
        self.panic_mode.recover(master_password_verified)
        self.mark_unlocked()
        self._audit(
            "panic_recovery_completed",
            {
                "restored_search_query": restored.search_query,
                "selected_count": len(restored.selected_entry_ids),
            },
        )
        return restored

    def minimize_to_tray_with_snapshot(
        self,
        selected_entry_ids: list[int] | None = None,
        search_query: str = "",
        table_scroll_position: float = 0.0,
        password_visibility_enabled: bool = False,
        window_geometry: str = "",
    ):
        snapshot = self.create_session_snapshot(
            selected_entry_ids=selected_entry_ids,
            search_query=search_query,
            table_scroll_position=table_scroll_position,
            password_visibility_enabled=password_visibility_enabled,
            window_geometry=window_geometry,
            window_visible=False,
        )
        self.minimize_to_tray()
        return snapshot

    def restore_from_tray_with_state(self, master_password_verified: bool):
        restored = self.session_recovery.restore_snapshot(master_password_verified)
        self.restore_from_tray()
        return restored