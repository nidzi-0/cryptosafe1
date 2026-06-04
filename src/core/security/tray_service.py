from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class TrayState(str, Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    WARNING = "warning"
    BUSY = "busy"


@dataclass
class TrayMenuItem:
    label: str
    action: str
    enabled: bool = True
    shortcut: str = ""


@dataclass
class TrayIconState:
    color: str
    animated: bool
    frame: int = 0


@dataclass
class TrayStatus:
    state: TrayState = TrayState.LOCKED
    tooltip: str = "CryptoSafe Manager locked"
    clipboard_active: bool = False
    background_running: bool = False
    minimized_to_tray: bool = False
    notifications: list[str] = field(default_factory=list)
    icon: TrayIconState = field(
        default_factory=lambda: TrayIconState(color="red", animated=False)
    )


class TrayService:

    def __init__(
        self,
        lock_vault: Callable[[], None] | None = None,
        unlock_vault: Callable[[], None] | None = None,
        show_main_window: Callable[[], None] | None = None,
        quick_search: Callable[[str], list[dict]] | None = None,
        clear_clipboard: Callable[[], None] | None = None,
        activate_panic: Callable[[], None] | None = None,
        open_settings: Callable[[], None] | None = None,
        exit_application: Callable[[], None] | None = None,
    ):
        self.lock_vault = lock_vault
        self.unlock_vault = unlock_vault
        self.show_main_window = show_main_window
        self.quick_search = quick_search
        self.clear_clipboard = clear_clipboard
        self.activate_panic = activate_panic
        self.open_settings = open_settings
        self.exit_application = exit_application

        self.status = TrayStatus()
        self._lock = threading.RLock()
        self._running = False
        self._frames = itertools.cycle(range(4))

    def start(self) -> None:
        with self._lock:
            self._running = True
            self.status.background_running = True

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self.status.background_running = False
            self.status.icon.animated = False

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def set_state(self, state: TrayState) -> None:
        with self._lock:
            self.status.state = state
            self.status.tooltip = self._tooltip_for_state(state)
            self.status.icon = self._icon_for_state(state)

    def _icon_for_state(self, state: TrayState) -> TrayIconState:
        if state == TrayState.LOCKED:
            return TrayIconState(color="red", animated=False)
        if state == TrayState.UNLOCKED:
            return TrayIconState(color="green", animated=False)
        if state == TrayState.WARNING:
            return TrayIconState(color="yellow", animated=False)
        if state == TrayState.BUSY:
            return TrayIconState(color="blue", animated=True, frame=next(self._frames))
        return TrayIconState(color="gray", animated=False)

    def animate_crypto_operation(self) -> TrayIconState:
        with self._lock:
            self.status.state = TrayState.BUSY
            self.status.tooltip = self._tooltip_for_state(TrayState.BUSY)
            self.status.icon = TrayIconState(
                color="blue",
                animated=True,
                frame=next(self._frames),
            )
            return self.status.icon

    def set_clipboard_active(self, active: bool) -> None:
        with self._lock:
            self.status.clipboard_active = active

    def minimize_to_tray(self) -> None:
        with self._lock:
            self.status.minimized_to_tray = True

    def restore_from_tray(self) -> None:
        with self._lock:
            self.status.minimized_to_tray = False

        if self.show_main_window is not None:
            self.show_main_window()

    def notify_security_event(self, message: str) -> None:
        with self._lock:
            self.status.notifications.append(message)

    def build_menu(self) -> list[TrayMenuItem]:
        with self._lock:
            is_locked = self.status.state == TrayState.LOCKED
            clipboard_active = self.status.clipboard_active

        return [
            TrayMenuItem("Unlock vault" if is_locked else "Lock vault", "unlock" if is_locked else "lock"),
            TrayMenuItem("Show main window", "show"),
            TrayMenuItem("Quick search", "quick_search", enabled=not is_locked),
            TrayMenuItem("Clear clipboard", "clear_clipboard", enabled=clipboard_active),
            TrayMenuItem("Panic mode", "panic", shortcut="Ctrl+Shift+Esc"),
            TrayMenuItem("Settings", "settings"),
            TrayMenuItem("Exit", "exit"),
        ]

    def execute_menu_action(self, action: str, query: str = ""):
        if action == "lock":
            if self.lock_vault is not None:
                self.lock_vault()
            self.set_state(TrayState.LOCKED)
            return None

        if action == "unlock":
            if self.unlock_vault is not None:
                self.unlock_vault()
            self.set_state(TrayState.UNLOCKED)
            return None

        if action == "show":
            self.restore_from_tray()
            return None

        if action == "quick_search":
            if self.status.state == TrayState.LOCKED:
                return []
            if self.quick_search is None:
                return []
            return self.quick_search(query)

        if action == "clear_clipboard":
            if self.clear_clipboard is not None:
                self.clear_clipboard()
            self.set_clipboard_active(False)
            return None

        if action == "panic":
            if self.activate_panic is not None:
                self.activate_panic()
            self.set_state(TrayState.LOCKED)
            return None

        if action == "settings":
            if self.open_settings is not None:
                self.open_settings()
            return None

        if action == "exit":
            self.stop()
            if self.exit_application is not None:
                self.exit_application()
            return None

        raise ValueError(f"Unknown tray action: {action}")

    def operation_started(self) -> None:
        self.animate_crypto_operation()

    def operation_finished(self, locked: bool = False) -> None:
        self.set_state(TrayState.LOCKED if locked else TrayState.UNLOCKED)

    def _tooltip_for_state(self, state: TrayState) -> str:
        if state == TrayState.LOCKED:
            return "CryptoSafe Manager locked"
        if state == TrayState.UNLOCKED:
            return "CryptoSafe Manager unlocked"
        if state == TrayState.WARNING:
            return "CryptoSafe Manager security warning"
        if state == TrayState.BUSY:
            return "CryptoSafe Manager working"
        return "CryptoSafe Manager"