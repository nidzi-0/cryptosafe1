from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable


class PanicAction(str, Enum):
    LOCK_VAULT = "lock_vault"
    CLEAR_CLIPBOARD = "clear_clipboard"
    WIPE_MEMORY = "wipe_memory"
    CLOSE_WINDOWS = "close_windows"
    EXIT_APPLICATION = "exit_application"
    FAKE_ERROR = "fake_error"


@dataclass
class PanicModeConfig:
    hotkey: str = "Ctrl+Shift+Esc"
    close_application: bool = False
    stealth_mode: bool = False
    fake_error_message: str = "Application error. Please restart CryptoSafe Manager."
    enabled_actions: list[PanicAction] = field(
        default_factory=lambda: [
            PanicAction.LOCK_VAULT,
            PanicAction.CLEAR_CLIPBOARD,
            PanicAction.WIPE_MEMORY,
            PanicAction.CLOSE_WINDOWS,
        ]
    )


@dataclass
class PanicEvent:
    activated_at: str
    trigger: str
    actions_executed: list[str]
    success: bool
    error: str = ""


class PanicMode:
    def __init__(
        self,
        config: PanicModeConfig | None = None,
        lock_vault: Callable[[], None] | None = None,
        clear_clipboard: Callable[[], None] | None = None,
        wipe_memory: Callable[[], None] | None = None,
        close_windows: Callable[[], None] | None = None,
        exit_application: Callable[[], None] | None = None,
        show_fake_error: Callable[[str], None] | None = None,
        audit_log: Callable[[str, dict], None] | None = None,
    ):
        self.config = config or PanicModeConfig()
        self.lock_vault = lock_vault
        self.clear_clipboard = clear_clipboard
        self.wipe_memory = wipe_memory
        self.close_windows = close_windows
        self.exit_application = exit_application
        self.show_fake_error = show_fake_error
        self.audit_log = audit_log
        self.last_event: PanicEvent | None = None

    def activate(self, trigger: str = "manual") -> PanicEvent:
        actions_executed: list[str] = []

        try:
            for action in self.config.enabled_actions:
                self._execute_action(action)
                actions_executed.append(action.value)

            if self.config.stealth_mode and self.show_fake_error is not None:
                self.show_fake_error(self.config.fake_error_message)
                actions_executed.append(PanicAction.FAKE_ERROR.value)

            if self.config.close_application and self.exit_application is not None:
                self.exit_application()
                actions_executed.append(PanicAction.EXIT_APPLICATION.value)

            event = PanicEvent(
                activated_at=self._now(),
                trigger=trigger,
                actions_executed=actions_executed,
                success=True,
            )

            self._audit(event)
            self.last_event = event
            return event

        except Exception as exc:
            event = PanicEvent(
                activated_at=self._now(),
                trigger=trigger,
                actions_executed=actions_executed,
                success=False,
                error=str(exc),
            )
            self._audit(event)
            self.last_event = event
            return event

    def recover(self, master_password_verified: bool) -> bool:
        """
        Recovery is allowed only after master password verification.
        """
        return bool(master_password_verified)

    def _execute_action(self, action: PanicAction) -> None:
        callbacks = {
            PanicAction.LOCK_VAULT: self.lock_vault,
            PanicAction.CLEAR_CLIPBOARD: self.clear_clipboard,
            PanicAction.WIPE_MEMORY: self.wipe_memory,
            PanicAction.CLOSE_WINDOWS: self.close_windows,
        }

        callback = callbacks.get(action)
        if callback is not None:
            callback()

    def _audit(self, event: PanicEvent) -> None:
        if self.audit_log is None:
            return

        self.audit_log(
            "panic_mode_activated",
            {
                "trigger": event.trigger,
                "actions": event.actions_executed,
                "success": event.success,
                "error": event.error,
            },
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")