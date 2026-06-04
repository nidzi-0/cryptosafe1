from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class ProgressState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class SecurityColor(str, Enum):
    LOCKED = "red"
    UNLOCKED = "green"
    WARNING = "yellow"
    BUSY = "blue"


@dataclass
class KeyboardShortcut:
    action: str
    shortcut: str
    description: str


@dataclass
class AccessibilityElement:
    element_id: str
    role: str
    label: str
    description: str = ""
    focusable: bool = True


@dataclass
class ProgressIndicator:
    operation: str
    state: ProgressState = ProgressState.IDLE
    percent: int = 0
    message: str = ""
    started_at: float = field(default_factory=time.monotonic)

    def start(self, message: str = "") -> None:
        self.state = ProgressState.RUNNING
        self.percent = 0
        self.message = message or f"{self.operation} started"
        self.started_at = time.monotonic()

    def update(self, percent: int, message: str = "") -> None:
        self.percent = max(0, min(100, int(percent)))
        if message:
            self.message = message

    def finish(self, message: str = "") -> None:
        self.state = ProgressState.DONE
        self.percent = 100
        self.message = message or f"{self.operation} completed"

    def fail(self, message: str) -> None:
        self.state = ProgressState.FAILED
        self.message = message


@dataclass
class UserFriendlyError:
    title: str
    message: str
    solution: str
    debug_details: str


class UXAccessibilityManager:

    def __init__(self, debug_logger: Callable[[str], None] | None = None):
        self.debug_logger = debug_logger
        self.shortcuts = self._default_shortcuts()
        self.accessibility_elements: dict[str, AccessibilityElement] = {}
        self.progress: dict[str, ProgressIndicator] = {}

    def _default_shortcuts(self) -> dict[str, KeyboardShortcut]:
        shortcuts = [
            KeyboardShortcut("add_entry", "Ctrl+N", "Add new vault entry"),
            KeyboardShortcut("edit_entry", "Enter", "Edit selected vault entry"),
            KeyboardShortcut("delete_entry", "Delete", "Delete selected vault entry"),
            KeyboardShortcut("search", "Ctrl+F", "Focus search field"),
            KeyboardShortcut("copy_password", "Ctrl+Shift+C", "Copy selected password"),
            KeyboardShortcut("toggle_password", "Ctrl+Shift+P", "Show or hide selected password"),
            KeyboardShortcut("panic_mode", "Ctrl+Shift+Esc", "Activate panic mode"),
            KeyboardShortcut("lock_vault", "Ctrl+L", "Lock vault"),
        ]
        return {shortcut.action: shortcut for shortcut in shortcuts}

    def supported_navigation_keys(self) -> set[str]:
        return {"Tab", "Shift+Tab", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Enter", "Escape"}

    def get_shortcut(self, action: str) -> KeyboardShortcut:
        return self.shortcuts[action]

    def register_accessibility_element(
        self,
        element_id: str,
        role: str,
        label: str,
        description: str = "",
        focusable: bool = True,
    ) -> AccessibilityElement:
        element = AccessibilityElement(
            element_id=element_id,
            role=role,
            label=label,
            description=description,
            focusable=focusable,
        )
        self.accessibility_elements[element_id] = element
        return element

    def screen_reader_summary(self) -> list[str]:
        return [
            f"{element.role}: {element.label}"
            for element in self.accessibility_elements.values()
        ]

    def start_progress(self, operation: str, message: str = "") -> ProgressIndicator:
        indicator = ProgressIndicator(operation=operation)
        indicator.start(message)
        self.progress[operation] = indicator
        return indicator

    def update_progress(self, operation: str, percent: int, message: str = "") -> ProgressIndicator:
        indicator = self.progress[operation]
        indicator.update(percent, message)
        return indicator

    def finish_progress(self, operation: str, message: str = "") -> ProgressIndicator:
        indicator = self.progress[operation]
        indicator.finish(message)
        return indicator

    def color_for_security_state(self, state: str) -> str:
        normalized = state.lower().strip()
        mapping = {
            "locked": SecurityColor.LOCKED.value,
            "unlocked": SecurityColor.UNLOCKED.value,
            "warning": SecurityColor.WARNING.value,
            "busy": SecurityColor.BUSY.value,
        }
        return mapping.get(normalized, "gray")

    def confirm_destructive_action(self, action: str, confirmation_provider: Callable[[str], bool]) -> bool:
        prompt = f"Confirm destructive action: {action}"
        return confirmation_provider(prompt)

    def friendly_error(self, code: str, debug_details: str = "") -> UserFriendlyError:
        errors = {
            "clipboard_unavailable": UserFriendlyError(
                title="Clipboard unavailable",
                message="The clipboard could not be accessed.",
                solution="Try again, use ephemeral mode, or restart the application.",
                debug_details=debug_details,
            ),
            "vault_locked": UserFriendlyError(
                title="Vault locked",
                message="The vault is currently locked.",
                solution="Unlock the vault with your master password and repeat the action.",
                debug_details=debug_details,
            ),
            "import_failed": UserFriendlyError(
                title="Import failed",
                message="The selected file could not be imported.",
                solution="Check the file format, password and integrity, then try again.",
                debug_details=debug_details,
            ),
            "network_push_failed": UserFriendlyError(
                title="Network operation failed",
                message="The network connection was reset.",
                solution="Check VPN or internet connection and retry later.",
                debug_details=debug_details,
            ),
        }

        result = errors.get(
            code,
            UserFriendlyError(
                title="Operation failed",
                message="The operation could not be completed.",
                solution="Check the input data and try again.",
                debug_details=debug_details,
            ),
        )

        self.log_debug_error(code, debug_details)
        return result

    def log_debug_error(self, code: str, details: str) -> None:
        if self.debug_logger is not None:
            self.debug_logger(f"{code}: {details}")

    def lazy_load_entries(self, entries: list[dict], page: int = 0, page_size: int = 100) -> list[dict]:
        if page < 0:
            raise ValueError("page must be non-negative")
        if page_size <= 0:
            raise ValueError("page_size must be positive")

        start = page * page_size
        end = start + page_size
        return entries[start:end]

    def optimize_query_limit(self, requested_limit: int, maximum: int = 1000) -> int:
        if requested_limit <= 0:
            return 100
        return min(requested_limit, maximum)