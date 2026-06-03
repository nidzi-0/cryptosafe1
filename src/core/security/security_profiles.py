from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SecurityProfileName(str, Enum):
    STANDARD = "standard"
    ENHANCED = "enhanced"
    PARANOID = "paranoid"


@dataclass
class SecurityProfile:
    name: SecurityProfileName
    auto_lock_timeout_seconds: int
    timing_noise_enabled: bool
    memory_locking_enabled: bool
    panic_stealth_enabled: bool
    clipboard_auto_clear_seconds: int
    start_minimized_to_tray: bool = False

    def validate(self) -> None:
        if not 60 <= self.auto_lock_timeout_seconds <= 8 * 60 * 60:
            raise ValueError("Invalid auto lock timeout")

        if not 5 <= self.clipboard_auto_clear_seconds <= 300:
            raise ValueError("Invalid clipboard auto clear timeout")


class SecurityProfileManager:
    def __init__(self):
        self.current_profile = self.standard()

    def standard(self) -> SecurityProfile:
        return SecurityProfile(
            name=SecurityProfileName.STANDARD,
            auto_lock_timeout_seconds=300,
            timing_noise_enabled=False,
            memory_locking_enabled=True,
            panic_stealth_enabled=False,
            clipboard_auto_clear_seconds=30,
        )

    def enhanced(self) -> SecurityProfile:
        return SecurityProfile(
            name=SecurityProfileName.ENHANCED,
            auto_lock_timeout_seconds=180,
            timing_noise_enabled=True,
            memory_locking_enabled=True,
            panic_stealth_enabled=False,
            clipboard_auto_clear_seconds=20,
        )

    def paranoid(self) -> SecurityProfile:
        return SecurityProfile(
            name=SecurityProfileName.PARANOID,
            auto_lock_timeout_seconds=60,
            timing_noise_enabled=True,
            memory_locking_enabled=True,
            panic_stealth_enabled=True,
            clipboard_auto_clear_seconds=10,
            start_minimized_to_tray=True,
        )

    def get_profile(self, name: str) -> SecurityProfile:
        normalized = SecurityProfileName(name)

        if normalized == SecurityProfileName.STANDARD:
            return self.standard()
        if normalized == SecurityProfileName.ENHANCED:
            return self.enhanced()
        if normalized == SecurityProfileName.PARANOID:
            return self.paranoid()

        raise ValueError(f"Unknown security profile: {name}")

    def explain_changes(self, target: SecurityProfile) -> list[str]:
        current = self.current_profile
        changes: list[str] = []

        if current.auto_lock_timeout_seconds != target.auto_lock_timeout_seconds:
            changes.append(
                f"Auto-lock timeout: {current.auto_lock_timeout_seconds}s -> {target.auto_lock_timeout_seconds}s"
            )

        if current.timing_noise_enabled != target.timing_noise_enabled:
            changes.append(
                f"Timing noise: {current.timing_noise_enabled} -> {target.timing_noise_enabled}"
            )

        if current.panic_stealth_enabled != target.panic_stealth_enabled:
            changes.append(
                f"Panic stealth mode: {current.panic_stealth_enabled} -> {target.panic_stealth_enabled}"
            )

        return changes

    def apply_profile(self, profile_name: str) -> SecurityProfile:
        old_profile = self.current_profile
        target = self.get_profile(profile_name)

        try:
            target.validate()
            self.current_profile = target
            return target
        except Exception:
            self.current_profile = old_profile
            raise