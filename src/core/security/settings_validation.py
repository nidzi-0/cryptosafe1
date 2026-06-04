from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SecuritySettings:
    profile: str = "standard"
    auto_lock_timeout_seconds: int = 300
    clipboard_clear_seconds: int = 30
    timing_noise_enabled: bool = False
    memory_locking_enabled: bool = True
    start_minimized_to_tray: bool = False
    panic_mode_enabled: bool = True
    allow_plaintext_export: bool = False


@dataclass
class SettingsValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class SecuritySettingsValidator:
    allowed_profiles = {"standard", "enhanced", "paranoid"}

    def validate(self, settings: SecuritySettings) -> SettingsValidationResult:
        errors: list[str] = []
        warnings: list[str] = []

        if settings.profile not in self.allowed_profiles:
            errors.append("Unknown security profile.")

        if not 60 <= settings.auto_lock_timeout_seconds <= 8 * 60 * 60:
            errors.append("Auto-lock timeout must be between 1 minute and 8 hours.")

        if not 5 <= settings.clipboard_clear_seconds <= 300:
            errors.append("Clipboard clear timeout must be between 5 and 300 seconds.")

        if settings.profile == "paranoid" and settings.allow_plaintext_export:
            errors.append("Paranoid profile cannot allow plaintext export.")

        if settings.profile == "paranoid" and not settings.memory_locking_enabled:
            errors.append("Paranoid profile requires memory locking.")

        if settings.profile == "enhanced" and settings.auto_lock_timeout_seconds > 300:
            warnings.append("Enhanced profile usually uses auto-lock timeout of 5 minutes or less.")

        if settings.allow_plaintext_export:
            warnings.append("Plaintext export is insecure and should only be used for migration.")

        if not settings.panic_mode_enabled:
            warnings.append("Disabling panic mode reduces emergency protection.")

        if settings.auto_lock_timeout_seconds != 300:
            warnings.append("Auto-lock timeout differs from the default value.")

        return SettingsValidationResult(
            valid=not errors,
            errors=errors,
            warnings=warnings,
        )

    def validate_or_raise(self, settings: SecuritySettings) -> SettingsValidationResult:
        result = self.validate(settings)
        if not result.valid:
            raise ValueError("; ".join(result.errors))
        return result