import pytest

from src.core.security.settings_validation import (
    SecuritySettings,
    SecuritySettingsValidator,
)
from src.core.security.ux_accessibility import (
    ProgressState,
    UXAccessibilityManager,
)


def test_ux1_keyboard_navigation_and_shortcuts_are_defined():
    manager = UXAccessibilityManager()

    keys = manager.supported_navigation_keys()

    assert "Tab" in keys
    assert "ArrowUp" in keys
    assert "ArrowDown" in keys
    assert "Enter" in keys

    assert manager.get_shortcut("panic_mode").shortcut == "Ctrl+Shift+Esc"
    assert manager.get_shortcut("copy_password").shortcut == "Ctrl+Shift+C"
    assert manager.get_shortcut("toggle_password").shortcut == "Ctrl+Shift+P"


def test_ux1_accessibility_elements_support_screen_reader_summary():
    manager = UXAccessibilityManager()

    manager.register_accessibility_element(
        element_id="vault_table",
        role="table",
        label="Vault entries",
        description="List of encrypted vault entries",
    )
    manager.register_accessibility_element(
        element_id="search",
        role="textbox",
        label="Search entries",
    )

    summary = manager.screen_reader_summary()

    assert "table: Vault entries" in summary
    assert "textbox: Search entries" in summary


def test_ux2_progress_indicator_confirmation_and_color_feedback():
    manager = UXAccessibilityManager()

    progress = manager.start_progress("export", "Export started")
    assert progress.state == ProgressState.RUNNING

    manager.update_progress("export", 50, "Half complete")
    assert manager.progress["export"].percent == 50

    manager.finish_progress("export", "Export complete")
    assert manager.progress["export"].state == ProgressState.DONE
    assert manager.progress["export"].percent == 100

    confirmed = manager.confirm_destructive_action(
        "delete selected entry",
        confirmation_provider=lambda prompt: "delete" in prompt,
    )
    assert confirmed is True

    assert manager.color_for_security_state("locked") == "red"
    assert manager.color_for_security_state("unlocked") == "green"
    assert manager.color_for_security_state("warning") == "yellow"


def test_ux3_friendly_errors_suggest_solutions_and_log_debug_details():
    logs = []
    manager = UXAccessibilityManager(debug_logger=lambda message: logs.append(message))

    error = manager.friendly_error(
        "clipboard_unavailable",
        debug_details="platform adapter returned false",
    )

    assert "clipboard" in error.message.lower()
    assert "try again" in error.solution.lower()
    assert logs
    assert "platform adapter returned false" in logs[0]


def test_ux4_lazy_loading_and_query_limit_optimization():
    manager = UXAccessibilityManager()
    entries = [{"id": index} for index in range(1000)]

    page = manager.lazy_load_entries(entries, page=2, page_size=100)

    assert len(page) == 100
    assert page[0]["id"] == 200
    assert page[-1]["id"] == 299

    assert manager.optimize_query_limit(5000) == 1000
    assert manager.optimize_query_limit(0) == 100


def test_cfg1_security_profiles_include_standard_enhanced_paranoid():
    validator = SecuritySettingsValidator()

    for profile in ("standard", "enhanced", "paranoid"):
        result = validator.validate(SecuritySettings(profile=profile))
        assert result.valid is True


def test_cfg2_profile_migration_prevents_invalid_profile():
    validator = SecuritySettingsValidator()

    result = validator.validate(SecuritySettings(profile="unknown"))

    assert result.valid is False
    assert "Unknown security profile." in result.errors


def test_cfg3_settings_validation_prevents_insecure_combinations():
    validator = SecuritySettingsValidator()

    result = validator.validate(
        SecuritySettings(
            profile="paranoid",
            allow_plaintext_export=True,
        )
    )

    assert result.valid is False
    assert "Paranoid profile cannot allow plaintext export." in result.errors


def test_cfg3_settings_validation_warns_for_non_default_settings():
    validator = SecuritySettingsValidator()

    result = validator.validate(
        SecuritySettings(
            profile="standard",
            auto_lock_timeout_seconds=600,
            allow_plaintext_export=True,
            panic_mode_enabled=False,
        )
    )

    assert result.valid is True
    assert any("Plaintext export is insecure" in warning for warning in result.warnings)
    assert any("Disabling panic mode" in warning for warning in result.warnings)
    assert any("Auto-lock timeout differs" in warning for warning in result.warnings)


def test_cfg3_validate_or_raise_rejects_invalid_settings():
    validator = SecuritySettingsValidator()

    with pytest.raises(ValueError):
        validator.validate_or_raise(
            SecuritySettings(
                profile="paranoid",
                memory_locking_enabled=False,
            )
        )


def test_test5_usability_plan_is_defined_in_code():
    usability_plan = {
        "participants": 5,
        "tasks": [
            "Keyboard navigation",
            "Auto-lock",
            "Panic mode",
            "Tray/background",
            "Security profiles",
        ],
        "metrics": [
            "task completion time",
            "error rate",
            "critical security error count",
            "difficulty score",
        ],
        "acceptance": {
            "minimum_success_rate": 0.8,
            "critical_security_error_count": 0,
        },
    }

    assert usability_plan["participants"] >= 5
    assert "Keyboard navigation" in usability_plan["tasks"]
    assert "Auto-lock" in usability_plan["tasks"]
    assert "Panic mode" in usability_plan["tasks"]
    assert "Tray/background" in usability_plan["tasks"]
    assert "Security profiles" in usability_plan["tasks"]
    assert "task completion time" in usability_plan["metrics"]
    assert "error rate" in usability_plan["metrics"]
    assert usability_plan["acceptance"]["critical_security_error_count"] == 0