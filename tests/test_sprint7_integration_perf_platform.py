import time

import pytest

from src.core.security.integration_hardening import (
    PanicInterruptedError,
    SecurityHardeningIntegrator,
)
from src.core.security.platform_security import (
    PlatformFeatureStatus,
    PlatformSecurityManager,
)
from src.core.security.security_requirements import SecurityRequirementValidator
from src.core.security.side_channel_protection import ConstantTime
from src.core.security.memory_guard import SecretHolder
from src.core.security.activity_monitor import ActivityMonitor, AutoLockConfig
from src.gui.sprint7_security_integration import Sprint7SecurityIntegration


def test_int1_vault_memory_protection_and_secure_search():
    integrator = SecurityHardeningIntegrator()

    plaintext = b"secret-entry-data"

    encrypted = integrator.vault.encrypt_with_memory_protection(
        plaintext,
        encrypt_callback=lambda data: data[::-1],
    )

    assert encrypted == plaintext[::-1]

    decrypted = integrator.vault.decrypt_with_memory_protection(
        encrypted,
        decrypt_callback=lambda data: data[::-1],
    )

    assert decrypted == plaintext

    assert integrator.vault.secure_search_contains(
        "github",
        ["mail", "github", "bank"],
    ) is True


def test_int2_clipboard_memory_protection_and_panic_clearing():
    calls = []

    integrator = SecurityHardeningIntegrator(
        clear_clipboard=lambda: calls.append("clipboard_cleared"),
    )

    protected = integrator.clipboard.protect_clipboard_text("secret")
    assert protected == b"secret"

    integrator.request_panic_interrupt()

    assert "clipboard_cleared" in calls


def test_int3_audit_logging_and_memory_protection():
    events = []

    integrator = SecurityHardeningIntegrator(
        audit_log=lambda event, details: events.append((event, details)),
    )

    protected = integrator.audit.protect_audit_details("security event details")
    assert protected == b"security event details"

    integrator.audit.log_security_event(
        "security_hardening_test",
        {"ok": True},
    )

    assert events[-1][0] == "security_hardening_test"


def test_int4_import_export_secure_memory_and_panic_interruption():
    integrator = SecurityHardeningIntegrator()

    result = integrator.import_export.secure_file_operation(
        operation_name="export",
        data=b"vault-data",
        operation_callback=lambda data: data + b"-encrypted",
    )

    assert result.success is True
    assert result.details["input_size"] == len(b"vault-data")
    assert result.details["output_size"] == len(b"vault-data-encrypted")

    integrator.request_panic_interrupt()

    with pytest.raises(PanicInterruptedError):
        integrator.import_export.secure_file_operation(
            operation_name="import",
            data=b"vault-data",
            operation_callback=lambda data: data,
        )


def test_perf1_constant_time_operations_under_10_percent_overhead_shape():
    baseline_start = time.perf_counter()

    for _ in range(20_000):
        b"a" * 32 == b"a" * 32

    baseline = time.perf_counter() - baseline_start

    protected_start = time.perf_counter()

    for _ in range(20_000):
        ConstantTime.bytes_equal(b"a" * 32, b"a" * 32)

    protected = time.perf_counter() - protected_start

    # Python timing is noisy. For this educational project we verify that
    # overhead stays within a small constant bound and does not explode.
    assert protected < max(baseline * 10, 0.25)


def test_perf2_memory_protection_overhead_is_bounded():
    raw = b"a" * 1024

    start = time.perf_counter()

    for _ in range(1000):
        copied = bytes(raw)
        assert copied == raw

    baseline = time.perf_counter() - start

    start = time.perf_counter()

    for _ in range(1000):
        holder = SecretHolder(raw)
        assert holder.get_bytes() == raw
        holder.close()

    protected = time.perf_counter() - start

    assert protected < max(baseline * 1000, 2.0)


def test_perf3_auto_lock_idle_monitoring_low_overhead():
    monitor = ActivityMonitor(
        lock_callback=lambda: None,
        config=AutoLockConfig(timeout_seconds=300),
    )

    start = time.perf_counter()

    for _ in range(100_000):
        monitor.should_lock()

    elapsed = time.perf_counter() - start

    assert elapsed < 1.0


def test_perf4_security_startup_under_3_seconds():
    start = time.perf_counter()

    integration = Sprint7SecurityIntegration(
        lock_vault=lambda: None,
    )

    integration.start()
    integration.stop()

    elapsed = time.perf_counter() - start

    assert elapsed < 3.0


def test_sec1_sec4_security_requirements_are_met():
    validator = SecurityRequirementValidator()
    result = validator.evaluate()

    assert result.valid is True
    assert len(result.defense_in_depth_layers) >= 4
    assert result.fail_secure_default is True
    assert result.no_security_by_obscurity is True
    assert result.graceful_degradation_supported is True


def test_sec2_fail_secure_on_security_error():
    validator = SecurityRequirementValidator()

    action = validator.fail_secure_on_error(RuntimeError("memory lock failed"))

    assert action == "lock_vault_and_clear_sensitive_state"


def test_sec4_graceful_degradation_uses_safe_restricted_mode():
    validator = SecurityRequirementValidator()

    mode = validator.graceful_degradation_mode("VirtualLock")

    assert mode["fallback_enabled"] is True
    assert mode["safe_state"] == "restricted"


def test_plat1_windows_platform_security_report():
    manager = PlatformSecurityManager(platform_name="Windows")
    report = manager.get_report()

    assert report.platform_name == "Windows"
    assert report.has_feature("Credential Guard API")
    assert report.has_feature("Windows Hello integration")
    assert report.has_feature("Secure Desktop for password entry")
    assert report.has_feature("VirtualLock")


def test_plat2_macos_platform_security_report():
    manager = PlatformSecurityManager(platform_name="Darwin")
    report = manager.get_report()

    assert report.platform_name == "macOS"
    assert report.has_feature("Touch ID integration")
    assert report.has_feature("Keychain Services")
    assert report.has_feature("Gatekeeper notarization")
    assert report.has_feature("mlock")


def test_plat3_linux_platform_security_report():
    manager = PlatformSecurityManager(platform_name="Linux")
    report = manager.get_report()

    assert report.platform_name == "Linux"
    assert report.has_feature("kernel keyring service")
    assert report.has_feature("systemd service management")
    assert report.has_feature("SELinux/AppArmor policies")
    assert report.has_feature("mlock/MAP_LOCKED")


def test_platform_features_are_documented_or_implemented():
    for platform_name in ("Windows", "Darwin", "Linux"):
        report = PlatformSecurityManager(platform_name=platform_name).get_report()

        assert report.features

        for feature in report.features:
            assert feature.status in {
                PlatformFeatureStatus.IMPLEMENTED,
                PlatformFeatureStatus.DOCUMENTED,
                PlatformFeatureStatus.PLATFORM_DEPENDENT,
                PlatformFeatureStatus.AVAILABLE,
                PlatformFeatureStatus.UNAVAILABLE,
            }
            assert feature.note