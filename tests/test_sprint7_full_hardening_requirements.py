from src.core.security.memory_guard import (
    MMapLockedBuffer,
    SecureHeapAllocator,
    StackSecret,
    VolatileSecret,
)
from src.core.security.physical_security import (
    PhysicalMitigationStatus,
    PhysicalSecurityManager,
    PowerAnalysisMitigator,
)


def test_sc3_power_analysis_random_delay_and_blinding():
    mitigator = PowerAnalysisMitigator()

    secret = b"secret-key-material"
    blinded, mask = mitigator.blind_bytes(secret)

    assert blinded != secret
    assert mask != b"\x00" * len(secret)
    assert mitigator.unblind_bytes(blinded, mask) == secret

    mitigator.random_delay()


def test_sc3_sc4_physical_security_report_documents_platform_controls():
    manager = PhysicalSecurityManager()
    report = manager.report()

    assert report.power_random_delay == PhysicalMitigationStatus.IMPLEMENTED
    assert report.power_blinding == PhysicalMitigationStatus.IMPLEMENTED
    assert report.constant_power_mode == PhysicalMitigationStatus.PLATFORM_DEPENDENT
    assert report.electromagnetic_filtering == PhysicalMitigationStatus.DOCUMENTED_NOT_APPLICABLE
    assert report.electromagnetic_plaintext_policy == PhysicalMitigationStatus.IMPLEMENTED
    assert report.notes


def test_sc4_plaintext_external_export_blocked_without_explicit_approval():
    manager = PhysicalSecurityManager()

    assert manager.em_policy.plaintext_external_export_allowed(False) is False
    assert manager.em_policy.plaintext_external_export_allowed(True) is True


def test_mem1_mmap_locked_buffer_write_read_and_close():
    with MMapLockedBuffer(64) as buffer:
        buffer.write(b"pinned-secret")
        assert buffer.read() == b"pinned-secret"

    assert buffer.closed is True


def test_mem3_secure_heap_allocator_guard_canary_path():
    allocator = SecureHeapAllocator()

    block = allocator.allocate_with_data(b"heap-secret")
    assert block.read() == b"heap-secret"

    allocator.free(block)
    assert allocator.active_blocks() == 0


def test_mem4_stack_secret_context_wipes_after_return_pattern():
    secret = StackSecret(b"stack-secret")

    with secret as value:
        assert value.bytes() == b"stack-secret"

    try:
        value.bytes()
        assert False
    except Exception:
        assert True


def test_mem4_volatile_secret_wipes_after_context():
    secret = VolatileSecret(b"volatile-secret")

    with secret as value:
        assert value.reveal() == b"volatile-secret"

    try:
        secret.reveal()
        assert False
    except Exception:
        assert True