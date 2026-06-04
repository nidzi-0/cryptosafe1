from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Any

from src.core.security.memory_guard import SecretHolder, StackSecret
from src.core.security.side_channel_protection import ConstantTime
from src.core.security.panic_mode import PanicMode


class PanicInterruptedError(Exception):
    """Операция была прервана из-за активации panic mode."""


@dataclass
class HardenedOperationResult:
    success: bool
    operation: str
    duration_seconds: float
    details: dict[str, Any]


class PanicInterruptController:
    def __init__(self):
        self._panic_requested = False

    def request_panic(self) -> None:
        self._panic_requested = True

    def clear(self) -> None:
        self._panic_requested = False

    def is_panic_requested(self) -> bool:
        return self._panic_requested

    def check(self) -> None:
        if self._panic_requested:
            raise PanicInterruptedError("Операция прервана panic mode.")


class VaultHardeningIntegration:

    def decrypt_with_memory_protection(
        self,
        encrypted_entry: bytes,
        decrypt_callback: Callable[[bytes], bytes],
    ) -> bytes:
        with SecretHolder(encrypted_entry) as protected_ciphertext:
            plaintext = decrypt_callback(protected_ciphertext.get_bytes())

        with SecretHolder(plaintext) as protected_plaintext:
            return protected_plaintext.get_bytes()

    def encrypt_with_memory_protection(
        self,
        plaintext: bytes,
        encrypt_callback: Callable[[bytes], bytes],
    ) -> bytes:
        with SecretHolder(plaintext) as protected_plaintext:
            ciphertext = encrypt_callback(protected_plaintext.get_bytes())

        with SecretHolder(ciphertext) as protected_ciphertext:
            return protected_ciphertext.get_bytes()

    def secure_search_contains(self, query: str, candidates: list[str]) -> bool:
        return ConstantTime.fixed_time_contains(query, candidates)


class ClipboardHardeningIntegration:

    def __init__(
        self,
        clear_clipboard_callback: Callable[[], None] | None = None,
    ):
        self.clear_clipboard_callback = clear_clipboard_callback

    def protect_clipboard_text(self, text: str) -> bytes:
        with StackSecret(text.encode("utf-8")) as secret:
            return secret.bytes()

    def clear_clipboard_on_panic(self) -> None:
        if self.clear_clipboard_callback is not None:
            self.clear_clipboard_callback()


class AuditHardeningIntegration:
    def __init__(
        self,
        audit_log: Callable[[str, dict], None] | None = None,
    ):
        self.audit_log = audit_log

    def log_security_event(self, event_type: str, details: dict[str, Any]) -> None:
        if self.audit_log is not None:
            self.audit_log(event_type, details)

    def protect_audit_details(self, details: str) -> bytes:
        with StackSecret(details.encode("utf-8")) as secret:
            return secret.bytes()


class ImportExportHardeningIntegration:
    def __init__(
        self,
        panic_controller: PanicInterruptController | None = None,
    ):
        self.panic_controller = panic_controller or PanicInterruptController()

    def secure_file_operation(
        self,
        operation_name: str,
        data: bytes,
        operation_callback: Callable[[bytes], bytes],
    ) -> HardenedOperationResult:
        start = time.perf_counter()

        self.panic_controller.check()

        with SecretHolder(data) as protected_input:
            self.panic_controller.check()
            output = operation_callback(protected_input.get_bytes())

        self.panic_controller.check()

        with SecretHolder(output) as protected_output:
            result_bytes = protected_output.get_bytes()

        return HardenedOperationResult(
            success=True,
            operation=operation_name,
            duration_seconds=time.perf_counter() - start,
            details={
                "input_size": len(data),
                "output_size": len(result_bytes),
                "panic_checked": True,
            },
        )

    def interrupt_for_panic(self) -> None:
        self.panic_controller.request_panic()


class SecurityHardeningIntegrator:
    def __init__(
        self,
        audit_log: Callable[[str, dict], None] | None = None,
        clear_clipboard: Callable[[], None] | None = None,
    ):
        self.panic_controller = PanicInterruptController()
        self.vault = VaultHardeningIntegration()
        self.clipboard = ClipboardHardeningIntegration(clear_clipboard)
        self.audit = AuditHardeningIntegration(audit_log)
        self.import_export = ImportExportHardeningIntegration(self.panic_controller)

    def request_panic_interrupt(self) -> None:
        self.panic_controller.request_panic()
        self.clipboard.clear_clipboard_on_panic()
        self.audit.log_security_event(
            "panic_interrupt_requested",
            {"source": "security_hardening_integrator"},
        )

    def clear_panic_interrupt(self) -> None:
        self.panic_controller.clear()