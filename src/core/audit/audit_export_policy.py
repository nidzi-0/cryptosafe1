from __future__ import annotations

import hmac


class AuditExportPolicyError(Exception):
    """Ошибка политики безопасности экспорта audit log."""


class AuditExportPolicy:

    def __init__(
        self,
        auth_service=None,
        confirm_callback=None,
    ):
        self.auth_service = auth_service
        self.confirm_callback = confirm_callback

    def require_master_password_confirmation(
        self,
        password: str | None = None,
    ) -> bool:
        if self.auth_service is not None and password is not None:
            if hasattr(self.auth_service, "verify_master_password"):
                return bool(
                    self.auth_service.verify_master_password(password)
                )

            if hasattr(self.auth_service, "verify_password"):
                return bool(
                    self.auth_service.verify_password(password)
                )

        if self.confirm_callback is not None:
            return bool(self.confirm_callback())

        raise AuditExportPolicyError(
            "Для экспорта требуется подтверждение мастер-пароля."
        )

    def validate_export_allowed(
        self,
        password: str | None = None,
    ) -> None:
        confirmed = self.require_master_password_confirmation(password)

        if not confirmed:
            raise AuditExportPolicyError(
                "Экспорт audit log запрещён: мастер-пароль не подтверждён."
            )

    @staticmethod
    def constant_time_compare(left: str, right: str) -> bool:
        return hmac.compare_digest(
            str(left or ""),
            str(right or ""),
        )