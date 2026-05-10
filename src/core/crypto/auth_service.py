from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import PasswordPolicy, PasswordValidationResult
from src.core.crypto.placeholder import AES256Placeholder
from src.core.crypto.mfa import MFAProvider
from src.core.events import EventBus, UserLoggedIn, UserLoggedOut
from src.database.key_store_repo import KeyStoreRepository
from src.database.repo import VaultRepository


@dataclass(frozen=True)
class AuthSetupResult:
    success: bool
    errors: list[str]


@dataclass(frozen=True)
class LoginResult:
    success: bool
    message: str


class FixedKeyManager:
    def __init__(self, key: bytes) -> None:
        self.key = key

    def get_encryption_key(self) -> bytes:
        return self.key


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthService:
    def __init__(self, key_store: KeyStoreRepository, event_bus: EventBus | None = None) -> None:
        self.key_store = key_store
        self.auth_manager = AuthenticationManager()
        self.password_policy = PasswordPolicy()
        self.event_bus = event_bus

        self.mfa_provider: MFAProvider | None = None
        self.mfa_enabled = False

    def enable_mfa(self, provider: MFAProvider) -> None:
        self.mfa_provider = provider
        self.mfa_enabled = True

    def disable_mfa(self) -> None:
        self.mfa_provider = None
        self.mfa_enabled = False

    def verify_mfa(self, code: str) -> bool:
        if not self.mfa_enabled:
            return True

        if self.mfa_provider is None:
            return False

        return self.mfa_provider.verify(code)

    def is_configured(self) -> bool:
        return (
            self.key_store.exists("auth_hash")
            and self.key_store.exists("enc_salt")
            and self.key_store.exists("params")
        )

    def validate_master_password(self, password: str) -> PasswordValidationResult:
        return self.password_policy.validate(password)

    def setup_master_password(self, password: str) -> AuthSetupResult:
        validation = self.validate_master_password(password)

        if not validation.valid:
            return AuthSetupResult(False, validation.errors)

        credentials = self.auth_manager.create_master_credentials(password)

        self.key_store.set_key_data("auth_hash", credentials["auth_hash"].encode("utf-8"), version=1)
        self.key_store.set_key_data("enc_salt", credentials["enc_salt"], version=1)
        self.key_store.set_json_params("params", credentials["params"], version=1)

        return AuthSetupResult(True, [])

    def login(self, password: str) -> LoginResult:
        auth_hash_raw = self.key_store.get_key_data("auth_hash")
        enc_salt = self.key_store.get_key_data("enc_salt")

        if auth_hash_raw is None or enc_salt is None:
            return LoginResult(False, "Хранилище ещё не настроено")

        stored_hash = auth_hash_raw.decode("utf-8")
        ok = self.auth_manager.login(password, stored_hash, enc_salt)

        if not ok:
            return LoginResult(False, "Неверный мастер-пароль")

        if self.mfa_enabled:
            return LoginResult(False, "Требуется второй фактор аутентификации")

        if self.event_bus is not None:
            self.event_bus.publish(UserLoggedIn(user="локально"))

        return LoginResult(True, "Вход выполнен успешно")

    def change_master_password(self, current_password: str, new_password: str) -> AuthSetupResult:
        auth_hash_raw = self.key_store.get_key_data("auth_hash")
        old_enc_salt = self.key_store.get_key_data("enc_salt")

        if auth_hash_raw is None or old_enc_salt is None:
            return AuthSetupResult(False, ["Хранилище ещё не настроено"])

        stored_hash = auth_hash_raw.decode("utf-8")

        if not self.auth_manager.kdf.verify_password(current_password, stored_hash):
            return AuthSetupResult(False, ["Текущий мастер-пароль указан неверно"])

        validation = self.validate_master_password(new_password)

        if not validation.valid:
            return AuthSetupResult(False, validation.errors)

        old_key = self.auth_manager.kdf.derive_encryption_key(current_password, old_enc_salt)
        credentials = self.auth_manager.create_master_credentials(new_password)
        new_key = self.auth_manager.kdf.derive_encryption_key(new_password, credentials["enc_salt"])

        old_crypto = AES256Placeholder(FixedKeyManager(old_key))
        new_crypto = AES256Placeholder(FixedKeyManager(new_key))

        conn = self.key_store.db.connect()

        try:
            conn.execute("BEGIN")

            repo = VaultRepository(self.key_store.db, new_crypto)
            repo.reencrypt_all_entries(old_crypto, new_crypto)

            conn.execute(
                """
                INSERT INTO key_store(key_type, key_data, version, created_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    key_data = excluded.key_data,
                    version = excluded.version,
                    created_at = excluded.created_at
                """,
                ("auth_hash", credentials["auth_hash"].encode("utf-8"), 2, utc_now_iso()),
            )

            conn.execute(
                """
                INSERT INTO key_store(key_type, key_data, version, created_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    key_data = excluded.key_data,
                    version = excluded.version,
                    created_at = excluded.created_at
                """,
                ("enc_salt", credentials["enc_salt"], 2, utc_now_iso()),
            )

            conn.execute(
                """
                INSERT INTO key_store(key_type, key_data, version, created_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    key_data = excluded.key_data,
                    version = excluded.version,
                    created_at = excluded.created_at
                """,
                (
                    "params",
                    json.dumps(credentials["params"], ensure_ascii=False).encode("utf-8"),
                    2,
                    utc_now_iso(),
                ),
            )

            conn.commit()

        except Exception:
            conn.rollback()
            return AuthSetupResult(False, ["Ошибка при перешифровании. Изменения отменены."])

        self.auth_manager.logout()
        self.auth_manager.login(new_password, credentials["auth_hash"], credentials["enc_salt"])

        return AuthSetupResult(True, [])

    def logout(self) -> None:
        self.auth_manager.logout()

        if self.event_bus is not None:
            self.event_bus.publish(UserLoggedOut(user="локально"))

    def get_encryption_key(self) -> bytes | None:
        return self.auth_manager.get_active_key()

    def is_logged_in(self) -> bool:
        return self.auth_manager.is_logged_in()

    def failed_attempts(self) -> int:
        return self.auth_manager.session.failed_attempts