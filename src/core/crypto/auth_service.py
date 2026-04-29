from __future__ import annotations

from dataclasses import dataclass

from src.core.crypto.authentication import AuthenticationManager
from src.core.crypto.key_derivation import PasswordPolicy, PasswordValidationResult
from src.database.key_store_repo import KeyStoreRepository


@dataclass(frozen=True)
class AuthSetupResult:
    success: bool
    errors: list[str]


@dataclass(frozen=True)
class LoginResult:
    success: bool
    message: str


class AuthService:
    def __init__(self, key_store: KeyStoreRepository) -> None:
        self.key_store = key_store
        self.auth_manager = AuthenticationManager()
        self.password_policy = PasswordPolicy()

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
            return AuthSetupResult(success=False, errors=validation.errors)

        credentials = self.auth_manager.create_master_credentials(password)

        self.key_store.set_key_data(
            "auth_hash",
            credentials["auth_hash"].encode("utf-8"),
            version=1,
        )

        self.key_store.set_key_data(
            "enc_salt",
            credentials["enc_salt"],
            version=1,
        )

        self.key_store.set_json_params(
            "params",
            credentials["params"],
            version=1,
        )

        return AuthSetupResult(success=True, errors=[])

    def login(self, password: str) -> LoginResult:
        auth_hash_raw = self.key_store.get_key_data("auth_hash")
        enc_salt = self.key_store.get_key_data("enc_salt")

        if auth_hash_raw is None or enc_salt is None:
            return LoginResult(False, "Хранилище ещё не настроено")

        stored_hash = auth_hash_raw.decode("utf-8")
        ok = self.auth_manager.login(password, stored_hash, enc_salt)

        if not ok:
            return LoginResult(False, "Неверный мастер-пароль")

        return LoginResult(True, "Вход выполнен успешно")

    def change_master_password(self, current_password: str, new_password: str) -> AuthSetupResult:
        auth_hash_raw = self.key_store.get_key_data("auth_hash")
        enc_salt = self.key_store.get_key_data("enc_salt")

        if auth_hash_raw is None or enc_salt is None:
            return AuthSetupResult(False, ["Хранилище ещё не настроено"])

        stored_hash = auth_hash_raw.decode("utf-8")

        if not self.auth_manager.kdf.verify_password(current_password, stored_hash):
            return AuthSetupResult(False, ["Текущий мастер-пароль указан неверно"])

        validation = self.validate_master_password(new_password)

        if not validation.valid:
            return AuthSetupResult(False, validation.errors)

        credentials = self.auth_manager.create_master_credentials(new_password)

        self.key_store.set_key_data(
            "auth_hash",
            credentials["auth_hash"].encode("utf-8"),
            version=2,
        )

        self.key_store.set_key_data(
            "enc_salt",
            credentials["enc_salt"],
            version=2,
        )

        self.key_store.set_json_params(
            "params",
            credentials["params"],
            version=2,
        )

        self.auth_manager.logout()
        self.auth_manager.login(
            new_password,
            credentials["auth_hash"],
            credentials["enc_salt"],
        )

        return AuthSetupResult(True, [])

    def logout(self) -> None:
        self.auth_manager.logout()

    def get_encryption_key(self) -> bytes | None:
        return self.auth_manager.get_active_key()

    def is_logged_in(self) -> bool:
        return self.auth_manager.is_logged_in()

    def failed_attempts(self) -> int:
        return self.auth_manager.session.failed_attempts