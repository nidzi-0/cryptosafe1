from __future__ import annotations

import time
from dataclasses import dataclass

from src.core.crypto.key_derivation import KeyDerivationManager
from src.core.crypto.key_storage import KeyCache


@dataclass
class AuthSession:
    logged_in: bool = False
    login_time: float = 0.0
    last_activity: float = 0.0
    failed_attempts: int = 0


class AuthenticationManager:
    def __init__(self) -> None:
        self.kdf = KeyDerivationManager()
        self.cache = KeyCache(ttl_seconds=3600, clear_on_focus_lost=True)
        self.session = AuthSession()

    def _delay_for_failures(self) -> int:
        n = self.session.failed_attempts

        if n <= 0:
            return 0
        if n <= 2:
            return 1
        if n <= 4:
            return 5
        return 30

    def create_master_credentials(self, password: str) -> dict:
        auth_hash = self.kdf.create_auth_hash(password)
        enc_salt = self.kdf.generate_encryption_salt()

        return {
            "auth_hash": auth_hash,
            "enc_salt": enc_salt,
            "params": self.kdf.export_params(),
        }

    def login(self, password: str, stored_hash: str, enc_salt: bytes) -> bool:
        self.cache.on_focus_restored()

        if not self.kdf.verify_password(password, stored_hash):
            self.session.failed_attempts += 1
            time.sleep(self._delay_for_failures())
            return False

        key = self.kdf.derive_encryption_key(password, enc_salt)
        self.cache.store_key(key)

        now = time.time()
        self.session.logged_in = True
        self.session.login_time = now
        self.session.last_activity = now
        self.session.failed_attempts = 0

        return True

    def logout(self) -> None:
        self.cache.clear()
        self.session.logged_in = False
        self.session.login_time = 0.0
        self.session.last_activity = 0.0

    def touch(self) -> None:
        if self.session.logged_in:
            self.session.last_activity = time.time()

    def is_logged_in(self) -> bool:
        if not self.session.logged_in:
            return False

        if not self.cache.is_unlocked():
            self.logout()
            return False

        return True

    def get_active_key(self) -> bytes | None:
        return self.cache.get_key()

    def on_focus_lost(self) -> None:
        self.cache.on_focus_lost()
        self.session.logged_in = False

    def on_focus_restored(self) -> None:
        self.cache.on_focus_restored()

    def on_window_minimized(self) -> None:
        self.cache.on_window_minimized()
        self.session.logged_in = False

    def on_auto_lock(self) -> None:
        self.cache.on_auto_lock()
        self.logout()