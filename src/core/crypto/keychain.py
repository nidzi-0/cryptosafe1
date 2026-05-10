from __future__ import annotations

import json
from pathlib import Path


class KeychainStorage:
    def __init__(self, service_name: str = "CryptoSafeManager") -> None:
        self.service_name = service_name
        self.fallback_path = Path.home() / ".cryptosafe_keychain_fallback.json"

    def store_secret(self, name: str, secret: str) -> bool:
        try:
            import keyring

            keyring.set_password(self.service_name, name, secret)
            return True
        except Exception:
            self._store_fallback(name, secret)
            return False

    def load_secret(self, name: str) -> str | None:
        try:
            import keyring

            value = keyring.get_password(self.service_name, name)
            if value is not None:
                return value
        except Exception:
            pass

        return self._load_fallback(name)

    def delete_secret(self, name: str) -> None:
        try:
            import keyring

            keyring.delete_password(self.service_name, name)
        except Exception:
            pass

        data = self._read_fallback()
        if name in data:
            del data[name]
            self._write_fallback(data)

    def _read_fallback(self) -> dict[str, str]:
        if not self.fallback_path.exists():
            return {}

        try:
            return json.loads(self.fallback_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _write_fallback(self, data: dict[str, str]) -> None:
        self.fallback_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _store_fallback(self, name: str, secret: str) -> None:
        data = self._read_fallback()
        data[name] = secret
        self._write_fallback(data)

    def _load_fallback(self, name: str) -> str | None:
        data = self._read_fallback()
        return data.get(name)