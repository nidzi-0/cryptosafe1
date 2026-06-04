from __future__ import annotations

import hmac
import json
import os
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Callable


class SessionRecoveryError(Exception):
    """Базовая ошибка восстановления сессии."""


class SessionIntegrityError(SessionRecoveryError):
    """Ошибка, возникающая при нарушении целостности снимка сессии."""


class MasterPasswordRequiredError(SessionRecoveryError):
    """Ошибка, возникающая при попытке восстановления без повторной проверки мастер-пароля."""


@dataclass
class WindowState:
    geometry: str = ""
    is_visible: bool = True
    minimized_to_tray: bool = False


@dataclass
class VaultSessionState:
    selected_entry_ids: list[int] = field(default_factory=list)
    search_query: str = ""
    table_scroll_position: float = 0.0
    password_visibility_enabled: bool = False
    active_security_profile: str = "standard"
    window_state: WindowState = field(default_factory=WindowState)
    created_at: float = field(default_factory=time.time)


@dataclass
class SignedSessionSnapshot:
    payload_json: str
    signature_hex: str
    nonce_hex: str
    created_at: float


class SessionRecoveryManager:
    def __init__(
        self,
        audit_log: Callable[[str, dict], None] | None = None,
        signing_key: bytes | None = None,
    ):
        self.audit_log = audit_log
        self.signing_key = signing_key or os.urandom(32)
        self._snapshot: SignedSessionSnapshot | None = None

    def create_snapshot(self, state: VaultSessionState) -> SignedSessionSnapshot:
        payload = {
            "selected_entry_ids": state.selected_entry_ids,
            "search_query": state.search_query,
            "table_scroll_position": state.table_scroll_position,
            "password_visibility_enabled": state.password_visibility_enabled,
            "active_security_profile": state.active_security_profile,
            "window_state": {
                "geometry": state.window_state.geometry,
                "is_visible": state.window_state.is_visible,
                "minimized_to_tray": state.window_state.minimized_to_tray,
            },
            "created_at": state.created_at,
        }

        payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        nonce = os.urandom(16)
        signature = self._sign(payload_json.encode("utf-8"), nonce)

        snapshot = SignedSessionSnapshot(
            payload_json=payload_json,
            signature_hex=signature.hex(),
            nonce_hex=nonce.hex(),
            created_at=time.time(),
        )

        self._snapshot = snapshot
        self._audit("session_snapshot_created", {"created_at": snapshot.created_at})

        return snapshot

    def has_snapshot(self) -> bool:
        return self._snapshot is not None

    def verify_snapshot(self, snapshot: SignedSessionSnapshot | None = None) -> bool:
        snapshot = snapshot or self._snapshot

        if snapshot is None:
            return False

        expected = self._sign(
            snapshot.payload_json.encode("utf-8"),
            bytes.fromhex(snapshot.nonce_hex),
        )

        actual = bytes.fromhex(snapshot.signature_hex)

        return hmac.compare_digest(expected, actual)

    def restore_snapshot(
        self,
        master_password_verified: bool,
        snapshot: SignedSessionSnapshot | None = None,
    ) -> VaultSessionState:
        if not master_password_verified:
            raise MasterPasswordRequiredError(
                "Master password re-authentication is required."
            )

        snapshot = snapshot or self._snapshot

        if snapshot is None:
            raise SessionRecoveryError("No session snapshot available.")

        if not self.verify_snapshot(snapshot):
            self._audit("session_snapshot_integrity_failed", {})
            raise SessionIntegrityError("Session snapshot integrity check failed.")

        payload = json.loads(snapshot.payload_json)
        window_data = payload.get("window_state", {})

        restored = VaultSessionState(
            selected_entry_ids=list(payload.get("selected_entry_ids", [])),
            search_query=str(payload.get("search_query", "")),
            table_scroll_position=float(payload.get("table_scroll_position", 0.0)),
            password_visibility_enabled=bool(
                payload.get("password_visibility_enabled", False)
            ),
            active_security_profile=str(
                payload.get("active_security_profile", "standard")
            ),
            window_state=WindowState(
                geometry=str(window_data.get("geometry", "")),
                is_visible=bool(window_data.get("is_visible", True)),
                minimized_to_tray=bool(window_data.get("minimized_to_tray", False)),
            ),
            created_at=float(payload.get("created_at", time.time())),
        )

        self._audit(
            "session_snapshot_restored",
            {
                "selected_count": len(restored.selected_entry_ids),
                "search_query_present": bool(restored.search_query),
            },
        )

        return restored

    def clear_snapshot(self) -> None:
        self._snapshot = None
        self._audit("session_snapshot_cleared", {})

    def tamper_snapshot_for_testing(self) -> SignedSessionSnapshot:
        if self._snapshot is None:
            raise SessionRecoveryError("No session snapshot available.")

        tampered_payload = self._snapshot.payload_json.replace(
            "standard",
            "paranoid",
            1,
        )

        return SignedSessionSnapshot(
            payload_json=tampered_payload,
            signature_hex=self._snapshot.signature_hex,
            nonce_hex=self._snapshot.nonce_hex,
            created_at=self._snapshot.created_at,
        )

    def _sign(self, payload: bytes, nonce: bytes) -> bytes:
        return hmac.new(self.signing_key, nonce + payload, sha256).digest()

    def _audit(self, event_type: str, details: dict[str, Any]) -> None:
        if self.audit_log is None:
            return

        self.audit_log(event_type, details)