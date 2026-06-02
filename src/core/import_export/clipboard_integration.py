import base64
import json
import time
from typing import Any, Dict, List, Optional


class ClipboardIntegrationError(Exception):
    pass


class ShareClipboardIntegration:
    SHARE_LINK_PREFIX = "cryptosafe-share://"
    QR_TEXT_PREFIX = "cryptosafe-qr://"

    def __init__(self, clipboard_service: Optional[Any] = None):
        self.clipboard_service = clipboard_service

    def create_share_link(self, share_package: Dict[str, Any]) -> str:
        if not isinstance(share_package, dict):
            raise ClipboardIntegrationError("Share package must be a dictionary")

        raw = json.dumps(
            share_package,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        encoded = base64.urlsafe_b64encode(raw).decode("ascii")

        return f"{self.SHARE_LINK_PREFIX}{encoded}"

    def parse_share_link(self, share_link: str) -> Dict[str, Any]:
        if not isinstance(share_link, str):
            raise ClipboardIntegrationError("Share link must be a string")

        if not share_link.startswith(self.SHARE_LINK_PREFIX):
            raise ClipboardIntegrationError("Invalid CryptoSafe share link")

        encoded = share_link[len(self.SHARE_LINK_PREFIX):]

        try:
            raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ClipboardIntegrationError("Failed to parse share link") from exc

        if not isinstance(data, dict):
            raise ClipboardIntegrationError("Decoded share link data must be a dictionary")

        return data

    def copy_share_link_to_clipboard(
        self,
        share_package: Dict[str, Any],
        source_entry_id: Optional[Any] = None,
        vault_unlocked: bool = True,
    ) -> str:
        share_link = self.create_share_link(share_package)

        self._copy_text(
            text=share_link,
            data_type="share_link",
            source_entry_id=source_entry_id,
            vault_unlocked=vault_unlocked,
        )

        return share_link

    def copy_qr_payload_to_clipboard(
        self,
        qr_chunks: List[str],
        source_entry_id: Optional[Any] = None,
        vault_unlocked: bool = True,
    ) -> str:
        if not isinstance(qr_chunks, list):
            raise ClipboardIntegrationError("QR chunks must be a list")

        payload = {
            "type": "qr_chunks",
            "created_at": int(time.time()),
            "chunks": qr_chunks,
        }

        raw = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        qr_clipboard_text = f"{self.QR_TEXT_PREFIX}{base64.urlsafe_b64encode(raw.encode('utf-8')).decode('ascii')}"

        self._copy_text(
            text=qr_clipboard_text,
            data_type="qr_payload",
            source_entry_id=source_entry_id,
            vault_unlocked=vault_unlocked,
        )

        return qr_clipboard_text

    def parse_qr_payload_from_clipboard_text(self, clipboard_text: str) -> List[str]:
        if not isinstance(clipboard_text, str):
            raise ClipboardIntegrationError("Clipboard text must be a string")

        if not clipboard_text.startswith(self.QR_TEXT_PREFIX):
            raise ClipboardIntegrationError("Clipboard text does not contain CryptoSafe QR payload")

        encoded = clipboard_text[len(self.QR_TEXT_PREFIX):]

        try:
            raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ClipboardIntegrationError("Failed to parse QR clipboard payload") from exc

        chunks = data.get("chunks")

        if not isinstance(chunks, list):
            raise ClipboardIntegrationError("QR payload does not contain chunks")

        return chunks

    def scan_qr_from_clipboard_image(self) -> Optional[str]:
        try:
            from PIL import ImageGrab
        except Exception:
            return None

        try:
            image = ImageGrab.grabclipboard()
        except Exception:
            return None

        if image is None:
            return None

        try:
            from pyzbar.pyzbar import decode
        except Exception:
            return None

        try:
            decoded_items = decode(image)
        except Exception:
            return None

        if not decoded_items:
            return None

        try:
            return decoded_items[0].data.decode("utf-8")
        except Exception:
            return None

    def _copy_text(
        self,
        text: str,
        data_type: str,
        source_entry_id: Optional[Any],
        vault_unlocked: bool,
    ) -> None:
        if self.clipboard_service is None:
            raise ClipboardIntegrationError("Clipboard service is not configured")

        if hasattr(self.clipboard_service, "copy_to_clipboard"):
            self.clipboard_service.copy_to_clipboard(
                data=text,
                data_type=data_type,
                source_entry_id=source_entry_id,
                vault_unlocked=vault_unlocked,
                never_copy=False,
            )
            return

        raise ClipboardIntegrationError("Clipboard service does not support copy_to_clipboard")