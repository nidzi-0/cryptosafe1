import pytest

from src.core.import_export.clipboard_integration import (
    ClipboardIntegrationError,
    ShareClipboardIntegration,
)


class FakeClipboardService:
    def __init__(self):
        self.copied = []

    def copy_to_clipboard(
        self,
        data,
        data_type,
        source_entry_id=None,
        vault_unlocked=True,
        never_copy=False,
    ):
        self.copied.append(
            {
                "data": data,
                "data_type": data_type,
                "source_entry_id": source_entry_id,
                "vault_unlocked": vault_unlocked,
                "never_copy": never_copy,
            }
        )


def test_create_and_parse_share_link_round_trip():
    integration = ShareClipboardIntegration()

    package = {
        "version": "1.0",
        "cryptosafe_shared_package": True,
        "share_id": "share-1",
        "data": "encrypted-data",
    }

    link = integration.create_share_link(package)
    parsed = integration.parse_share_link(link)

    assert link.startswith("cryptosafe-share://")
    assert parsed["share_id"] == "share-1"
    assert parsed["cryptosafe_shared_package"] is True


def test_copy_share_link_to_clipboard():
    clipboard = FakeClipboardService()
    integration = ShareClipboardIntegration(clipboard_service=clipboard)

    package = {
        "version": "1.0",
        "cryptosafe_shared_package": True,
        "share_id": "share-1",
        "data": "encrypted-data",
    }

    link = integration.copy_share_link_to_clipboard(
        share_package=package,
        source_entry_id="1",
        vault_unlocked=True,
    )

    assert link.startswith("cryptosafe-share://")
    assert len(clipboard.copied) == 1
    assert clipboard.copied[0]["data_type"] == "share_link"
    assert clipboard.copied[0]["source_entry_id"] == "1"
    assert clipboard.copied[0]["never_copy"] is False


def test_invalid_share_link_rejected():
    integration = ShareClipboardIntegration()

    with pytest.raises(ClipboardIntegrationError):
        integration.parse_share_link("bad-link")


def test_copy_and_parse_qr_payload_clipboard_text():
    clipboard = FakeClipboardService()
    integration = ShareClipboardIntegration(clipboard_service=clipboard)

    chunks = [
        '{"chunk": 1, "total": 1, "data": "abc", "checksum": "12345678"}'
    ]

    text = integration.copy_qr_payload_to_clipboard(
        qr_chunks=chunks,
        source_entry_id="1",
        vault_unlocked=True,
    )

    parsed_chunks = integration.parse_qr_payload_from_clipboard_text(text)

    assert text.startswith("cryptosafe-qr://")
    assert parsed_chunks == chunks
    assert len(clipboard.copied) == 1
    assert clipboard.copied[0]["data_type"] == "qr_payload"


def test_qr_clipboard_image_scan_gracefully_returns_none_without_image():
    integration = ShareClipboardIntegration()

    result = integration.scan_qr_from_clipboard_image()

    assert result is None or isinstance(result, str)