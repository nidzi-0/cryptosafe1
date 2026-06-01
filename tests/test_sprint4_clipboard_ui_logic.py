from __future__ import annotations

from src.gui.widgets.vault_table import VaultTable


def test_vault_table_clipboard_marker_logic():
    table = object.__new__(VaultTable)

    table.clipboard_entry_id = None
    table.clipboard_data_type = None

    assert VaultTable._clipboard_display(table, 1) == ""

    table.clipboard_entry_id = 1
    table.clipboard_data_type = "password"

    assert VaultTable._clipboard_display(table, 1) == "В буфере: password"
    assert VaultTable._clipboard_display(table, 2) == ""


def test_vault_table_action_constants_exist():
    assert VaultTable.ACTION_COPY_PASSWORD == "Copy Password"
    assert VaultTable.ACTION_COPY_USERNAME == "Copy Username"