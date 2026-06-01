from __future__ import annotations
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox

from src.core.vault.entry_manager import EntryManager
from src.core.vault.password_generator import PasswordGenerator
from src.core.crypto.key_manager import CachedKeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService

from src.core.clipboard.clipboard_service import ClipboardService, ClipboardSettings
from src.core.clipboard.clipboard_settings_store import ClipboardSettingsStore
from src.core.clipboard.future_features import FutureIntegration

from src.gui.widgets.vault_table import VaultTable
from src.gui.entry_dialog import EntryDialog
from src.gui.settings_dialog import SettingsDialog
from src.gui.change_password_dialog import ChangePasswordDialog
from src.gui.widgets.audit_log_viewer import AuditLogViewer

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cryptosafe_dev.db")


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSafe Manager")
        self.geometry("1120x700")
        self.minsize(1000, 600)

        self.entry_manager = EntryManager(DB_PATH)
        self.password_generator = PasswordGenerator()

        self.clipboard_settings_store = ClipboardSettingsStore(DB_PATH)
        self.clipboard_settings = self.clipboard_settings_store.load()
        self.clipboard_service = ClipboardService(settings=self.clipboard_settings)
        self.clipboard_service.subscribe(self.on_clipboard_event)

        self.passwords_visible_var = tk.BooleanVar(value=False)

        self.table = VaultTable(self)
        self.table.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Изменить", command=self.edit_entry)
        self.context_menu.add_command(label="Удалить", command=self.delete_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Показать/скрыть пароль",
            command=self.toggle_selected_passwords,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Копировать пароль",
            command=self.copy_selected_password,
        )
        self.context_menu.add_command(
            label="Копировать логин",
            command=self.copy_selected_username,
        )
        self.context_menu.add_command(
            label="Копировать всё",
            command=self.copy_selected_all,
        )
        self.context_menu.add_command(
            label="Предпросмотр буфера",
            command=self.show_clipboard_preview,
        )
        self.context_menu.add_command(
            label="Показать содержимое буфера",
            command=self.reveal_clipboard_preview_with_auth,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Очистить буфер обмена",
            command=self.clear_clipboard_manual,
        )

        self.table.tree.bind("<Button-3>", self.show_context_menu)
        self.table.tree.bind("<Button-1>", self.on_table_left_click)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.apply_search())

        self.clipboard_status_var = tk.StringVar(value="Буфер обмена: пусто")
        self.status_var = tk.StringVar(value="Статус: заблокировано")
        self.status_frame = ttk.Frame(self)
        self.status_frame.pack(fill="x", side="bottom", padx=10, pady=(0, 8))

        ttk.Label(
            self.status_frame,
            textvariable=self.status_var,
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        ttk.Label(
            self.status_frame,
            textvariable=self.clipboard_status_var,
            anchor="e",
        ).pack(side="right")

        self.refresh_entries()

        # Future Integration INT-3 (Sprint 6/7) заглушки
        FutureIntegration.generate_totp("secret123")
        FutureIntegration.secure_share(1, "user@example.com")
        FutureIntegration.panic_mode()

        self.protocol("WM_DELETE_WINDOW", self.secure_close)

    def on_clipboard_event(self, event):
        if hasattr(self, "table") and self.table:
            self.table.set_clipboard_marker(
                getattr(event, "source_entry_id", None),
                getattr(event, "data_type", None),
            )

    def show_clipboard_preview(self):
        status = self.clipboard_service.get_status()
        if not status.active:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст.")
            return

        messagebox.showinfo(
            "Предпросмотр буфера",
            f"Тип: {status.data_type}\nИсточник: {status.source_entry_id}\nPreview: {status.preview}",
        )

    def reveal_clipboard_preview_with_auth(self):
        status = self.clipboard_service.get_status()
        if not status.active:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст.")
            return

        answer = messagebox.askyesno(
            "Подтверждение",
            "Показать полное содержимое буфера обмена?",
        )
        if not answer:
            return

        plaintext = self.clipboard_service.get_current_plaintext_for_testing()
        messagebox.showinfo("Полное содержимое буфера", plaintext)

    def copy_selected_password(self):
        entry = self.get_single_selected_entry()
        if entry:
            self.clipboard_service.copy_to_clipboard(entry.get("password", ""), "password", entry.get("id"))

    def copy_selected_username(self):
        entry = self.get_single_selected_entry()
        if entry:
            self.clipboard_service.copy_to_clipboard(entry.get("username", ""), "username", entry.get("id"))

    def copy_selected_all(self):
        entry = self.get_single_selected_entry()
        if entry:
            data = f"Title: {entry.get('title')}\nUsername: {entry.get('username')}\nPassword: {entry.get('password')}\nURL: {entry.get('url')}"
            self.clipboard_service.copy_to_clipboard(data, "text", entry.get("id"))

    def clear_clipboard_manual(self):
        self.clipboard_service.clear_clipboard(reason="manual")

    def get_single_selected_entry(self):
        selected_ids = self.table.get_selected_ids()
        if not selected_ids:
            return None
        return self.entry_manager.get_entry(selected_ids[0])

    def add_entry(self):
        dialog = EntryDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            self.entry_manager.create_entry(dialog.result)
            self.refresh_entries()

    def edit_entry(self):
        entry = self.get_single_selected_entry()
        if not entry:
            return
        dialog = EntryDialog(self, entry)
        self.wait_window(dialog)
        if dialog.result:
            self.entry_manager.update_entry(entry["id"], dialog.result)
            self.refresh_entries()

    def delete_entry(self):
        selected_ids = self.table.get_selected_ids()
        for entry_id in selected_ids:
            self.entry_manager.delete_entry(entry_id, soft_delete=True)
        self.refresh_entries()

    def toggle_selected_passwords(self):
        self.table.toggle_selected_password_visibility()

    def refresh_entries(self):
        self.all_entries = self.entry_manager.get_all_entries()
        self.displayed_entries = self.all_entries[:]
        self.table.load_entries(self.displayed_entries)

    def apply_search(self):
        query = self.search_var.get().strip().lower()
        if not query:
            self.table.load_entries(self.all_entries)
            return

        filtered = [
            entry for entry in self.all_entries
            if query in entry.get("title", "").lower()
            or query in entry.get("username", "").lower()
            or query in entry.get("url", "").lower()
        ]
        self.table.load_entries(filtered)

    def get_single_entry_by_id(self, entry_id):
        return self.entry_manager.get_entry(entry_id)

    def on_table_left_click(self, event):
        action, entry_id = self.table.identify_action(event)
        if action == self.table.ACTION_COPY_PASSWORD:
            self.copy_selected_password()
        elif action == self.table.ACTION_COPY_USERNAME:
            self.copy_selected_username()

    def show_context_menu(self, event):
        row_id = self.table.tree.identify_row(event.y)
        if row_id:
            self.table.tree.selection_set(row_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def secure_close(self):
        try:
            self.clipboard_service.close()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()