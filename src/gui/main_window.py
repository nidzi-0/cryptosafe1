from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.gui.widgets.vault_table import VaultTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.settings_dialog import SettingsDialog
from src.gui.change_password_dialog import ChangePasswordDialog
from src.gui.entry_dialog import EntryDialog


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSafe Manager")
        self.geometry("900x560")
        self.minsize(850, 520)

        self.auth_service = None
        self.entry_manager = None
        self.all_entries = []

        self._build_menu()
        self._build_toolbar()
        self._build_table()

        self.status_var = tk.StringVar(value="Статус: заблокировано")
        self.status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        self.status.pack(fill="x", side="bottom", padx=10, pady=(0, 8))

    def set_auth_service(self, auth_service):
        self.auth_service = auth_service

    def set_entry_manager(self, entry_manager):
        self.entry_manager = entry_manager
        self.refresh_entries()

    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать", command=self._stub)
        file_menu.add_command(label="Открыть", command=self._stub)
        file_menu.add_command(label="Резервная копия", command=self._stub)
        file_menu.add_separator()
        file_menu.add_command(
            label="Сменить мастер-пароль",
            command=self.change_master_password,
        )
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.destroy)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.add_entry)
        edit_menu.add_command(label="Изменить", command=self.edit_entry)
        edit_menu.add_command(label="Удалить", command=self.delete_entry)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи", command=self.open_logs)
        view_menu.add_command(label="Настройки", command=self.open_settings)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.about)

        menubar.add_cascade(label="Файл", menu=file_menu)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        menubar.add_cascade(label="Вид", menu=view_menu)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.config(menu=menubar)

    def _build_toolbar(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=10, pady=8)

        ttk.Button(toolbar, text="Добавить", command=self.add_entry).pack(side="left")

        ttk.Button(toolbar, text="Изменить", command=self.edit_entry).pack(
            side="left", padx=(6, 0)
        )

        ttk.Button(toolbar, text="Удалить", command=self.delete_entry).pack(
            side="left", padx=(6, 0)
        )

        ttk.Label(toolbar, text="Поиск:").pack(side="left", padx=(20, 6))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.apply_search())

        ttk.Entry(toolbar, textvariable=self.search_var, width=35).pack(side="left")

    def _build_table(self):
        self.table = VaultTable(self)
        self.table.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Изменить", command=self.edit_entry)
        self.context_menu.add_command(label="Удалить", command=self.delete_entry)

        self.table.tree.bind("<Button-3>", self.show_context_menu)

    def refresh_entries(self):
        if self.entry_manager is None:
            return

        try:
            self.all_entries = self.entry_manager.get_all_entries()
            self.table.load_entries(self.all_entries)
            self.status_var.set(
                f"Статус: разблокировано | Записей: {len(self.all_entries)}"
            )
        except Exception as exc:
            messagebox.showerror(
                "Ошибка",
                f"Не удалось загрузить записи:\n{exc}",
            )

    def apply_search(self):
        query = self.search_var.get().strip().lower()

        if not query:
            self.table.load_entries(self.all_entries)
            return

        filtered = []

        for entry in self.all_entries:
            text = " ".join(
                [
                    str(entry.get("title", "")),
                    str(entry.get("username", "")),
                    str(entry.get("url", "")),
                    str(entry.get("notes", "")),
                    str(entry.get("category", "")),
                    str(entry.get("tags", "")),
                ]
            ).lower()

            if query in text:
                filtered.append(entry)

        self.table.load_entries(filtered)

    def selected_entry_id(self):
        selected = self.table.tree.selection()

        if not selected:
            messagebox.showwarning("Выбор записи", "Выберите запись.")
            return None

        try:
            return int(selected[0])
        except ValueError:
            messagebox.showerror(
                "Ошибка",
                "Не удалось определить id выбранной записи. "
                "Проверьте VaultTable.load_entries().",
            )
            return None

    def add_entry(self):
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return

        dialog = EntryDialog(self)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        try:
            self.entry_manager.create_entry(dialog.result)
            self.refresh_entries()
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def edit_entry(self):
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return

        entry_id = self.selected_entry_id()

        if entry_id is None:
            return

        try:
            current = self.entry_manager.get_entry(entry_id)
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось открыть запись:\n{exc}")
            return

        dialog = EntryDialog(self, current)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        try:
            self.entry_manager.update_entry(entry_id, dialog.result)
            self.refresh_entries()
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def delete_entry(self):
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return

        entry_id = self.selected_entry_id()

        if entry_id is None:
            return

        answer = messagebox.askyesno("Удаление", "Удалить выбранную запись?")

        if not answer:
            return

        try:
            self.entry_manager.delete_entry(entry_id, soft_delete=True)
            self.refresh_entries()
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def show_context_menu(self, event):
        row_id = self.table.tree.identify_row(event.y)

        if row_id:
            self.table.tree.selection_set(row_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def open_logs(self):
        win = tk.Toplevel(self)
        win.title("Журнал аудита")
        win.geometry("700x400")

        AuditLogViewer(win).pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10,
        )

    def open_settings(self):
        SettingsDialog(self)

    def change_master_password(self):
        if self.auth_service is None:
            messagebox.showerror(
                "Ошибка",
                "Сервис аутентификации не подключён.",
            )
            return

        dialog = ChangePasswordDialog(self, self.auth_service)
        self.wait_window(dialog)

    def about(self):
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager — Sprint 3: AES-GCM, CRUD, таблица записей",
        )

    def _stub(self):
        messagebox.showinfo(
            "Заглушка",
            "Это действие будет реализовано позже.",
        )