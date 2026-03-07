from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.settings_dialog import SettingsDialog


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("760x440")

        self._build_menu()

        self.table = SecureTable(self)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)
        self.table.load_test_data()

        self.status_var = tk.StringVar(value="Статус: заблокировано | Таймер буфера обмена: --")
        self.status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        self.status.pack(fill="x", side="bottom", padx=10, pady=(0, 8))

    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать", command=self._stub)
        file_menu.add_command(label="Открыть", command=self._stub)
        file_menu.add_command(label="Резервная копия", command=self._stub)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.destroy)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self._stub)
        edit_menu.add_command(label="Изменить", command=self._stub)
        edit_menu.add_command(label="Удалить", command=self._stub)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи", command=self.open_logs)
        view_menu.add_command(label="Настройки", command=self._stub_settings)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.about)

        menubar.add_cascade(label="Файл", menu=file_menu)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        menubar.add_cascade(label="Вид", menu=view_menu)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.config(menu=menubar)

    def open_logs(self):
        win = tk.Toplevel(self)
        win.title("Журнал аудита (заглушка)")
        AuditLogViewer(win).pack(fill="both", expand=True, padx=10, pady=10)

    def _stub_settings(self):
        SettingsDialog(self)

    def about(self):
        messagebox.showinfo("О программе", "CryptoSafe Manager")

    def _stub(self):
        messagebox.showinfo("Заглушка")