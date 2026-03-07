from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass
from pathlib import Path

from src.gui.widgets.password_entry import PasswordEntry


@dataclass(frozen=True)
class SetupResult:
    db_path: Path
    master_password: str


class SetupWizard(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("CryptoSafe Setup Wizard")
        self.resizable(False, False)

        self.result: SetupResult | None = None

        ttk.Label(self, text="Создайте мастер-пароль").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))

        ttk.Label(self, text="Пароль:").grid(row=1, column=0, sticky="w", padx=10)
        self.pw1 = PasswordEntry(self)
        self.pw1.grid(row=2, column=0, sticky="ew", padx=10)

        ttk.Label(self, text="Подтверждение:").grid(row=3, column=0, sticky="w", padx=10, pady=(10, 0))
        self.pw2 = PasswordEntry(self)
        self.pw2.grid(row=4, column=0, sticky="ew", padx=10)

        ttk.Separator(self).grid(row=5, column=0, sticky="ew", padx=10, pady=10)

        ttk.Label(self, text="Путь к базе данных:").grid(row=6, column=0, sticky="w", padx=10)
        self.db_var = tk.StringVar(value="")
        row = ttk.Frame(self)
        row.grid(row=7, column=0, sticky="ew", padx=10)

        ttk.Entry(row, textvariable=self.db_var, width=42).grid(row=0, column=0, sticky="ew")
        ttk.Button(row, text="Обзор", command=self.browse).grid(row=0, column=1, padx=(6, 0))
        row.columnconfigure(0, weight=1)

        ttk.Separator(self).grid(row=8, column=0, sticky="ew", padx=10, pady=10)
        ttk.Label(self, text="Настройки шифрования: заглушка").grid(row=9, column=0, sticky="w", padx=10)

        btns = ttk.Frame(self)
        btns.grid(row=10, column=0, sticky="e", padx=10, pady=(10, 10))
        ttk.Button(btns, text="Отмена", command=self._cancel).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Создать", command=self.submit).grid(row=0, column=1)

        self.columnconfigure(0, weight=1)

        self.transient(master)

    def browse(self):
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("База данных SQLite", "*.db")])
        if path:
            self.db_var.set(path)

    def _cancel(self):
        self.result = None
        self.destroy()

    def submit(self):
        pw1 = self.pw1.get()
        pw2 = self.pw2.get()
        dbp = self.db_var.get().strip()

        if len(pw1) < 8:
            messagebox.showerror("Ошибка", "Пароль должен содержать не менее 8 символов.")
            return
        if pw1 != pw2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return
        if not dbp:
            messagebox.showerror("Ошибка", "Выберите путь к базе данных.")
            return

        self.result = SetupResult(db_path=Path(dbp), master_password=pw1)
        self.destroy()