from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass

from src.gui.widgets.password_entry import PasswordEntry


@dataclass(frozen=True)
class LoginResult:
    master_password: str


class LoginDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Вход в CryptoSafe")
        self.resizable(False, False)

        self.result: LoginResult | None = None

        ttk.Label(self, text="Введите мастер-пароль").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 8)
        )

        ttk.Label(self, text="Мастер-пароль:").grid(
            row=1, column=0, sticky="w", padx=10
        )

        self.password_entry = PasswordEntry(self)
        self.password_entry.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10)

        self.status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status_var, foreground="red").grid(
            row=3, column=0, columnspan=2, sticky="w", padx=10, pady=(6, 0)
        )

        buttons = ttk.Frame(self)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e", padx=10, pady=10)

        ttk.Button(buttons, text="Отмена", command=self._cancel).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(buttons, text="Войти", command=self._submit).grid(
            row=0, column=1
        )

        self.columnconfigure(0, weight=1)

        self.transient(master)
        self.grab_set()

        self.bind("<Return>", lambda _event: self._submit())
        self.bind("<Escape>", lambda _event: self._cancel())

    def _submit(self) -> None:
        password = self.password_entry.get()

        if not password:
            self.status_var.set("Введите мастер-пароль.")
            return

        self.result = LoginResult(master_password=password)
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    def show_error(self, message: str) -> None:
        self.status_var.set(message)
        messagebox.showerror("Ошибка входа", message)