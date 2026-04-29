from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass

from src.gui.widgets.password_entry import PasswordEntry


@dataclass(frozen=True)
class ChangePasswordResult:
    current_password: str
    new_password: str


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Смена мастер-пароля")
        self.resizable(False, False)

        self.result: ChangePasswordResult | None = None

        ttk.Label(self, text="Текущий мастер-пароль:").grid(
            row=0, column=0, sticky="w", padx=10, pady=(10, 0)
        )
        self.current_password = PasswordEntry(self)
        self.current_password.grid(row=1, column=0, sticky="ew", padx=10)

        ttk.Label(self, text="Новый мастер-пароль:").grid(
            row=2, column=0, sticky="w", padx=10, pady=(10, 0)
        )
        self.new_password = PasswordEntry(self)
        self.new_password.grid(row=3, column=0, sticky="ew", padx=10)

        ttk.Label(self, text="Подтверждение нового пароля:").grid(
            row=4, column=0, sticky="w", padx=10, pady=(10, 0)
        )
        self.confirm_password = PasswordEntry(self)
        self.confirm_password.grid(row=5, column=0, sticky="ew", padx=10)

        ttk.Label(
            self,
            text="Требования: минимум 12 символов, заглавная и строчная буквы, цифра и спецсимвол.",
        ).grid(row=6, column=0, sticky="w", padx=10, pady=(6, 0))

        buttons = ttk.Frame(self)
        buttons.grid(row=7, column=0, sticky="e", padx=10, pady=10)

        ttk.Button(buttons, text="Отмена", command=self._cancel).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(buttons, text="Сменить", command=self._submit).grid(row=0, column=1)

        self.columnconfigure(0, weight=1)

        self.transient(master)
        self.grab_set()

    def _submit(self) -> None:
        current = self.current_password.get()
        new = self.new_password.get()
        confirm = self.confirm_password.get()

        if not current:
            messagebox.showerror("Ошибка", "Введите текущий мастер-пароль.")
            return

        if len(new) < 12:
            messagebox.showerror("Ошибка", "Новый пароль должен содержать не менее 12 символов.")
            return

        if new != confirm:
            messagebox.showerror("Ошибка", "Новый пароль и подтверждение не совпадают.")
            return

        self.result = ChangePasswordResult(
            current_password=current,
            new_password=new,
        )
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()