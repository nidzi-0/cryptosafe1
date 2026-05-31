from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, parent, auth_service):
        super().__init__(parent)

        self.parent = parent
        self.auth_service = auth_service

        self.title("Сменить мастер-пароль")
        self.geometry("420x300")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self.old_password_var = tk.StringVar()
        self.new_password_var = tk.StringVar()
        self.repeat_password_var = tk.StringVar()

        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self.destroy)

        self.after(100, self.old_password_entry.focus_set)

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=18)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(
            main_frame,
            text="Смена мастер-пароля",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        ttk.Label(main_frame, text="Старый мастер-пароль:").pack(anchor="w")

        self.old_password_entry = ttk.Entry(
            main_frame,
            textvariable=self.old_password_var,
            show="*",
        )
        self.old_password_entry.pack(fill="x", pady=(4, 10))

        ttk.Label(main_frame, text="Новый мастер-пароль:").pack(anchor="w")

        ttk.Entry(
            main_frame,
            textvariable=self.new_password_var,
            show="*",
        ).pack(fill="x", pady=(4, 10))

        ttk.Label(main_frame, text="Повторите новый пароль:").pack(anchor="w")

        ttk.Entry(
            main_frame,
            textvariable=self.repeat_password_var,
            show="*",
        ).pack(fill="x", pady=(4, 14))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")

        ttk.Button(
            button_frame,
            text="Сохранить",
            command=self.save,
        ).pack(side="right")

        ttk.Button(
            button_frame,
            text="Отмена",
            command=self.destroy,
        ).pack(side="right", padx=(0, 8))

    def save(self):
        old_password = self.old_password_var.get()
        new_password = self.new_password_var.get()
        repeat_password = self.repeat_password_var.get()

        if not old_password:
            messagebox.showwarning(
                "Проверка данных",
                "Введите старый мастер-пароль.",
                parent=self,
            )
            return

        if not new_password:
            messagebox.showwarning(
                "Проверка данных",
                "Введите новый мастер-пароль.",
                parent=self,
            )
            return

        if len(new_password) < 8:
            messagebox.showwarning(
                "Проверка данных",
                "Новый мастер-пароль должен содержать минимум 8 символов.",
                parent=self,
            )
            return

        if new_password != repeat_password:
            messagebox.showwarning(
                "Проверка данных",
                "Новые мастер-пароли не совпадают.",
                parent=self,
            )
            return

        try:
            self.auth_service.change_master_password(
                old_password=old_password,
                new_password=new_password,
            )
        except Exception as exc:
            messagebox.showerror(
                "Ошибка",
                str(exc),
                parent=self,
            )
            return

        messagebox.showinfo(
            "Готово",
            "Мастер-пароль изменён.",
            parent=self,
        )

        self.destroy()