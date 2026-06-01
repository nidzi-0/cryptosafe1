from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from src.core.crypto.auth_service import (
    AuthService,
    AuthServiceError,
    InvalidMasterPasswordError,
)


BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cryptosafe_dev.db"


class SetupWizard(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)

        self.parent = parent
        self.result = None

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.auth_service = AuthService(DB_PATH)

        self.password_var = tk.StringVar()
        self.password_repeat_var = tk.StringVar()

        self.is_setup_mode = not self.auth_service.has_master_password()

        self.title("CryptoSafe Manager — вход")
        self.geometry("430x330")
        self.resizable(False, False)

        self.grab_set()

        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        self.update_idletasks()
        self.deiconify()
        self.lift()
        self.focus_force()
        self.attributes("-topmost", True)
        self.after(1000, lambda: self.attributes("-topmost", False))
        self.after(100, self.password_entry.focus_set)

        self._center_window()

    def _center_window(self):
        self.update_idletasks()

        width = self.winfo_width()
        height = self.winfo_height()

        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        x = int((screen_width - width) / 2)
        y = int((screen_height - height) / 2)

        self.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill="both", expand=True)

        if self.is_setup_mode:
            title = "Первичная настройка хранилища"
            description = (
                "Создайте мастер-пароль. Он будет использоваться "
                "для входа и шифрования записей."
            )
            button_text = "Создать хранилище"
        else:
            title = "Вход в хранилище"
            description = "Введите мастер-пароль для разблокировки хранилища."
            button_text = "Войти"

        ttk.Label(
            main_frame,
            text=title,
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(
            main_frame,
            text=description,
            wraplength=370,
        ).pack(anchor="w", pady=(0, 16))

        ttk.Label(
            main_frame,
            text="Мастер-пароль:",
        ).pack(anchor="w")

        self.password_entry = ttk.Entry(
            main_frame,
            textvariable=self.password_var,
            show="*",
            width=40,
        )
        self.password_entry.pack(fill="x", pady=(4, 10))

        if self.is_setup_mode:
            ttk.Label(
                main_frame,
                text="Повторите мастер-пароль:",
            ).pack(anchor="w")

            self.password_repeat_entry = ttk.Entry(
                main_frame,
                textvariable=self.password_repeat_var,
                show="*",
                width=40,
            )
            self.password_repeat_entry.pack(fill="x", pady=(4, 10))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(16, 0))

        ttk.Button(
            button_frame,
            text=button_text,
            command=self.submit,
        ).pack(side="right")

        ttk.Button(
            button_frame,
            text="Отмена",
            command=self.cancel,
        ).pack(side="right", padx=(0, 8))

        self.bind("<Return>", lambda event: self.submit())
        self.bind("<Escape>", lambda event: self.cancel())

    def submit(self):
        password = self.password_var.get()

        if not password:
            messagebox.showwarning(
                "Проверка данных",
                "Введите мастер-пароль.",
                parent=self,
            )
            return

        if self.is_setup_mode:
            self._submit_setup(password)
        else:
            self._submit_login(password)

    def _submit_setup(self, password: str):
        password_repeat = self.password_repeat_var.get()

        if password != password_repeat:
            messagebox.showwarning(
                "Проверка данных",
                "Мастер-пароли не совпадают.",
                parent=self,
            )
            return

        if len(password) < 8:
            messagebox.showwarning(
                "Проверка данных",
                "Мастер-пароль должен содержать минимум 8 символов.",
                parent=self,
            )
            return

        try:
            master_key = self.auth_service.create_master_password(password)
        except AuthServiceError as exc:
            messagebox.showerror(
                "Ошибка",
                str(exc),
                parent=self,
            )
            return
        except Exception as exc:
            messagebox.showerror(
                "Ошибка",
                f"Не удалось создать мастер-пароль:\n{exc}",
                parent=self,
            )
            return

        self.result = {
            "master_key": master_key,
            "auth_service": self.auth_service,
        }

        self.destroy()

    def _submit_login(self, password: str):
        try:
            master_key = self.auth_service.unlock_with_password(password)
        except InvalidMasterPasswordError:
            messagebox.showerror(
                "Ошибка входа",
                "Неверный мастер-пароль.",
                parent=self,
            )
            return
        except AuthServiceError as exc:
            messagebox.showerror(
                "Ошибка",
                str(exc),
                parent=self,
            )
            return
        except Exception as exc:
            messagebox.showerror(
                "Ошибка",
                f"Не удалось войти в хранилище:\n{exc}",
                parent=self,
            )
            return

        self.result = {
            "master_key": master_key,
            "auth_service": self.auth_service,
        }

        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()