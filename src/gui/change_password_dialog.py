from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import customtkinter as ctk


class ChangePasswordDialog(ctk.CTkToplevel):
    def __init__(self, master, auth_service):
        super().__init__(master)

        self.auth_service = auth_service

        self.title("Смена мастер-пароля")
        self.geometry("500x420")
        self.resizable(False, False)

        self.pause_event = threading.Event()
        self.pause_event.set()

        self.stop_requested = False
        self.worker_thread = None

        self.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            self,
            text="Смена мастер-пароля",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        title.pack(pady=(20, 15))

        self.current_entry = ctk.CTkEntry(
            self,
            placeholder_text="Текущий пароль",
            show="*",
            width=320,
        )
        self.current_entry.pack(pady=10)

        self.new_entry = ctk.CTkEntry(
            self,
            placeholder_text="Новый пароль",
            show="*",
            width=320,
        )
        self.new_entry.pack(pady=10)

        self.confirm_entry = ctk.CTkEntry(
            self,
            placeholder_text="Подтверждение нового пароля",
            show="*",
            width=320,
        )
        self.confirm_entry.pack(pady=10)

        self.status_label = ctk.CTkLabel(
            self,
            text="",
            font=ctk.CTkFont(size=14),
        )
        self.status_label.pack(pady=(10, 5))

        self.progress = ttk.Progressbar(
            self,
            orient="horizontal",
            mode="determinate",
            length=320,
            maximum=100,
        )
        self.progress.pack(pady=10)

        buttons_frame = ctk.CTkFrame(self, fg_color="transparent")
        buttons_frame.pack(pady=15)

        self.start_button = ctk.CTkButton(
            buttons_frame,
            text="Начать",
            command=self.start_change_password,
            width=110,
        )
        self.start_button.grid(row=0, column=0, padx=5)

        self.pause_button = ctk.CTkButton(
            buttons_frame,
            text="Пауза",
            command=self.pause_process,
            width=110,
        )
        self.pause_button.grid(row=0, column=1, padx=5)

        self.resume_button = ctk.CTkButton(
            buttons_frame,
            text="Продолжить",
            command=self.resume_process,
            width=110,
        )
        self.resume_button.grid(row=0, column=2, padx=5)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def start_change_password(self):
        current_password = self.current_entry.get()
        new_password = self.new_entry.get()
        confirm_password = self.confirm_entry.get()

        if new_password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return

        self.start_button.configure(state="disabled")
        self.stop_requested = False

        self.worker_thread = threading.Thread(
            target=self.change_password_worker,
            args=(current_password, new_password),
            daemon=True,
        )
        self.worker_thread.start()

    def change_password_worker(self, current_password: str, new_password: str):
        try:
            self.set_status("Проверка пароля...")

            for i in range(0, 21, 5):
                if self.stop_requested:
                    return

                self.pause_event.wait()
                self.set_progress(i)
                time.sleep(0.15)

            self.set_status("Формирование новых ключей...")

            for i in range(25, 46, 5):
                if self.stop_requested:
                    return

                self.pause_event.wait()
                self.set_progress(i)
                time.sleep(0.15)

            self.set_status("Перешифрование хранилища...")

            for i in range(50, 91, 5):
                if self.stop_requested:
                    return

                self.pause_event.wait()
                self.set_progress(i)
                time.sleep(0.2)

            result = self.auth_service.change_master_password(
                current_password,
                new_password,
            )

            if not result.success:
                self.after(
                    0,
                    lambda: messagebox.showerror(
                        "Ошибка",
                        "\n".join(result.errors),
                    ),
                )

                self.after(
                    0,
                    lambda: self.start_button.configure(state="normal"),
                )

                return

            self.set_progress(100)
            self.set_status("Смена пароля завершена")

            self.after(
                0,
                lambda: messagebox.showinfo(
                    "Успех",
                    "Мастер-пароль успешно изменён",
                ),
            )

        except Exception as e:
            self.after(
                0,
                lambda: messagebox.showerror(
                    "Ошибка",
                    str(e),
                ),
            )

        finally:
            self.after(
                0,
                lambda: self.start_button.configure(state="normal"),
            )

    def pause_process(self):
        self.pause_event.clear()
        self.set_status("Процесс приостановлен")

    def resume_process(self):
        self.pause_event.set()
        self.set_status("Процесс продолжен")

    def set_progress(self, value: int):
        self.after(0, lambda: self.progress.configure(value=value))

    def set_status(self, text: str):
        self.after(0, lambda: self.status_label.configure(text=text))

    def on_close(self):
        self.stop_requested = True
        self.pause_event.set()
        self.destroy()