from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.title("Настройки")
        self.geometry("380x220")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=18)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(
            main_frame,
            text="Настройки CryptoSafe Manager",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        ttk.Label(
            main_frame,
            text=(
                "В Sprint 3 окно настроек является заготовкой.\n"
                "В следующих спринтах сюда можно добавить:\n"
                "- автозакрытие хранилища;\n"
                "- параметры генерации паролей;\n"
                "- настройки резервного копирования."
            ),
            justify="left",
        ).pack(anchor="w", pady=(0, 18))

        ttk.Button(
            main_frame,
            text="Закрыть",
            command=self.destroy,
        ).pack(anchor="e")