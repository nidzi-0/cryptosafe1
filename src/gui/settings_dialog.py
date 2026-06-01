from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.core.clipboard.clipboard_service import (
    ClipboardSecurityLevel,
    ClipboardSettings,
)


class SettingsDialog(tk.Toplevel):
    PRESETS = {
        "standard": {
            "timeout": 30,
            "notifications": True,
            "security_level": ClipboardSecurityLevel.BASIC,
            "block_suspicious": False,
        },
        "secure": {
            "timeout": 15,
            "notifications": True,
            "security_level": ClipboardSecurityLevel.ADVANCED,
            "block_suspicious": False,
        },
        "public": {
            "timeout": 5,
            "notifications": True,
            "security_level": ClipboardSecurityLevel.PARANOID,
            "block_suspicious": True,
        },
    }

    def __init__(self, parent):
        super().__init__(parent)

        self.parent = parent

        self.title("Настройки")
        self.geometry("460x420")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        current_settings = getattr(parent, "clipboard_settings", ClipboardSettings())

        timeout = current_settings.auto_clear_seconds

        self.never_auto_clear_var = tk.BooleanVar(value=timeout is None)
        self.timeout_var = tk.IntVar(value=timeout if timeout is not None else 30)
        self.notifications_var = tk.BooleanVar(value=current_settings.notifications_enabled)
        self.security_level_var = tk.StringVar(value=current_settings.security_level.value)
        self.block_suspicious_var = tk.BooleanVar(value=current_settings.block_on_suspicious_activity)

        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _build_ui(self):
        main = ttk.Frame(self, padding=18)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="Настройки буфера обмена",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        preset_frame = ttk.LabelFrame(main, text="Профили")
        preset_frame.pack(fill="x", pady=(0, 12))

        ttk.Button(
            preset_frame,
            text="Standard",
            command=lambda: self.apply_preset("standard"),
        ).pack(side="left", padx=6, pady=8)

        ttk.Button(
            preset_frame,
            text="Secure",
            command=lambda: self.apply_preset("secure"),
        ).pack(side="left", padx=6, pady=8)

        ttk.Button(
            preset_frame,
            text="Public Computer",
            command=lambda: self.apply_preset("public"),
        ).pack(side="left", padx=6, pady=8)

        timeout_frame = ttk.LabelFrame(main, text="Auto-clear")
        timeout_frame.pack(fill="x", pady=(0, 12))

        row = ttk.Frame(timeout_frame)
        row.pack(fill="x", padx=8, pady=8)

        ttk.Label(row, text="Очистить через:").pack(side="left")

        ttk.Spinbox(
            row,
            from_=5,
            to=300,
            textvariable=self.timeout_var,
            width=8,
        ).pack(side="left", padx=(8, 4))

        ttk.Label(row, text="секунд").pack(side="left")

        ttk.Checkbutton(
            timeout_frame,
            text="Никогда не очищать автоматически (не рекомендуется)",
            variable=self.never_auto_clear_var,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        security_frame = ttk.LabelFrame(main, text="Безопасность")
        security_frame.pack(fill="x", pady=(0, 12))

        ttk.Label(security_frame, text="Уровень безопасности:").pack(anchor="w", padx=8, pady=(8, 4))

        ttk.Combobox(
            security_frame,
            textvariable=self.security_level_var,
            values=[
                ClipboardSecurityLevel.BASIC.value,
                ClipboardSecurityLevel.ADVANCED.value,
                ClipboardSecurityLevel.PARANOID.value,
            ],
            state="readonly",
            width=20,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        ttk.Checkbutton(
            security_frame,
            text="Блокировать будущие копирования при подозрительной активности",
            variable=self.block_suspicious_var,
        ).pack(anchor="w", padx=8, pady=(0, 8))

        notification_frame = ttk.LabelFrame(main, text="Уведомления")
        notification_frame.pack(fill="x", pady=(0, 12))

        ttk.Checkbutton(
            notification_frame,
            text="Показывать уведомления clipboard",
            variable=self.notifications_var,
        ).pack(anchor="w", padx=8, pady=8)

        button_frame = ttk.Frame(main)
        button_frame.pack(fill="x", pady=(10, 0))

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

    def apply_preset(self, name: str):
        preset = self.PRESETS[name]

        self.timeout_var.set(preset["timeout"])
        self.never_auto_clear_var.set(False)
        self.notifications_var.set(preset["notifications"])
        self.security_level_var.set(preset["security_level"].value)
        self.block_suspicious_var.set(preset["block_suspicious"])

    def save(self):
        try:
            if self.never_auto_clear_var.get():
                timeout = None
            else:
                timeout = int(self.timeout_var.get())

            settings = ClipboardSettings(
                auto_clear_seconds=timeout,
                notifications_enabled=self.notifications_var.get(),
                warning_before_clear_seconds=5,
                security_level=ClipboardSecurityLevel(self.security_level_var.get()),
                block_on_suspicious_activity=self.block_suspicious_var.get(),
            )

            settings.validate()
        except Exception as exc:
            messagebox.showerror(
                "Ошибка настроек",
                str(exc),
                parent=self,
            )
            return

        if hasattr(self.parent, "apply_clipboard_settings"):
            self.parent.apply_clipboard_settings(settings)

        self.destroy()