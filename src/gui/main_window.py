from __future__ import annotations

import re
import tkinter as tk
from collections import deque
from datetime import datetime
from difflib import SequenceMatcher
from tkinter import messagebox, ttk
from typing import Any

from src.core.clipboard.clipboard_monitor import ClipboardMonitor
from src.core.clipboard.clipboard_service import (
    ClipboardCleared,
    ClipboardCopied,
    ClipboardSecurityAlert,
    ClipboardService,
    ClipboardSettings,
    ClipboardStateChanged,
    ClipboardWarning,
)
from src.core.vault.password_generator import PasswordGenerator
from src.gui.change_password_dialog import ChangePasswordDialog
from src.gui.entry_dialog import EntryDialog
from src.gui.settings_dialog import SettingsDialog
from src.gui.sprint7_security_integration import Sprint7SecurityIntegration
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.widgets.vault_table import VaultTable


class MainWindow(tk.Tk):
    SEARCH_HISTORY_LIMIT = 10
    FUZZY_THRESHOLD = 0.72

    SEARCHABLE_FIELDS = (
        "title",
        "username",
        "url",
        "notes",
        "category",
        "tags",
    )

    FILTER_ALIASES = {
        "title": "title",
        "name": "title",
        "username": "username",
        "user": "username",
        "login": "username",
        "url": "url",
        "site": "url",
        "notes": "notes",
        "note": "notes",
        "category": "category",
        "cat": "category",
        "tag": "tags",
        "tags": "tags",
        "date_from": "date_from",
        "from": "date_from",
        "date_to": "date_to",
        "to": "date_to",
        "strength": "strength",
        "score": "strength",
    }

    def __init__(self):
        super().__init__()

        self.title("CryptoSafe Manager")
        self.geometry("1120x700")
        self.minsize(1000, 600)

        self.auth_service = None
        self.entry_manager = None
        self.key_manager = None
        self.audit_logger = None
        self.event_bus = None

        self.all_entries: list[dict[str, Any]] = []
        self.displayed_entries: list[dict[str, Any]] = []

        self.password_generator = PasswordGenerator()

        self.clipboard_settings = ClipboardSettings(
            auto_clear_seconds=30,
            notifications_enabled=True,
            warning_before_clear_seconds=5,
        )
        self.clipboard_service = ClipboardService(settings=self.clipboard_settings)
        self.clipboard_service.subscribe(self.on_clipboard_event)

        self.clipboard_monitor = ClipboardMonitor(
            platform_adapter=self.clipboard_service.platform_adapter,
            clipboard_service=self.clipboard_service,
            poll_interval_seconds=1.0,
        )

        try:
            self.clipboard_monitor.start()
        except Exception:
            pass

        self.passwords_visible_var = tk.BooleanVar(value=False)
        self.search_history: deque[str] = deque(maxlen=self.SEARCH_HISTORY_LIMIT)
        self.clipboard_status_var = tk.StringVar(value="Буфер обмена: пусто")
        self.status_var = tk.StringVar(value="Статус: заблокировано")

        self._build_menu()
        self._build_toolbar()
        self._build_table()
        self._build_status_bar()
        self._bind_hotkeys()

        self.protocol("WM_DELETE_WINDOW", self.secure_close)

        self.sprint7_security = Sprint7SecurityIntegration(
            lock_vault=self._sprint7_lock_vault,
            unlock_vault=self._sprint7_unlock_vault,
            clear_clipboard=self._sprint7_clear_clipboard,
            wipe_memory=self._sprint7_wipe_memory,
            close_sensitive_windows=self._sprint7_close_sensitive_windows,
            show_main_window=self._sprint7_show_main_window,
            open_settings=self._sprint7_open_settings,
            exit_application=self._sprint7_exit_application,
            quick_search=self._sprint7_quick_search,
            audit_log=self._sprint7_audit_log,
            auto_lock_timeout_seconds=300,
        )

        try:
            self.sprint7_security.start()
        except Exception:
            pass

        try:
            self.bind_all(
                "<Key>",
                lambda event: self.sprint7_security.record_keyboard_activity(),
            )
            self.bind_all(
                "<Button>",
                lambda event: self.sprint7_security.record_mouse_activity(),
            )
            self.bind_all(
                "<FocusIn>",
                lambda event: self.sprint7_security.record_focus_change(),
            )
            self.bind_all(
                "<Control-Shift-Escape>",
                lambda event: self.sprint7_security.activate_panic("hotkey"),
            )
        except Exception:
            pass

        self.after(1000, self.update_clipboard_status_loop)


    def set_auth_service(self, auth_service):
        self.auth_service = auth_service

    def set_entry_manager(self, entry_manager):
        self.entry_manager = entry_manager
        self.refresh_entries()

    def set_key_manager(self, key_manager):
        self.key_manager = key_manager

    def set_audit_logger(self, audit_logger):
        self.audit_logger = audit_logger

    def set_event_bus(self, event_bus):
        self.event_bus = event_bus


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
        file_menu.add_command(label="Выход", command=self.secure_close)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить", command=self.add_entry)
        edit_menu.add_command(label="Изменить", command=self.edit_entry)
        edit_menu.add_command(label="Удалить", command=self.delete_entry)
        edit_menu.add_separator()
        edit_menu.add_command(
            label="Показать/скрыть пароль выбранной записи",
            command=self.toggle_selected_passwords,
            accelerator="Ctrl+Shift+P",
        )
        edit_menu.add_separator()
        edit_menu.add_command(
            label="Копировать пароль",
            command=self.copy_selected_password,
            accelerator="Ctrl+Shift+C",
        )
        edit_menu.add_command(
            label="Копировать логин",
            command=self.copy_selected_username,
        )
        edit_menu.add_command(
            label="Копировать всё",
            command=self.copy_selected_all,
        )
        edit_menu.add_command(
            label="Очистить буфер обмена",
            command=self.clear_clipboard_manual,
        )
        edit_menu.add_separator()
        edit_menu.add_command(
            label="Предпросмотр буфера",
            command=self.show_clipboard_preview,
        )
        edit_menu.add_command(
            label="Показать содержимое буфера",
            command=self.reveal_clipboard_preview_with_auth,
        )

        security_menu = tk.Menu(menubar, tearoff=0)
        security_menu.add_command(
            label="Panic mode",
            command=lambda: self.sprint7_security.activate_panic("menu"),
            accelerator="Ctrl+Shift+Esc",
        )
        security_menu.add_command(
            label="Свернуть в трей",
            command=self._sprint7_minimize_to_tray,
        )
        security_menu.add_separator()
        security_menu.add_command(
            label="Профиль Standard",
            command=lambda: self._sprint7_apply_profile("standard"),
        )
        security_menu.add_command(
            label="Профиль Enhanced",
            command=lambda: self._sprint7_apply_profile("enhanced"),
        )
        security_menu.add_command(
            label="Профиль Paranoid",
            command=lambda: self._sprint7_apply_profile("paranoid"),
        )

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи", command=self.open_logs)
        view_menu.add_command(label="Настройки", command=self.open_settings)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.about)

        menubar.add_cascade(label="Файл", menu=file_menu)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        menubar.add_cascade(label="Безопасность", menu=security_menu)
        menubar.add_cascade(label="Вид", menu=view_menu)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.config(menu=menubar)

    def _build_toolbar(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=10, pady=8)

        ttk.Button(
            toolbar,
            text="Добавить",
            command=self.add_entry,
        ).pack(side="left")

        ttk.Button(
            toolbar,
            text="Изменить",
            command=self.edit_entry,
        ).pack(side="left", padx=(6, 0))

        ttk.Button(
            toolbar,
            text="Удалить",
            command=self.delete_entry,
        ).pack(side="left", padx=(6, 0))

        ttk.Separator(toolbar, orient="vertical").pack(
            side="left",
            fill="y",
            padx=10,
        )

        self.passwords_button = ttk.Checkbutton(
            toolbar,
            text="Показать пароли",
            variable=self.passwords_visible_var,
            command=self.toggle_global_passwords,
        )
        self.passwords_button.pack(side="left")

        ttk.Button(
            toolbar,
            text="👁 выбранные",
            command=self.toggle_selected_passwords,
        ).pack(side="left", padx=(6, 0))

        ttk.Separator(toolbar, orient="vertical").pack(
            side="left",
            fill="y",
            padx=10,
        )

        ttk.Button(
            toolbar,
            text="Копировать пароль",
            command=self.copy_selected_password,
        ).pack(side="left")

        ttk.Button(
            toolbar,
            text="Копировать логин",
            command=self.copy_selected_username,
        ).pack(side="left", padx=(6, 0))

        ttk.Button(
            toolbar,
            text="Очистить буфер",
            command=self.clear_clipboard_manual,
        ).pack(side="left", padx=(6, 0))

        ttk.Button(
            toolbar,
            text="Panic",
            command=lambda: self.sprint7_security.activate_panic("toolbar"),
        ).pack(side="left", padx=(6, 0))

        ttk.Button(
            toolbar,
            text="Предпросмотр",
            command=self.show_clipboard_preview,
        ).pack(side="left", padx=(6, 0))

        ttk.Label(toolbar, text="Поиск:").pack(side="left", padx=(20, 6))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.apply_search())

        self.search_combo = ttk.Combobox(
            toolbar,
            textvariable=self.search_var,
            width=36,
            values=[],
        )
        self.search_combo.pack(side="left")
        self.search_combo.bind("<<ComboboxSelected>>", lambda event: self.apply_search())
        self.search_combo.bind("<Return>", lambda event: self.remember_search_query())

        ttk.Button(
            toolbar,
            text="Очистить",
            command=self.clear_search,
        ).pack(side="left", padx=(6, 0))

        ttk.Button(
            toolbar,
            text="?",
            width=3,
            command=self.show_search_help,
        ).pack(side="left", padx=(6, 0))

    def _build_table(self):
        self.table = VaultTable(self)
        self.table.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Изменить", command=self.edit_entry)
        self.context_menu.add_command(label="Удалить", command=self.delete_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Показать/скрыть пароль",
            command=self.toggle_selected_passwords,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Копировать пароль",
            command=self.copy_selected_password,
        )
        self.context_menu.add_command(
            label="Копировать логин",
            command=self.copy_selected_username,
        )
        self.context_menu.add_command(
            label="Копировать всё",
            command=self.copy_selected_all,
        )
        self.context_menu.add_command(
            label="Предпросмотр буфера",
            command=self.show_clipboard_preview,
        )
        self.context_menu.add_command(
            label="Показать содержимое буфера",
            command=self.reveal_clipboard_preview_with_auth,
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Очистить буфер обмена",
            command=self.clear_clipboard_manual,
        )

        self.table.tree.bind("<Button-3>", self.show_context_menu)
        self.table.tree.bind("<Button-1>", self.on_table_left_click)

    def _build_status_bar(self):
        self.status_frame = ttk.Frame(self)
        self.status_frame.pack(fill="x", side="bottom", padx=10, pady=(0, 8))

        ttk.Label(
            self.status_frame,
            textvariable=self.status_var,
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

        ttk.Label(
            self.status_frame,
            textvariable=self.clipboard_status_var,
            anchor="e",
        ).pack(side="right")

    def _bind_hotkeys(self):
        self.bind_all(
            "<Control-Shift-P>",
            lambda event: self.toggle_selected_passwords(),
        )
        self.bind_all(
            "<Control-Shift-p>",
            lambda event: self.toggle_selected_passwords(),
        )
        self.bind_all(
            "<Control-Shift-C>",
            lambda event: self.copy_selected_password(),
        )
        self.bind_all(
            "<Control-Shift-c>",
            lambda event: self.copy_selected_password(),
        )


    def on_clipboard_event(self, event):
        if isinstance(event, ClipboardCopied):
            source_title = self.get_entry_title_by_id(event.source_entry_id)

            try:
                self.table.set_clipboard_marker(
                    entry_id=event.source_entry_id,
                    data_type=event.data_type,
                )
            except Exception:
                pass

            try:
                self.sprint7_security.set_clipboard_active(True)
            except Exception:
                pass

            if self.clipboard_settings.notifications_enabled:
                self.clipboard_status_var.set(
                    f"Буфер: скопировано {event.data_type}, "
                    f"очистка через {event.timeout_seconds} сек."
                )
                self.show_toast(
                    "Буфер обмена",
                    f"Скопировано: {event.data_type}\n"
                    f"Источник: {source_title or 'запись'}\n"
                    f"Автоочистка: {event.timeout_seconds} сек.",
                )

        elif isinstance(event, ClipboardWarning):
            if self.clipboard_settings.notifications_enabled:
                self.clipboard_status_var.set("Буфер: скоро будет очищен")
                self.show_toast(
                    "Предупреждение",
                    f"Буфер обмена будет очищен через {event.remaining_seconds} сек.",
                )

        elif isinstance(event, ClipboardCleared):
            try:
                self.table.set_clipboard_marker(None, None)
            except Exception:
                pass

            try:
                self.sprint7_security.set_clipboard_active(False)
            except Exception:
                pass

            if self.clipboard_settings.notifications_enabled:
                self.clipboard_status_var.set("Буфер обмена: очищен")
                self.show_toast(
                    "Буфер обмена",
                    "Буфер обмена очищен.",
                )

        elif isinstance(event, ClipboardSecurityAlert):
            messagebox.showwarning(
                "Безопасность буфера обмена",
                event.message,
            )

        elif isinstance(event, ClipboardStateChanged):
            self.update_clipboard_status()

    def update_clipboard_status_loop(self):
        self.update_clipboard_status()
        self.after(1000, self.update_clipboard_status_loop)

    def update_clipboard_status(self):
        try:
            status = self.clipboard_service.get_status()
        except Exception:
            self.clipboard_status_var.set("Буфер обмена: ошибка")
            return

        if not status.active:
            self.clipboard_status_var.set("Буфер обмена: пусто")
            return

        remaining = int(status.remaining_seconds)
        mode_text = "ephemeral" if status.ephemeral else "system"

        if remaining > 0:
            self.clipboard_status_var.set(
                f"Буфер: {status.data_type}, {mode_text}, "
                f"осталось {remaining} сек., {status.preview}"
            )
        else:
            self.clipboard_status_var.set(
                f"Буфер: {status.data_type}, {mode_text}, "
                f"без автоочистки, {status.preview}"
            )

    def get_single_selected_entry(self) -> dict[str, Any] | None:
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return None

        selected_ids = self.table.get_selected_ids()

        if not selected_ids:
            messagebox.showwarning("Выбор записи", "Выберите запись.")
            return None

        if len(selected_ids) > 1:
            messagebox.showwarning(
                "Выбор записи",
                "Для копирования выберите только одну запись.",
            )
            return None

        entry_id = selected_ids[0]

        try:
            return self.entry_manager.get_entry(entry_id)
        except Exception:
            messagebox.showerror(
                "Ошибка",
                "Не удалось открыть выбранную запись.",
            )
            return None

    def get_single_entry_by_id(self, entry_id: int) -> dict[str, Any] | None:
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return None

        try:
            return self.entry_manager.get_entry(entry_id)
        except Exception:
            messagebox.showerror(
                "Ошибка",
                "Не удалось открыть выбранную запись.",
            )
            return None

    def is_vault_unlocked(self) -> bool:
        if self.key_manager is None:
            return True

        if hasattr(self.key_manager, "is_unlocked"):
            try:
                return bool(self.key_manager.is_unlocked())
            except Exception:
                return True

        return True

    def copy_entry_field_to_clipboard(
        self,
        entry: dict[str, Any],
        field_name: str,
        data_type: str,
    ) -> None:
        data = str(entry.get(field_name, ""))

        try:
            if self.entry_manager is not None and hasattr(
                self.entry_manager,
                "request_clipboard_copy",
            ):
                self.entry_manager.request_clipboard_copy(
                    entry["id"],
                    field_name,
                )

            self.clipboard_service.copy_to_clipboard(
                data=data,
                data_type=data_type,
                source_entry_id=entry.get("id"),
                vault_unlocked=self.is_vault_unlocked(),
                never_copy=bool(entry.get("never_copy_to_clipboard", False)),
            )

        except Exception as exc:
            messagebox.showerror(
                "Буфер обмена",
                str(exc),
            )

    def copy_selected_password(self):
        entry = self.get_single_selected_entry()
        if entry is None:
            return

        self.copy_entry_field_to_clipboard(
            entry=entry,
            field_name="password",
            data_type="password",
        )

    def copy_selected_username(self):
        entry = self.get_single_selected_entry()
        if entry is None:
            return

        self.copy_entry_field_to_clipboard(
            entry=entry,
            field_name="username",
            data_type="username",
        )

    def copy_selected_all(self):
        entry = self.get_single_selected_entry()
        if entry is None:
            return

        text = (
            f"Title: {entry.get('title', '')}\n"
            f"Username: {entry.get('username', '')}\n"
            f"Password: {entry.get('password', '')}\n"
            f"URL: {entry.get('url', '')}"
        )

        try:
            self.clipboard_service.copy_to_clipboard(
                data=text,
                data_type="text",
                source_entry_id=entry.get("id"),
                vault_unlocked=self.is_vault_unlocked(),
                never_copy=bool(entry.get("never_copy_to_clipboard", False)),
            )
        except Exception as exc:
            messagebox.showerror(
                "Буфер обмена",
                str(exc),
            )

    def clear_clipboard_manual(self):
        try:
            self.clipboard_service.clear_clipboard(reason="manual")
        except Exception:
            messagebox.showwarning(
                "Буфер обмена",
                "Не удалось очистить буфер обмена.\nОчистите его вручную.",
            )

    def apply_clipboard_settings(self, settings: ClipboardSettings):
        self.clipboard_settings = settings
        self.clipboard_service.settings = settings
        self.clipboard_service.settings.validate()

        if hasattr(self, "clipboard_settings_store"):
            try:
                self.clipboard_settings_store.save(settings)
            except Exception:
                pass

        self.update_clipboard_status()

    def show_toast(self, title: str, message: str, duration_ms: int = 2500):
        try:
            toast = tk.Toplevel(self)
            toast.title(title)
            toast.resizable(False, False)
            toast.attributes("-topmost", True)

            frame = ttk.Frame(toast, padding=12)
            frame.pack(fill="both", expand=True)

            ttk.Label(
                frame,
                text=title,
                font=("Segoe UI", 10, "bold"),
            ).pack(anchor="w")

            ttk.Label(
                frame,
                text=message,
                wraplength=280,
            ).pack(anchor="w", pady=(4, 0))

            self.update_idletasks()

            x = self.winfo_rootx() + self.winfo_width() - 330
            y = self.winfo_rooty() + self.winfo_height() - 150
            toast.geometry(f"300x90+{x}+{y}")
            toast.after(duration_ms, toast.destroy)
        except Exception:
            pass

    def get_entry_title_by_id(self, entry_id) -> str:
        for entry in self.all_entries:
            if str(entry.get("id")) == str(entry_id):
                return str(entry.get("title", ""))

        return ""

    def show_clipboard_preview(self):
        status = self.clipboard_service.get_status()

        if not status.active:
            messagebox.showinfo(
                "Буфер обмена",
                "Буфер обмена пуст.",
            )
            return

        source_title = self.get_entry_title_by_id(status.source_entry_id)

        text = (
            f"Тип данных: {status.data_type}\n"
            f"Источник: {source_title or 'не указан'}\n"
            f"Предпросмотр: {status.preview}\n"
            f"Осталось секунд: {int(status.remaining_seconds)}"
        )

        messagebox.showinfo(
            "Предпросмотр буфера обмена",
            text,
        )

    def reveal_clipboard_preview_with_auth(self):
        status = self.clipboard_service.get_status()

        if not status.active:
            messagebox.showinfo(
                "Буфер обмена",
                "Буфер обмена пуст.",
            )
            return

        answer = messagebox.askyesno(
            "Подтверждение",
            "Показать полное содержимое буфера обмена?\n\n"
            "Делайте это только если рядом нет посторонних.",
        )

        if not answer:
            return

        plaintext = self.clipboard_service.get_current_plaintext_for_testing()

        messagebox.showinfo(
            "Полное содержимое буфера",
            plaintext,
        )

    # =========================
    # Table actions
    # =========================

    def on_table_left_click(self, event):
        action, entry_id = self.table.identify_action(event)

        if action is None or entry_id is None:
            return None

        self.table.tree.selection_set(str(entry_id))

        if action == self.table.ACTION_COPY_PASSWORD:
            entry = self.get_single_entry_by_id(entry_id)
            if entry is not None:
                self.copy_entry_field_to_clipboard(
                    entry=entry,
                    field_name="password",
                    data_type="password",
                )
            return "break"

        if action == self.table.ACTION_COPY_USERNAME:
            entry = self.get_single_entry_by_id(entry_id)
            if entry is not None:
                self.copy_entry_field_to_clipboard(
                    entry=entry,
                    field_name="username",
                    data_type="username",
                )
            return "break"

        return None

    def refresh_entries(self):
        if self.entry_manager is None:
            return

        try:
            self.all_entries = self.entry_manager.get_all_entries()
            self.apply_search(update_status=False)
            self.status_var.set(
                f"Статус: разблокировано | "
                f"Всего записей: {len(self.all_entries)} | "
                f"Показано: {len(self.displayed_entries)}"
            )

            try:
                self.sprint7_security.mark_unlocked()
            except Exception:
                pass

        except Exception:
            messagebox.showerror("Ошибка", "Не удалось загрузить записи.")

    def selected_entry_ids(self) -> list[int]:
        selected_ids = self.table.get_selected_ids()

        if not selected_ids:
            messagebox.showwarning(
                "Выбор записи",
                "Выберите одну или несколько записей.",
            )
            return []

        return selected_ids

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
        except Exception:
            messagebox.showerror(
                "Ошибка",
                "Не удалось сохранить запись.\nПроверьте данные формы.",
            )

    def edit_entry(self):
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return

        selected_ids = self.table.get_selected_ids()

        if not selected_ids:
            messagebox.showwarning("Выбор записи", "Выберите запись.")
            return

        if len(selected_ids) > 1:
            messagebox.showwarning(
                "Редактирование",
                "Для редактирования выберите только одну запись.",
            )
            return

        entry_id = selected_ids[0]

        try:
            current = self.entry_manager.get_entry(entry_id)
        except Exception:
            messagebox.showerror(
                "Ошибка",
                "Не удалось открыть выбранную запись.",
            )
            return

        dialog = EntryDialog(self, current)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        try:
            self.entry_manager.update_entry(entry_id, dialog.result)
            self.refresh_entries()
        except Exception:
            messagebox.showerror(
                "Ошибка",
                "Не удалось обновить запись.\nПроверьте данные формы.",
            )

    def delete_entry(self):
        if self.entry_manager is None:
            messagebox.showerror("Ошибка", "Хранилище не подключено.")
            return

        selected_ids = self.selected_entry_ids()

        if not selected_ids:
            return

        if len(selected_ids) == 1:
            text = "Удалить выбранную запись?"
        else:
            text = f"Удалить выбранные записи: {len(selected_ids)} шт.?"

        answer = messagebox.askyesno("Удаление", text)

        if not answer:
            return

        has_errors = False

        for entry_id in selected_ids:
            try:
                self.entry_manager.delete_entry(entry_id, soft_delete=True)
            except Exception:
                has_errors = True

        self.refresh_entries()

        if has_errors:
            messagebox.showerror(
                "Ошибка удаления",
                "Не удалось удалить некоторые выбранные записи.",
            )

    def toggle_global_passwords(self):
        visible = self.passwords_visible_var.get()
        self.table.set_global_password_visibility(visible)

    def toggle_selected_passwords(self):
        selected_ids = self.table.get_selected_ids()

        if not selected_ids:
            messagebox.showwarning(
                "Выбор записи",
                "Выберите запись для показа или скрытия пароля.",
            )
            return

        self.table.toggle_selected_password_visibility()

    def show_context_menu(self, event):
        row_id = self.table.tree.identify_row(event.y)

        if row_id:
            current_selection = set(self.table.tree.selection())

            if row_id not in current_selection:
                self.table.tree.selection_set(row_id)

            self.context_menu.tk_popup(event.x_root, event.y_root)


    def apply_search(self, update_status: bool = True):
        query = self.search_var.get().strip()

        if query:
            self.remember_search_query()

        if not query:
            self.displayed_entries = list(self.all_entries)
            self.table.load_entries(self.displayed_entries)
            self._update_status_after_search(update_status)
            return

        parsed = self.parse_search_query(query)

        filtered = []

        for entry in self.all_entries:
            if self.entry_matches_search(entry, parsed):
                filtered.append(entry)

        self.displayed_entries = filtered
        self.table.load_entries(self.displayed_entries)
        self._update_status_after_search(update_status)

    def _update_status_after_search(self, update_status: bool = True):
        if not update_status:
            return

        self.status_var.set(
            f"Статус: разблокировано | "
            f"Всего записей: {len(self.all_entries)} | "
            f"Показано: {len(self.displayed_entries)}"
        )

    def remember_search_query(self):
        query = self.search_var.get().strip()

        if not query:
            return

        if query in self.search_history:
            self.search_history.remove(query)

        self.search_history.appendleft(query)
        self.search_combo.configure(values=list(self.search_history))

    def clear_search(self):
        self.search_var.set("")
        self.displayed_entries = list(self.all_entries)
        self.table.load_entries(self.displayed_entries)
        self._update_status_after_search(True)

    def parse_search_query(self, query: str) -> dict[str, Any]:
        filters: dict[str, list[str]] = {}
        free_terms = []

        pattern = re.compile(r'(?P<field>[a-zA-Z_]+):(?P<value>"[^"]+"|\S+)')
        consumed_spans = []

        for match in pattern.finditer(query):
            raw_field = match.group("field").strip().lower()
            raw_value = match.group("value").strip()

            if raw_value.startswith('"') and raw_value.endswith('"'):
                raw_value = raw_value[1:-1]

            field = self.FILTER_ALIASES.get(raw_field)

            if field:
                filters.setdefault(field, []).append(raw_value)
                consumed_spans.append(match.span())

        remaining_parts = []
        last_index = 0

        for start, end in consumed_spans:
            if start > last_index:
                remaining_parts.append(query[last_index:start])
            last_index = end

        if last_index < len(query):
            remaining_parts.append(query[last_index:])

        remaining_text = " ".join(remaining_parts).strip()

        if remaining_text:
            free_terms = [
                part.strip()
                for part in re.findall(r'"[^"]+"|\S+', remaining_text)
                if part.strip()
            ]

            free_terms = [
                term[1:-1] if term.startswith('"') and term.endswith('"') else term
                for term in free_terms
            ]

        return {
            "raw": query,
            "filters": filters,
            "free_terms": free_terms,
        }

    def entry_matches_search(self, entry: dict[str, Any], parsed: dict[str, Any]) -> bool:
        filters = parsed["filters"]
        free_terms = parsed["free_terms"]

        if filters and not self.entry_matches_filters(entry, filters):
            return False

        if free_terms and not self.entry_matches_free_terms(entry, free_terms):
            return False

        return True

    def entry_matches_filters(
        self,
        entry: dict[str, Any],
        filters: dict[str, list[str]],
    ) -> bool:
        for field, values in filters.items():
            for value in values:
                if not self.entry_matches_single_filter(entry, field, value):
                    return False

        return True

    def entry_matches_single_filter(
        self,
        entry: dict[str, Any],
        field: str,
        value: str,
    ) -> bool:
        value = str(value or "").strip()

        if not value:
            return True

        if field in self.SEARCHABLE_FIELDS:
            field_value = str(entry.get(field, "")).lower()
            return self.text_matches(value.lower(), field_value)

        if field == "date_from":
            return self.entry_date_is_after_or_equal(entry, value)

        if field == "date_to":
            return self.entry_date_is_before_or_equal(entry, value)

        if field == "strength":
            return self.entry_password_strength_at_least(entry, value)

        return True

    def entry_matches_free_terms(self, entry: dict[str, Any], terms: list[str]) -> bool:
        searchable_text = self.build_searchable_text(entry)

        for term in terms:
            if not self.text_matches(term.lower(), searchable_text):
                return False

        return True

    def build_searchable_text(self, entry: dict[str, Any]) -> str:
        return " ".join(
            str(entry.get(field, ""))
            for field in self.SEARCHABLE_FIELDS
        ).lower()

    def text_matches(self, query: str, text: str) -> bool:
        query = str(query or "").lower().strip()
        text = str(text or "").lower().strip()

        if not query:
            return True

        if query in text:
            return True

        words = re.findall(r"[a-zA-Zа-яА-ЯёЁ0-9_@.\-]+", text)

        for word in words:
            if self.fuzzy_match(query, word):
                return True

        return False

    def fuzzy_match(self, query: str, candidate: str) -> bool:
        query = query.strip().lower()
        candidate = candidate.strip().lower()

        if not query or not candidate:
            return False

        if len(query) <= 2:
            return False

        ratio = SequenceMatcher(None, query, candidate).ratio()
        return ratio >= self.FUZZY_THRESHOLD

    def entry_date_is_after_or_equal(self, entry: dict[str, Any], date_value: str) -> bool:
        entry_date = self.parse_date(
            str(entry.get("updated_at", "") or entry.get("created_at", ""))
        )
        filter_date = self.parse_date(date_value)

        if entry_date is None or filter_date is None:
            return False

        return entry_date >= filter_date

    def entry_date_is_before_or_equal(self, entry: dict[str, Any], date_value: str) -> bool:
        entry_date = self.parse_date(
            str(entry.get("updated_at", "") or entry.get("created_at", ""))
        )
        filter_date = self.parse_date(date_value)

        if entry_date is None or filter_date is None:
            return False

        return entry_date <= filter_date

    def parse_date(self, value: str) -> datetime | None:
        value = str(value or "").strip()

        if not value:
            return None

        normalized = value.replace("Z", "+00:00")

        formats = [
            "%Y-%m-%d",
            "%Y-%m-%d %H:%M:%S",
            "%d.%m.%Y",
            "%d.%m.%Y %H:%M:%S",
        ]

        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            pass

        for fmt in formats:
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue

        return None

    def entry_password_strength_at_least(self, entry: dict[str, Any], value: str) -> bool:
        try:
            required_score = int(value)
        except ValueError:
            return False

        password = str(entry.get("password", ""))

        try:
            result = self.password_generator.analyze_strength(password)
            score = int(result.get("score", 0))
        except Exception:
            score = 0

        return score >= required_score

    def show_search_help(self):
        messagebox.showinfo(
            "Справка по поиску",
            (
                "Поиск поддерживает:\n\n"
                "github\n"
                "githab — нечёткий поиск\n"
                "title:\"работа\"\n"
                "username:\"user\"\n"
                "url:\"github\"\n"
                "category:\"учёба\"\n"
                "tag:\"python\"\n"
                "date_from:\"2026-01-01\"\n"
                "date_to:\"2026-12-31\"\n"
                "strength:3\n\n"
                "История поиска хранит последние 10 запросов."
            ),
        )


    def open_logs(self):
        win = tk.Toplevel(self)
        win.title("Журнал аудита")
        win.geometry("760x440")

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
            "CryptoSafe Manager — secure vault with clipboard, audit, import/export and Sprint 7 security hardening.",
        )

    def _stub(self):
        messagebox.showinfo(
            "Заглушка",
            "Это действие будет реализовано позже.",
        )

    def _sprint7_lock_vault(self) -> None:
        if hasattr(self, "_lock_vault"):
            try:
                self._lock_vault()
                return
            except Exception:
                pass

        if hasattr(self, "state_manager"):
            try:
                self.state_manager.lock()
            except Exception:
                pass

        try:
            self.secure_clear_decrypted_data()
            self.status_var.set("Статус: заблокировано")
        except Exception:
            pass

    def _sprint7_unlock_vault(self) -> None:
        if hasattr(self, "_unlock_vault"):
            try:
                self._unlock_vault()
            except Exception:
                pass

    def _sprint7_clear_clipboard(self) -> None:
        if hasattr(self, "clipboard_service"):
            try:
                self.clipboard_service.clear_clipboard(reason="panic")
                return
            except Exception:
                pass

        try:
            self.clipboard_clear()
        except Exception:
            pass

    def _sprint7_wipe_memory(self) -> None:
        for attr_name in ("all_entries", "displayed_entries", "current_entry", "selected_entry"):
            if hasattr(self, attr_name):
                try:
                    value = getattr(self, attr_name)

                    if isinstance(value, list):
                        value.clear()
                    else:
                        setattr(self, attr_name, None)
                except Exception:
                    pass

        try:
            self.secure_clear_decrypted_data()
        except Exception:
            pass

    def _sprint7_close_sensitive_windows(self) -> None:
        try:
            for child in self.winfo_children():
                try:
                    if child is not self:
                        child.destroy()
                except Exception:
                    pass
        except Exception:
            pass

    def _sprint7_show_main_window(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _sprint7_open_settings(self) -> None:
        if hasattr(self, "_open_settings"):
            try:
                self._open_settings()
                return
            except Exception:
                pass

        if hasattr(self, "open_settings"):
            try:
                self.open_settings()
            except Exception:
                pass

    def _sprint7_exit_application(self) -> None:
        try:
            if hasattr(self, "sprint7_security"):
                self.sprint7_security.stop()
        except Exception:
            pass

        try:
            self.destroy()
        except Exception:
            pass

    def _sprint7_quick_search(self, query: str) -> list[dict]:
        entries = getattr(self, "all_entries", [])

        if not isinstance(entries, list):
            return []

        if not query:
            return entries[:10]

        result = []
        query_lower = query.lower()

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            title = str(entry.get("title", "")).lower()
            username = str(entry.get("username", "")).lower()
            url = str(entry.get("url", "")).lower()

            if query_lower in title or query_lower in username or query_lower in url:
                result.append(entry)

            if len(result) >= 10:
                break

        return result

    def _sprint7_audit_log(self, event_type: str, details: dict) -> None:
        if hasattr(self, "audit_logger") and self.audit_logger is not None:
            try:
                self.audit_logger.log_event(event_type, details)
                return
            except Exception:
                pass

        if hasattr(self, "event_bus") and self.event_bus is not None:
            try:
                self.event_bus.publish(event_type, details)
                return
            except Exception:
                pass

    def _sprint7_minimize_to_tray(self) -> None:
        try:
            self.sprint7_security.minimize_to_tray()
            self.withdraw()
        except Exception:
            pass

    def _sprint7_apply_profile(self, profile_name: str) -> None:
        try:
            profile = self.sprint7_security.apply_security_profile(profile_name)
            messagebox.showinfo(
                "Профиль безопасности",
                f"Применён профиль: {profile.name.value}",
            )
        except Exception as exc:
            messagebox.showerror(
                "Профиль безопасности",
                f"Не удалось применить профиль: {exc}",
            )

    # =========================
    # Secure close
    # =========================

    def secure_clear_decrypted_data(self):
        try:
            self.all_entries.clear()
        except Exception:
            self.all_entries = []

        try:
            self.displayed_entries.clear()
        except Exception:
            self.displayed_entries = []

        try:
            self.table.secure_clear()
        except Exception:
            pass

        try:
            self.passwords_visible_var.set(False)
        except Exception:
            pass

    def secure_close(self):
        try:
            if hasattr(self, "sprint7_security"):
                self.sprint7_security.stop()
        except Exception:
            pass

        self.secure_clear_decrypted_data()

        try:
            self.clipboard_service.close()
        except Exception:
            pass

        try:
            self.clipboard_monitor.stop()
        except Exception:
            pass

        try:
            if self.key_manager is not None:
                self.key_manager.clear_encryption_key()
        except Exception:
            pass

        try:
            if self.entry_manager is not None and hasattr(self.entry_manager, "close"):
                self.entry_manager.close()
        except Exception:
            pass

        self.destroy()