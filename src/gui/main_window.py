from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer
from src.gui.settings_dialog import SettingsDialog
from src.gui.change_password_dialog import ChangePasswordDialog


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager")
        self.geometry("760x440")

        self.auth_service = None

        self._build_menu()

        self.table = SecureTable(self)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)
        self.table.load_test_data()

        self.status_var = tk.StringVar(value="Статус: заблокировано | Таймер буфера обмена: --")
        self.status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        self.status.pack(fill="x", side="bottom", padx=10, pady=(0, 8))

    def set_auth_service(self, auth_service):
        self.auth_service = auth_service

    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Создать", command=self._stub)
        file_menu.add_command(label="Открыть", command=self._stub)
        file_menu.add_command(label="Резервная копия", command=self._stub)
        file_menu.add_separator()
        file_menu.add_command(label="Сменить мастер-пароль", command=self.change_master_password)
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
        win.title("Журнал аудита")
        AuditLogViewer(win).pack(fill="both", expand=True, padx=10, pady=10)

    def _stub_settings(self):
        SettingsDialog(self)

    def change_master_password(self):
        if self.auth_service is None:
            messagebox.showerror("Ошибка", "Сервис аутентификации не подключён.")
            return

        dialog = ChangePasswordDialog(self)
        dialog.geometry("500x300+320+220")
        dialog.lift()
        dialog.focus_force()

        self.wait_window(dialog)

        if dialog.result is None:
            return

        result = self.auth_service.change_master_password(
            dialog.result.current_password,
            dialog.result.new_password,
        )

        if not result.success:
            messagebox.showerror("Ошибка смены пароля", "\n".join(result.errors))
            return

        messagebox.showinfo("Готово", "Мастер-пароль успешно изменён. Выполните вход заново.")
        self.status_var.set("Статус: заблокировано | Мастер-пароль изменён")

    def about(self):
        messagebox.showinfo("О программе", "CryptoSafe Manager — Спринт 2: мастер-пароль и управление ключами")

    def _stub(self):
        messagebox.showinfo("Заглушка", "Это действие будет реализовано в следующих этапах проекта.")