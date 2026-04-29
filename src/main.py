from __future__ import annotations

from pathlib import Path
from tkinter import filedialog, messagebox

from src.core.config import load_config
from src.core.events import EventBus, UserLoggedIn, EntryAdded
from src.core.audit_logger import AuditLogger
from src.core.state_manager import StateManager
from src.core.crypto.auth_service import AuthService
from src.core.crypto.placeholder import AES256Placeholder
from src.database.db import Database
from src.database.repo import VaultRepository, VaultEntryInput
from src.database.settings_repo import SettingsRepository
from src.database.key_store_repo import KeyStoreRepository
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard
from src.gui.login_dialog import LoginDialog


def show_centered(window, width: int = 450, height: int = 340) -> None:
    window.update_idletasks()
    window.geometry(f"{width}x{height}+300+200")
    window.deiconify()
    window.lift()
    window.focus_force()
    window.attributes("-topmost", True)
    window.after(500, lambda: window.attributes("-topmost", False))


def choose_existing_or_new_db(default_path: Path) -> Path | None:
    answer = messagebox.askyesnocancel(
        "База данных",
        "Открыть существующую базу данных?\n\n"
        "Да — открыть существующую.\n"
        "Нет — создать новую.\n"
        "Отмена — выйти.",
    )

    if answer is None:
        return None

    if answer is True:
        path = filedialog.askopenfilename(
            title="Открыть базу данных CryptoSafe",
            filetypes=[("База данных SQLite", "*.db")],
        )
        if not path:
            return None
        return Path(path)

    path = filedialog.asksaveasfilename(
        title="Создать базу данных CryptoSafe",
        defaultextension=".db",
        initialfile=default_path.name,
        filetypes=[("База данных SQLite", "*.db")],
    )
    if not path:
        return None

    return Path(path)


def create_demo_entry_once(repo: VaultRepository, bus: EventBus) -> None:
    new_id = repo.add_entry(
        VaultEntryInput(
            title="Демонстрационная запись",
            username="пользователь",
            password="демо_пароль",
            url="https://example.com",
            notes="демонстрационные заметки",
            tags="демо",
        )
    )
    bus.publish(EntryAdded(entry_id=new_id, title="Демонстрационная запись"))


def main() -> None:
    cfg = load_config()

    app = MainWindow()

    db_path = choose_existing_or_new_db(cfg.db_path)
    if db_path is None:
        app.destroy()
        return

    db = Database(db_path)
    db.init_schema()

    key_store = KeyStoreRepository(db)
    auth_service = AuthService(key_store)

    if not auth_service.is_configured():
        wizard = SetupWizard(app)
        wizard.db_var.set(str(db_path))
        show_centered(wizard)

        app.wait_window(wizard)

        if wizard.result is None:
            app.destroy()
            return

        setup_result = auth_service.setup_master_password(wizard.result.master_password)

        if not setup_result.success:
            messagebox.showerror(
                "Ошибка мастер-пароля",
                "\n".join(setup_result.errors),
            )
            app.destroy()
            return

        login_result = auth_service.login(wizard.result.master_password)

        if not login_result.success:
            messagebox.showerror("Ошибка входа", login_result.message)
            app.destroy()
            return

    else:
        login_dialog = LoginDialog(app)
        show_centered(login_dialog, 420, 210)

        app.wait_window(login_dialog)

        if login_dialog.result is None:
            app.destroy()
            return

        login_result = auth_service.login(login_dialog.result.master_password)

        if not login_result.success:
            messagebox.showerror("Ошибка входа", login_result.message)
            app.destroy()
            return

    encryption_key = auth_service.get_encryption_key()

    if encryption_key is None:
        messagebox.showerror("Ошибка", "Ключ шифрования не был получен.")
        app.destroy()
        return

    crypto = AES256Placeholder()

    settings_repo = SettingsRepository(db, crypto, encryption_key)
    settings_repo.set_setting("clipboard_timeout_sec", str(cfg.clipboard_timeout_sec), encrypted=False)
    settings_repo.set_setting("auto_lock_idle_sec", str(cfg.auto_lock_idle_sec), encrypted=False)
    settings_repo.set_setting("theme", "light", encrypted=False)
    settings_repo.set_setting("language", "ru", encrypted=False)
    settings_repo.set_setting("argon2_time_cost", "3", encrypted=False)
    settings_repo.set_setting("argon2_memory_cost", "65536", encrypted=False)
    settings_repo.set_setting("argon2_parallelism", "4", encrypted=False)
    settings_repo.set_setting("pbkdf2_iterations", "100000", encrypted=False)

    state = StateManager()
    state.set_unlocked(True)

    bus = EventBus()
    audit = AuditLogger(db)

    bus.subscribe(UserLoggedIn, audit.on_login)
    bus.subscribe(EntryAdded, audit.on_entry_added)

    bus.publish(UserLoggedIn(user="локально"))

    repo = VaultRepository(db, crypto, encryption_key)

    try:
        create_demo_entry_once(repo, bus)
    except Exception:
        pass
    app.set_auth_service(auth_service)
    app.status_var.set(
        f"Статус: разблокировано | Таймер буфера обмена: {cfg.clipboard_timeout_sec} c"
    )

    app.protocol("WM_DELETE_WINDOW", lambda: (auth_service.logout(), app.destroy()))
    app.mainloop()


if __name__ == "__main__":
    main()