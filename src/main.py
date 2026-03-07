from __future__ import annotations

from src.core.config import load_config
from src.core.events import EventBus, UserLoggedIn, EntryAdded
from src.core.audit_logger import AuditLogger
from src.core.key_manager import KeyManager, generate_salt, KeyDerivationParams
from src.core.crypto.placeholder import AES256Placeholder
from src.core.state_manager import StateManager
from src.database.db import Database
from src.database.repo import VaultRepository, VaultEntryInput
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard

print("ШАГ 1: запуск")

def main() -> None:
    cfg = load_config()
    app = MainWindow()
    app.deiconify()
    app.lift()
    app.focus_force()

    wizard = SetupWizard(app)

    app.after(100, lambda: print("Окно мастера существует?", wizard.winfo_exists()))
    app.after(200, wizard.lift)
    app.after(300, wizard.focus_force)

    app.mainloop()
    return

    if wizard.result is None:
        app.destroy()
        return

    db = Database(wizard.result.db_path)
    db.init_schema()

    km = KeyManager()
    salt = generate_salt(16)
    key = km.derive_key(wizard.result.master_password, salt, KeyDerivationParams())
    crypto = AES256Placeholder()

    state = StateManager()
    state.set_unlocked(True)

    bus = EventBus()
    audit = AuditLogger(db)

    bus.subscribe(UserLoggedIn, audit.on_login)
    bus.subscribe(EntryAdded, audit.on_entry_added)

    bus.publish(UserLoggedIn(user="local"))

    repo = VaultRepository(db, crypto, key)
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

    app.deiconify()
    app.status_var.set(f"Статус: разблокировано | Таймер буфера обмена: {cfg.clipboard_timeout_sec} c (заглушка)")
    app.mainloop()


if __name__ == "__main__":
    main()