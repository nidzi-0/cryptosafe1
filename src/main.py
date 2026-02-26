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


def main() -> None:
    cfg = load_config()

    app = MainWindow()
    app.withdraw()

    wizard = SetupWizard(app)
    app.wait_window(wizard)

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
            title="Demo Entry",
            username="demo",
            password="demo_password",
            url="https://example.com",
            notes="demo notes",
            tags="demo",
        )
    )
    bus.publish(EntryAdded(entry_id=new_id, title="Demo Entry"))

    app.deiconify()
    app.status_var.set(f"Status: unlocked | Clipboard timer: {cfg.clipboard_timeout_sec}s (placeholder)")
    app.mainloop()


if __name__ == "__main__":
    main()