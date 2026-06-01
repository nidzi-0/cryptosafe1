from __future__ import annotations

import sys
import traceback
from pathlib import Path
from tkinter import messagebox

from src.core.crypto.auth_service import AuthService
from src.core.crypto.key_manager import CachedKeyManager
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.vault.entry_manager import EntryManager
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cryptosafe_dev.db"


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def show_fatal_error(title: str, exc: Exception) -> None:
    error_text = "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )

    print(error_text, file=sys.stderr)

    messagebox.showerror(
        title,
        f"{exc}\n\nПодробности ошибки выведены в консоль.",
    )


def get_master_key_from_dialog_result(result) -> bytes | None:
    if result is None:
        return None

    if isinstance(result, bytes):
        return result

    if isinstance(result, dict):
        master_key = result.get("master_key")

        if isinstance(master_key, bytes):
            return master_key

    return None


def get_auth_service_from_dialog_result(result) -> AuthService | None:
    if isinstance(result, dict):
        auth_service = result.get("auth_service")

        if isinstance(auth_service, AuthService):
            return auth_service

    return None


def run_auth_dialog(root: MainWindow) -> tuple[bytes | None, AuthService | None]:
    print("[INFO] Открываю окно входа / регистрации...")

    dialog = SetupWizard(root)

    root.wait_window(dialog)

    print("[INFO] Окно входа / регистрации закрыто.")

    result = getattr(dialog, "result", None)

    if result is None:
        print("[INFO] Пользователь отменил вход.")
        return None, None

    master_key = get_master_key_from_dialog_result(result)
    auth_service = get_auth_service_from_dialog_result(result)

    if master_key is None:
        raise RuntimeError(
            "SetupWizard завершился, но не вернул master_key. "
            "Проверь, что self.result содержит {'master_key': master_key}."
        )

    if auth_service is None:
        raise RuntimeError(
            "SetupWizard завершился, но не вернул auth_service. "
            "Проверь, что self.result содержит {'auth_service': auth_service}."
        )

    return master_key, auth_service


def connect_vault_services(
    root: MainWindow,
    auth_service: AuthService,
    master_key: bytes,
) -> None:
    print("[INFO] Создаю CachedKeyManager...")

    key_manager = CachedKeyManager(master_key)

    print("[INFO] Создаю AESGCMEncryptionService через KeyManager...")

    encryption_service = AESGCMEncryptionService(key_manager)

    print("[INFO] Создаю EntryManager...")

    entry_manager = EntryManager(
        db_path=DB_PATH,
        encryption_service=encryption_service,
    )

    print("[INFO] Подключаю сервисы к главному окну...")

    root.key_manager = key_manager
    root.set_auth_service(auth_service)
    root.set_entry_manager(entry_manager)


def main() -> None:
    ensure_data_dir()

    print("[INFO] CryptoSafe Manager запускается...")
    print(f"[INFO] BASE_DIR = {BASE_DIR}")
    print(f"[INFO] DB_PATH = {DB_PATH}")

    root = MainWindow()

    root.withdraw()

    try:
        master_key, auth_service = run_auth_dialog(root)

        if master_key is None or auth_service is None:
            print("[INFO] Вход отменён. Приложение закрывается.")
            root.destroy()
            return

        connect_vault_services(
            root=root,
            auth_service=auth_service,
            master_key=master_key,
        )

        print("[INFO] Главное окно запущено.")

        root.deiconify()
        root.lift()
        root.focus_force()
        root.mainloop()

    except Exception as exc:
        show_fatal_error("Критическая ошибка CryptoSafe Manager", exc)
        root.destroy()


if __name__ == "__main__":
    main()