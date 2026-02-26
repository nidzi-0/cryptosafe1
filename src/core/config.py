from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    env: str
    db_path: Path
    clipboard_timeout_sec: int = 30
    auto_lock_idle_sec: int = 0


def load_config() -> AppConfig:
    env = os.getenv("CRYPTOSAFE_ENV", "dev").strip() or "dev"
    db_path_str = os.getenv("CRYPTOSAFE_DB", "").strip()

    if db_path_str:
        db_path = Path(db_path_str)
    else:
        db_path = Path.cwd() / "data" / f"vault_{env}.db"

    return AppConfig(env=env, db_path=db_path)