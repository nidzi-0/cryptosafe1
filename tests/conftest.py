from __future__ import annotations

import pytest
from pathlib import Path
from src.database.db import Database


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Database:
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    db.init_schema()
    return db