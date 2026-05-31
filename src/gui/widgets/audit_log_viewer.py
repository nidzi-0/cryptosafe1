from __future__ import annotations

import sqlite3
from pathlib import Path
from tkinter import ttk


BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cryptosafe_dev.db"


class AuditLogViewer(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.tree = None

        self._build_ui()
        self.load_logs()

    def _build_ui(self):
        columns = (
            "created_at",
            "action",
            "details",
        )

        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.tree.heading("created_at", text="Дата и время")
        self.tree.heading("action", text="Действие")
        self.tree.heading("details", text="Описание")

        self.tree.column("created_at", width=180, anchor="w")
        self.tree.column("action", width=180, anchor="w")
        self.tree.column("details", width=300, anchor="w")

        y_scrollbar = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.tree.yview,
        )

        self.tree.configure(yscrollcommand=y_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def _connect(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def load_logs(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT created_at, action, details
                    FROM audit_log
                    ORDER BY id DESC
                    LIMIT 200
                    """
                ).fetchall()
        except Exception:
            rows = []

        for row in rows:
            self.tree.insert(
                "",
                "end",
                values=(
                    row["created_at"],
                    row["action"],
                    row["details"],
                ),
            )