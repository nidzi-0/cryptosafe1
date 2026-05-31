from __future__ import annotations

from tkinter import ttk


class VaultTable(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.tree = None

        self._build_table()

    def _build_table(self):
        columns = (
            "title",
            "username",
            "url",
            "category",
            "updated_at",
        )

        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.tree.heading("title", text="Название")
        self.tree.heading("username", text="Логин")
        self.tree.heading("url", text="Сайт / URL")
        self.tree.heading("category", text="Категория")
        self.tree.heading("updated_at", text="Обновлено")

        self.tree.column("title", width=180, minwidth=120, anchor="w")
        self.tree.column("username", width=160, minwidth=100, anchor="w")
        self.tree.column("url", width=230, minwidth=120, anchor="w")
        self.tree.column("category", width=130, minwidth=90, anchor="w")
        self.tree.column("updated_at", width=150, minwidth=120, anchor="center")

        y_scrollbar = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.tree.yview,
        )

        x_scrollbar = ttk.Scrollbar(
            self,
            orient="horizontal",
            command=self.tree.xview,
        )

        self.tree.configure(
            yscrollcommand=y_scrollbar.set,
            xscrollcommand=x_scrollbar.set,
        )

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def load_entries(self, entries):
        self.clear()

        for entry in entries:
            entry_id = entry.get("id")

            if entry_id is None:
                continue

            self.tree.insert(
                "",
                "end",
                iid=str(entry_id),
                values=(
                    entry.get("title", ""),
                    entry.get("username", ""),
                    entry.get("url", ""),
                    entry.get("category", ""),
                    entry.get("updated_at", ""),
                ),
            )

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def get_selected_id(self):
        selected = self.tree.selection()

        if not selected:
            return None

        try:
            return int(selected[0])
        except ValueError:
            return None