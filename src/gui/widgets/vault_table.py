from __future__ import annotations

from urllib.parse import urlparse

from tkinter import ttk


class VaultTable(ttk.Frame):
    PASSWORD_MASK = "••••••••"
    PASSWORD_VISIBLE_ICON = "👁 "
    PASSWORD_HIDDEN_ICON = "•••• "

    ACTION_COPY_PASSWORD = "Copy Password"
    ACTION_COPY_USERNAME = "Copy Username"

    def __init__(self, parent):
        super().__init__(parent)

        self.tree: ttk.Treeview | None = None
        self.entries: list[dict] = []
        self.show_passwords_global = False
        self.revealed_password_ids: set[int] = set()

        self.sort_column: str | None = None
        self.sort_reverse = False

        self.clipboard_entry_id: int | None = None
        self.clipboard_data_type: str | None = None

        self._build_table()

    def _build_table(self):
        columns = (
            "title",
            "username",
            "domain",
            "password",
            "updated_at",
            "clipboard",
            "copy_password",
            "copy_username",
        )

        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            selectmode="extended",
        )

        self.tree.heading(
            "title",
            text="Название",
            command=lambda: self.sort_by("title"),
        )
        self.tree.heading(
            "username",
            text="Пользователь",
            command=lambda: self.sort_by("username"),
        )
        self.tree.heading(
            "domain",
            text="Домен",
            command=lambda: self.sort_by("domain"),
        )
        self.tree.heading(
            "password",
            text="Пароль",
            command=lambda: self.sort_by("password"),
        )
        self.tree.heading(
            "updated_at",
            text="Изменено",
            command=lambda: self.sort_by("updated_at"),
        )
        self.tree.heading(
            "clipboard",
            text="Буфер",
            command=lambda: self.sort_by("clipboard"),
        )
        self.tree.heading(
            "copy_password",
            text="Copy Password",
        )
        self.tree.heading(
            "copy_username",
            text="Copy Username",
        )

        self.tree.column("title", width=210, minwidth=140, anchor="w", stretch=True)
        self.tree.column("username", width=160, minwidth=120, anchor="w", stretch=True)
        self.tree.column("domain", width=190, minwidth=120, anchor="w", stretch=True)
        self.tree.column("password", width=130, minwidth=110, anchor="center", stretch=True)
        self.tree.column("updated_at", width=160, minwidth=130, anchor="center", stretch=True)
        self.tree.column("clipboard", width=120, minwidth=90, anchor="center", stretch=False)
        self.tree.column("copy_password", width=130, minwidth=110, anchor="center", stretch=False)
        self.tree.column("copy_username", width=130, minwidth=110, anchor="center", stretch=False)

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

        self.tree.bind("<Double-1>", self._on_double_click)

    def load_entries(self, entries: list[dict]):
        self.entries = list(entries)

        if self.sort_column:
            self.entries.sort(
                key=lambda entry: self._sort_value(entry, self.sort_column),
                reverse=self.sort_reverse,
            )

        self._render_entries()

    def _render_entries(self):
        self.clear()

        if self.tree is None:
            return

        for entry in self.entries:
            entry_id = entry.get("id")

            if entry_id is None:
                continue

            try:
                entry_id_int = int(entry_id)
            except (TypeError, ValueError):
                continue

            self.tree.insert(
                "",
                "end",
                iid=str(entry_id_int),
                values=(
                    entry.get("title", ""),
                    self._mask_username(entry.get("username", "")),
                    self._extract_domain(entry.get("url", "")),
                    self._password_display(entry),
                    entry.get("updated_at", ""),
                    self._clipboard_display(entry_id_int),
                    "Copy Password",
                    "Copy Username",
                ),
            )

    def clear(self):
        if self.tree is None:
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

    def secure_clear(self):
        self.entries.clear()
        self.revealed_password_ids.clear()
        self.show_passwords_global = False
        self.clipboard_entry_id = None
        self.clipboard_data_type = None
        self.clear()

    def set_clipboard_marker(
        self,
        entry_id: int | str | None,
        data_type: str | None,
    ) -> None:
        if entry_id is None:
            self.clipboard_entry_id = None
        else:
            try:
                self.clipboard_entry_id = int(entry_id)
            except (TypeError, ValueError):
                self.clipboard_entry_id = None

        self.clipboard_data_type = data_type
        self._render_entries()

    def sort_by(self, column: str):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False

        self.entries.sort(
            key=lambda entry: self._sort_value(entry, column),
            reverse=self.sort_reverse,
        )

        self._render_entries()
        self._update_headings()

    def _update_headings(self):
        if self.tree is None:
            return

        headings = {
            "title": "Название",
            "username": "Пользователь",
            "domain": "Домен",
            "password": "Пароль",
            "updated_at": "Изменено",
            "clipboard": "Буфер",
            "copy_password": "Copy Password",
            "copy_username": "Copy Username",
        }

        for column, title in headings.items():
            if column == self.sort_column:
                arrow = " ↓" if self.sort_reverse else " ↑"
                self.tree.heading(column, text=title + arrow)
            else:
                self.tree.heading(column, text=title)

    def _sort_value(self, entry: dict, column: str) -> str:
        if column == "title":
            return str(entry.get("title", "")).lower()

        if column == "username":
            return str(entry.get("username", "")).lower()

        if column == "domain":
            return self._extract_domain(entry.get("url", "")).lower()

        if column == "password":
            return str(entry.get("password", "")).lower()

        if column == "updated_at":
            return str(entry.get("updated_at", ""))

        if column == "clipboard":
            try:
                entry_id = int(entry.get("id"))
            except (TypeError, ValueError):
                return ""

            return "1" if entry_id == self.clipboard_entry_id else "0"

        return ""

    def _mask_username(self, username: str) -> str:
        username = str(username or "")

        if not username:
            return ""

        if len(username) <= 4:
            return username

        return username[:4] + "••••"

    def _extract_domain(self, url: str) -> str:
        url = str(url or "").strip()

        if not url:
            return ""

        prepared_url = url

        if "://" not in prepared_url:
            prepared_url = "https://" + prepared_url

        parsed = urlparse(prepared_url)
        domain = parsed.netloc or parsed.path

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    def _password_display(self, entry: dict) -> str:
        entry_id = entry.get("id")

        try:
            entry_id_int = int(entry_id)
        except (TypeError, ValueError):
            entry_id_int = -1

        password = str(entry.get("password", ""))

        if self.show_passwords_global or entry_id_int in self.revealed_password_ids:
            return self.PASSWORD_VISIBLE_ICON + password

        return self.PASSWORD_HIDDEN_ICON + self.PASSWORD_MASK

    def _clipboard_display(self, entry_id: int) -> str:
        if self.clipboard_entry_id is None:
            return ""

        if entry_id != self.clipboard_entry_id:
            return ""

        if self.clipboard_data_type:
            return f"В буфере: {self.clipboard_data_type}"

        return "В буфере"

    def toggle_global_password_visibility(self):
        self.show_passwords_global = not self.show_passwords_global

        if self.show_passwords_global:
            self.revealed_password_ids.clear()

        self._render_entries()

    def set_global_password_visibility(self, visible: bool):
        self.show_passwords_global = bool(visible)

        if self.show_passwords_global:
            self.revealed_password_ids.clear()

        self._render_entries()

    def toggle_selected_password_visibility(self):
        for entry_id in self.get_selected_ids():
            if entry_id in self.revealed_password_ids:
                self.revealed_password_ids.remove(entry_id)
            else:
                self.revealed_password_ids.add(entry_id)

        self._render_entries()

    def toggle_password_visibility_for_row(self, entry_id: int):
        if entry_id in self.revealed_password_ids:
            self.revealed_password_ids.remove(entry_id)
        else:
            self.revealed_password_ids.add(entry_id)

        self._render_entries()

    def identify_action(self, event) -> tuple[str | None, int | None]:
        if self.tree is None:
            return None, None

        row_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)

        if not row_id:
            return None, None

        try:
            entry_id = int(row_id)
        except ValueError:
            return None, None


        if column_id == "#7":
            return self.ACTION_COPY_PASSWORD, entry_id

        if column_id == "#8":
            return self.ACTION_COPY_USERNAME, entry_id

        return None, entry_id

    def _on_double_click(self, event):
        if self.tree is None:
            return

        row_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)

        if not row_id:
            return

        if column_id != "#4":
            return

        try:
            entry_id = int(row_id)
        except ValueError:
            return

        self.toggle_password_visibility_for_row(entry_id)

    def get_selected_id(self) -> int | None:
        selected_ids = self.get_selected_ids()

        if not selected_ids:
            return None

        return selected_ids[0]

    def get_selected_ids(self) -> list[int]:
        if self.tree is None:
            return []

        selected = self.tree.selection()
        result = []

        for item in selected:
            try:
                result.append(int(item))
            except ValueError:
                continue

        return result