from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk


class EntryDialog(tk.Toplevel):
    def __init__(self, parent, entry: dict | None = None):
        super().__init__(parent)

        self.parent = parent
        self.entry = entry
        self.result = None

        self.title("Добавить запись" if entry is None else "Изменить запись")
        self.geometry("460x520")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self.title_var = tk.StringVar(value=self._get_value("title"))
        self.username_var = tk.StringVar(value=self._get_value("username"))
        self.password_var = tk.StringVar(value=self._get_value("password"))
        self.url_var = tk.StringVar(value=self._get_value("url"))
        self.category_var = tk.StringVar(value=self._get_value("category"))
        self.tags_var = tk.StringVar(value=self._get_value("tags"))

        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        self.after(100, self._focus_title)

    def _get_value(self, key: str) -> str:
        if self.entry is None:
            return ""

        value = self.entry.get(key, "")

        if value is None:
            return ""

        return str(value)

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=14)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(main_frame, text="Название:").grid(
            row=0, column=0, sticky="w", pady=(0, 4)
        )

        self.title_entry = ttk.Entry(
            main_frame,
            textvariable=self.title_var,
            width=46,
        )
        self.title_entry.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(main_frame, text="Логин / Email:").grid(
            row=2, column=0, sticky="w", pady=(0, 4)
        )

        ttk.Entry(
            main_frame,
            textvariable=self.username_var,
            width=46,
        ).grid(row=3, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(main_frame, text="Пароль:").grid(
            row=4, column=0, sticky="w", pady=(0, 4)
        )

        password_frame = ttk.Frame(main_frame)
        password_frame.grid(row=5, column=0, sticky="ew", pady=(0, 10))
        password_frame.grid_columnconfigure(0, weight=1)

        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="*",
        )
        self.password_entry.grid(row=0, column=0, sticky="ew")

        self.show_password_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            password_frame,
            text="Показать",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
        ).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(main_frame, text="Сайт / URL:").grid(
            row=6, column=0, sticky="w", pady=(0, 4)
        )

        ttk.Entry(
            main_frame,
            textvariable=self.url_var,
            width=46,
        ).grid(row=7, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(main_frame, text="Категория:").grid(
            row=8, column=0, sticky="w", pady=(0, 4)
        )

        ttk.Entry(
            main_frame,
            textvariable=self.category_var,
            width=46,
        ).grid(row=9, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(main_frame, text="Теги:").grid(
            row=10, column=0, sticky="w", pady=(0, 4)
        )

        ttk.Entry(
            main_frame,
            textvariable=self.tags_var,
            width=46,
        ).grid(row=11, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(main_frame, text="Заметки:").grid(
            row=12, column=0, sticky="w", pady=(0, 4)
        )

        self.notes_text = tk.Text(
            main_frame,
            width=46,
            height=6,
            wrap="word",
        )
        self.notes_text.grid(row=13, column=0, sticky="ew", pady=(0, 14))

        self.notes_text.insert("1.0", self._get_value("notes"))

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=14, column=0, sticky="e")

        ttk.Button(
            button_frame,
            text="Сохранить",
            command=self.save,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            button_frame,
            text="Отмена",
            command=self.cancel,
        ).pack(side="left")

        main_frame.grid_columnconfigure(0, weight=1)

    def _focus_title(self):
        self.title_entry.focus_set()

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def save(self):
        title = self.title_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        url = self.url_var.get().strip()
        category = self.category_var.get().strip()
        tags = self.tags_var.get().strip()
        notes = self.notes_text.get("1.0", "end").strip()

        if not title:
            messagebox.showwarning(
                "Проверка данных",
                "Введите название записи.",
                parent=self,
            )
            return

        if not password:
            messagebox.showwarning(
                "Проверка данных",
                "Введите пароль.",
                parent=self,
            )
            return

        self.result = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": category,
            "tags": tags,
        }

        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()