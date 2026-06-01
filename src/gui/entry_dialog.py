from __future__ import annotations

import re
import tkinter as tk
from tkinter import messagebox, ttk
from urllib.parse import urlparse

from src.core.vault.password_generator import PasswordGenerator, PasswordGeneratorError


class PasswordGeneratorSettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)

        self.parent = parent
        self.result = None

        self.title("Настройки генерации пароля")
        self.geometry("360x360")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self.length_var = tk.IntVar(value=16)
        self.use_lowercase_var = tk.BooleanVar(value=True)
        self.use_uppercase_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_special_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=True)

        self._build_ui()

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        self.update_idletasks()
        self.lift()
        self.focus_force()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=18)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(
            main_frame,
            text="Параметры генерации",
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        ttk.Label(main_frame, text="Длина пароля:").pack(anchor="w")

        length_frame = ttk.Frame(main_frame)
        length_frame.pack(fill="x", pady=(4, 12))

        ttk.Spinbox(
            length_frame,
            from_=8,
            to=64,
            textvariable=self.length_var,
            width=8,
        ).pack(side="left")

        ttk.Label(
            length_frame,
            text="от 8 до 64 символов",
        ).pack(side="left", padx=(10, 0))

        ttk.Checkbutton(
            main_frame,
            text="Строчные буквы a-z",
            variable=self.use_lowercase_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            main_frame,
            text="Заглавные буквы A-Z",
            variable=self.use_uppercase_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            main_frame,
            text="Цифры 0-9",
            variable=self.use_digits_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            main_frame,
            text="Спецсимволы !@#$%^&*",
            variable=self.use_special_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            main_frame,
            text="Исключить похожие символы l, I, 1, 0, O",
            variable=self.exclude_similar_var,
        ).pack(anchor="w", pady=(3, 14))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(12, 0))

        ttk.Button(
            button_frame,
            text="Сгенерировать",
            command=self.save,
        ).pack(side="right")

        ttk.Button(
            button_frame,
            text="Отмена",
            command=self.cancel,
        ).pack(side="right", padx=(0, 8))

    def save(self):
        selected_groups = [
            self.use_lowercase_var.get(),
            self.use_uppercase_var.get(),
            self.use_digits_var.get(),
            self.use_special_var.get(),
        ]

        if not any(selected_groups):
            messagebox.showwarning(
                "Проверка данных",
                "Выберите хотя бы один набор символов.",
                parent=self,
            )
            return

        try:
            length = int(self.length_var.get())
        except ValueError:
            messagebox.showwarning(
                "Проверка данных",
                "Длина пароля должна быть числом.",
                parent=self,
            )
            return

        if length < 8 or length > 64:
            messagebox.showwarning(
                "Проверка данных",
                "Длина пароля должна быть от 8 до 64 символов.",
                parent=self,
            )
            return

        self.result = {
            "length": length,
            "use_lowercase": self.use_lowercase_var.get(),
            "use_uppercase": self.use_uppercase_var.get(),
            "use_digits": self.use_digits_var.get(),
            "use_special": self.use_special_var.get(),
            "exclude_similar": self.exclude_similar_var.get(),
        }

        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()


class EntryDialog(tk.Toplevel):
    MIN_PASSWORD_SCORE = 3

    def __init__(self, parent, entry: dict | None = None):
        super().__init__(parent)

        self.parent = parent
        self.entry = entry
        self.result = None

        self.password_generator = PasswordGenerator()
        self.password_was_generated = False

        self.title("Добавить запись" if entry is None else "Изменить запись")
        self.geometry("520x660")
        self.minsize(500, 620)
        self.resizable(True, True)

        self.transient(parent)
        self.grab_set()

        self.title_var = tk.StringVar(value=self._get_value("title"))
        self.username_var = tk.StringVar(value=self._get_value("username"))
        self.password_var = tk.StringVar(value=self._get_value("password"))
        self.url_var = tk.StringVar(value=self._get_value("url"))
        self.category_var = tk.StringVar(value=self._get_value("category"))
        self.tags_var = tk.StringVar(value=self._get_value("tags"))

        self.password_strength_var = tk.StringVar(value="Надёжность: не проверена")
        self.url_status_var = tk.StringVar(value="URL: не указан")
        self.favicon_status_var = tk.StringVar(value="Иконка сайта: не определена")

        self.show_password_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._bind_events()

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        self.after(100, self._focus_title)
        self.after(150, self.update_password_strength)
        self.after(200, self.update_url_info)

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

        main_frame.grid_columnconfigure(0, weight=1)

        ttk.Label(main_frame, text="Название:").grid(
            row=0,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        self.title_entry = ttk.Entry(
            main_frame,
            textvariable=self.title_var,
        )
        self.title_entry.grid(
            row=1,
            column=0,
            sticky="ew",
            pady=(0, 10),
        )

        ttk.Label(main_frame, text="Логин / Email:").grid(
            row=2,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        username_frame = ttk.Frame(main_frame)
        username_frame.grid(
            row=3,
            column=0,
            sticky="ew",
            pady=(0, 10),
        )
        username_frame.grid_columnconfigure(0, weight=1)

        self.username_entry = ttk.Entry(
            username_frame,
            textvariable=self.username_var,
        )
        self.username_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(
            username_frame,
            text="Авто",
            command=self.autofill_username,
        ).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(main_frame, text="Пароль:").grid(
            row=4,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        password_frame = ttk.Frame(main_frame)
        password_frame.grid(
            row=5,
            column=0,
            sticky="ew",
            pady=(0, 6),
        )
        password_frame.grid_columnconfigure(0, weight=1)

        self.password_entry = ttk.Entry(
            password_frame,
            textvariable=self.password_var,
            show="*",
        )
        self.password_entry.grid(row=0, column=0, sticky="ew")

        ttk.Checkbutton(
            password_frame,
            text="Показать",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
        ).grid(row=0, column=1, padx=(8, 0))

        ttk.Button(
            password_frame,
            text="Сгенерировать пароль",
            command=self.open_password_generator_settings,
        ).grid(row=0, column=2, padx=(8, 0))

        self.strength_label = ttk.Label(
            main_frame,
            textvariable=self.password_strength_var,
        )
        self.strength_label.grid(
            row=6,
            column=0,
            sticky="w",
            pady=(0, 10),
        )

        ttk.Label(main_frame, text="Сайт / URL:").grid(
            row=7,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        url_frame = ttk.Frame(main_frame)
        url_frame.grid(
            row=8,
            column=0,
            sticky="ew",
            pady=(0, 6),
        )
        url_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ttk.Entry(
            url_frame,
            textvariable=self.url_var,
        )
        self.url_entry.grid(row=0, column=0, sticky="ew")

        ttk.Button(
            url_frame,
            text="Проверить URL",
            command=self.update_url_info,
        ).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(
            main_frame,
            textvariable=self.url_status_var,
        ).grid(
            row=9,
            column=0,
            sticky="w",
            pady=(0, 2),
        )

        ttk.Label(
            main_frame,
            textvariable=self.favicon_status_var,
        ).grid(
            row=10,
            column=0,
            sticky="w",
            pady=(0, 10),
        )

        ttk.Label(main_frame, text="Категория:").grid(
            row=11,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        ttk.Entry(
            main_frame,
            textvariable=self.category_var,
        ).grid(
            row=12,
            column=0,
            sticky="ew",
            pady=(0, 10),
        )

        ttk.Label(main_frame, text="Теги:").grid(
            row=13,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        ttk.Entry(
            main_frame,
            textvariable=self.tags_var,
        ).grid(
            row=14,
            column=0,
            sticky="ew",
            pady=(0, 10),
        )

        ttk.Label(main_frame, text="Заметки:").grid(
            row=15,
            column=0,
            sticky="w",
            pady=(0, 4),
        )

        notes_frame = ttk.Frame(main_frame)
        notes_frame.grid(row=16, column=0, sticky="nsew", pady=(0, 14))
        notes_frame.grid_columnconfigure(0, weight=1)
        notes_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_rowconfigure(16, weight=1)

        self.notes_text = tk.Text(
            notes_frame,
            height=6,
            wrap="word",
        )
        self.notes_text.grid(row=0, column=0, sticky="nsew")

        notes_scrollbar = ttk.Scrollbar(
            notes_frame,
            orient="vertical",
            command=self.notes_text.yview,
        )
        notes_scrollbar.grid(row=0, column=1, sticky="ns")

        self.notes_text.configure(yscrollcommand=notes_scrollbar.set)
        self.notes_text.insert("1.0", self._get_value("notes"))

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=17, column=0, sticky="e")

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

    def _bind_events(self):
        self.password_var.trace_add("write", lambda *_: self.update_password_strength())
        self.url_var.trace_add("write", lambda *_: self.update_url_info_light())

        self.bind("<Return>", lambda event: self.save())
        self.bind("<Escape>", lambda event: self.cancel())

    def _focus_title(self):
        self.title_entry.focus_set()

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def update_password_strength(self):
        password = self.password_var.get()

        if not password:
            self.password_strength_var.set("Надёжность: пароль не введён")
            return

        try:
            result = self.password_generator.analyze_strength(password)
        except Exception:
            self.password_strength_var.set("Надёжность: ошибка проверки")
            return

        score = int(result.get("score", 0))
        entropy = result.get("entropy_bits", 0)

        if score <= 1:
            level = "слабый"
        elif score == 2:
            level = "средний"
        elif score == 3:
            level = "надёжный"
        else:
            level = "очень надёжный"

        self.password_strength_var.set(
            f"Надёжность: {level} ({score}/4), энтропия: {entropy} бит"
        )

    def open_password_generator_settings(self):
        dialog = PasswordGeneratorSettingsDialog(self)
        self.wait_window(dialog)

        if dialog.result is None:
            return

        try:
            password = self.password_generator.generate(**dialog.result)
        except PasswordGeneratorError as exc:
            messagebox.showerror(
                "Ошибка генерации",
                str(exc),
                parent=self,
            )
            return
        except Exception as exc:
            messagebox.showerror(
                "Ошибка генерации",
                f"Не удалось сгенерировать пароль:\n{exc}",
                parent=self,
            )
            return

        self.password_var.set(password)
        self.password_was_generated = True
        self.update_password_strength()

    def update_url_info_light(self):
        url = self.url_var.get().strip()

        if not url:
            self.url_status_var.set("URL: не указан")
            self.favicon_status_var.set("Иконка сайта: не определена")
            return

        domain = self.extract_domain(url)

        if domain:
            self.url_status_var.set(f"URL: домен {domain}")
            self.favicon_status_var.set(
                f"Иконка сайта: https://{domain}/favicon.ico"
            )
        else:
            self.url_status_var.set("URL: некорректный формат")
            self.favicon_status_var.set("Иконка сайта: не определена")

    def update_url_info(self):
        url = self.url_var.get().strip()

        if not url:
            self.url_status_var.set("URL: не указан")
            self.favicon_status_var.set("Иконка сайта: не определена")
            return

        if not self.is_valid_url(url):
            self.url_status_var.set("URL: некорректный формат")
            self.favicon_status_var.set("Иконка сайта: не определена")
            return

        domain = self.extract_domain(url)

        self.url_status_var.set(f"URL: корректный, домен {domain}")
        self.favicon_status_var.set(
            f"Иконка сайта: https://{domain}/favicon.ico"
        )

    def is_valid_url(self, url: str) -> bool:
        url = str(url or "").strip()

        if not url:
            return True

        prepared_url = url

        if "://" not in prepared_url:
            prepared_url = "https://" + prepared_url

        parsed = urlparse(prepared_url)

        if parsed.scheme not in {"http", "https"}:
            return False

        domain = parsed.netloc or parsed.path

        if not domain:
            return False

        domain_pattern = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
            r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
            r"\.[A-Za-z]{2,63}$"
        )

        return bool(domain_pattern.match(domain))

    def extract_domain(self, url: str) -> str:
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

        if "/" in domain:
            domain = domain.split("/")[0]

        return domain

    def autofill_username(self):
        current_username = self.username_var.get().strip()

        if current_username:
            answer = messagebox.askyesno(
                "Автозаполнение",
                "Поле логина уже заполнено. Заменить его?",
                parent=self,
            )

            if not answer:
                return

        domain = self.extract_domain(self.url_var.get())

        if not domain:
            messagebox.showwarning(
                "Автозаполнение",
                "Сначала укажите корректный URL или домен.",
                parent=self,
            )
            return

        self.username_var.set(f"user@{domain}")

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

        if url and not self.is_valid_url(url):
            messagebox.showwarning(
                "Проверка данных",
                "Введите корректный URL или домен сайта.",
                parent=self,
            )
            return

        try:
            strength = self.password_generator.analyze_strength(password)
        except Exception as exc:
            messagebox.showerror(
                "Проверка пароля",
                f"Не удалось проверить надёжность пароля:\n{exc}",
                parent=self,
            )
            return

        score = int(strength.get("score", 0))

        if score < self.MIN_PASSWORD_SCORE:
            answer = messagebox.askyesno(
                "Слабый пароль",
                (
                    "Пароль имеет низкую надёжность "
                    f"({score}/4).\n\n"
                    "Рекомендуется использовать пароль с оценкой не ниже 3/4.\n"
                    "Сохранить запись всё равно?"
                ),
                parent=self,
            )

            if not answer:
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