import tkinter as tk
from tkinter import ttk


class SettingsDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)

        self.title("Настройки")
        self.geometry("400x300")
        self.resizable(False, False)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        security_tab = ttk.Frame(notebook)
        notebook.add(security_tab, text="Безопасность")

        ttk.Label(security_tab, text="Таймер очистки буфера обмена: заглушка").pack(pady=10)
        ttk.Label(security_tab, text="Автоблокировка: заглушка").pack(pady=10)

        appearance_tab = ttk.Frame(notebook)
        notebook.add(appearance_tab, text="Внешний вид")

        ttk.Label(appearance_tab, text="Тема оформления: заглушка").pack(pady=10)
        ttk.Label(appearance_tab, text="Язык интерфейса: заглушка").pack(pady=10)

        advanced_tab = ttk.Frame(notebook)
        notebook.add(advanced_tab, text="Дополнительно")

        ttk.Label(advanced_tab, text="Резервное копирование: заглушка").pack(pady=10)
        ttk.Label(advanced_tab, text="Экспорт данных: заглушка").pack(pady=10)

        ttk.Button(self, text="Закрыть", command=self.destroy).pack(pady=10)