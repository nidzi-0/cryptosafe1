from __future__ import annotations
from tkinter import ttk


class SecureTable(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.tree = ttk.Treeview(self, columns=("title", "username", "url"), show="headings", height=12)
        self.tree.heading("title", text="Title")
        self.tree.heading("username", text="Username")
        self.tree.heading("url", text="URL")

        self.tree.column("title", width=220, anchor="w")
        self.tree.column("username", width=200, anchor="w")
        self.tree.column("url", width=260, anchor="w")

        self.tree.pack(fill="both", expand=True)

    def load_test_data(self):
        self.tree.insert("", "end", values=("Gmail", "user@gmail.com", "https://mail.google.com"))
        self.tree.insert("", "end", values=("GitHub", "heis", "https://github.com"))