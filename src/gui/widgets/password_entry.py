from __future__ import annotations
import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.var = tk.StringVar()
        self._shown = False

        self.entry = ttk.Entry(self, textvariable=self.var, show="*")
        self.btn = ttk.Button(self, text="👁", width=3, command=self.toggle)

        self.entry.grid(row=0, column=0, sticky="ew")
        self.btn.grid(row=0, column=1, padx=(6, 0))
        self.columnconfigure(0, weight=1)

    def toggle(self):
        self._shown = not self._shown
        self.entry.configure(show="" if self._shown else "*")

    def get(self) -> str:
        return self.var.get()