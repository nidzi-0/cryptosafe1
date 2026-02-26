from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from src.gui.widgets.secure_table import SecureTable
from src.gui.widgets.audit_log_viewer import AuditLogViewer


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSafe Manager (Sprint 1)")
        self.geometry("760x440")

        self._build_menu()

        self.table = SecureTable(self)
        self.table.pack(fill="both", expand=True, padx=10, pady=10)
        self.table.load_test_data()

        self.status_var = tk.StringVar(value="Status: locked | Clipboard timer: --")
        self.status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        self.status.pack(fill="x", side="bottom", padx=10, pady=(0, 8))

    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Create", command=self._stub)
        file_menu.add_command(label="Open", command=self._stub)
        file_menu.add_command(label="Backup", command=self._stub)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Add", command=self._stub)
        edit_menu.add_command(label="Edit", command=self._stub)
        edit_menu.add_command(label="Delete", command=self._stub)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Logs", command=self.open_logs)
        view_menu.add_command(label="Settings", command=self._stub_settings)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.about)

        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        menubar.add_cascade(label="View", menu=view_menu)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def open_logs(self):
        win = tk.Toplevel(self)
        win.title("Audit Logs (placeholder)")
        AuditLogViewer(win).pack(fill="both", expand=True, padx=10, pady=10)

    def _stub_settings(self):
        messagebox.showinfo("Settings", "Settings dialog placeholder (Sprint 1).")

    def about(self):
        messagebox.showinfo("About", "CryptoSafe Manager — Sprint 1 foundation")

    def _stub(self):
        messagebox.showinfo("Stub", "This action is a placeholder in Sprint 1.")