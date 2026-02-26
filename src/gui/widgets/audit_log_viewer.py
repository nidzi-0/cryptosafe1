from __future__ import annotations
from tkinter import ttk


class AuditLogViewer(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        ttk.Label(self, text="AuditLogViewer (Sprint 1 placeholder)").pack(anchor="w", pady=10)