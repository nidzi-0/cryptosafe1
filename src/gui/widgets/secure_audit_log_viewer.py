from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


class SecureAuditLogViewer(ttk.Frame):
    PAGE_SIZE = 50

    def __init__(
        self,
        parent,
        audit_logger,
        audit_verifier,
        audit_exporter,
    ):
        super().__init__(parent)

        self.audit_logger = audit_logger
        self.audit_verifier = audit_verifier
        self.audit_exporter = audit_exporter

        self.current_page = 0
        self.current_rows: list[dict] = []

        self.event_type_var = tk.StringVar()
        self.severity_var = tk.StringVar()
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Integrity: not checked")

        self._build_ui()
        self.refresh()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=8)

        ttk.Label(top, text="Event type:").pack(side="left")
        ttk.Entry(top, textvariable=self.event_type_var, width=22).pack(
            side="left",
            padx=(4, 10),
        )

        ttk.Label(top, text="Severity:").pack(side="left")
        ttk.Combobox(
            top,
            textvariable=self.severity_var,
            values=["", "INFO", "WARN", "ERROR", "CRITICAL"],
            width=12,
            state="readonly",
        ).pack(side="left", padx=(4, 10))

        ttk.Label(top, text="Search:").pack(side="left")
        ttk.Entry(top, textvariable=self.search_var, width=28).pack(
            side="left",
            padx=(4, 10),
        )

        ttk.Button(top, text="Apply", command=self.refresh).pack(side="left")
        ttk.Button(top, text="Clear", command=self.clear_filters).pack(
            side="left",
            padx=(6, 0),
        )

        actions = ttk.Frame(self)
        actions.pack(fill="x", padx=8, pady=(0, 8))

        ttk.Button(actions, text="Verify integrity", command=self.verify_integrity).pack(
            side="left"
        )
        ttk.Button(actions, text="Export JSON", command=self.export_json).pack(
            side="left",
            padx=(6, 0),
        )
        ttk.Button(actions, text="Export CSV", command=self.export_csv).pack(
            side="left",
            padx=(6, 0),
        )
        ttk.Button(actions, text="Export PDF", command=self.export_pdf).pack(
            side="left",
            padx=(6, 0),
        )

        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        left = ttk.Frame(main)
        right = ttk.Frame(main)

        main.add(left, weight=3)
        main.add(right, weight=2)

        columns = (
            "sequence_number",
            "timestamp",
            "severity",
            "event_type",
            "source",
            "entry_id",
        )

        self.tree = ttk.Treeview(
            left,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "sequence_number": "#",
            "timestamp": "Timestamp",
            "severity": "Severity",
            "event_type": "Event Type",
            "source": "Source",
            "entry_id": "Entry ID",
        }

        for column, title in headings.items():
            self.tree.heading(
                column,
                text=title,
                command=lambda col=column: self.sort_by(col),
            )

        self.tree.column("sequence_number", width=70, anchor="center")
        self.tree.column("timestamp", width=170, anchor="w")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("event_type", width=190, anchor="w")
        self.tree.column("source", width=100, anchor="w")
        self.tree.column("entry_id", width=80, anchor="center")

        y_scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=y_scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        y_scroll.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Button-3>", self.show_context_menu)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(
            label="Investigate selected entry",
            command=self.investigate_selected,
        )
        self.context_menu.add_command(
            label="Copy event JSON",
            command=self.copy_selected_json,
        )

        ttk.Label(right, text="Entry details").pack(anchor="w")

        self.details_text = tk.Text(right, height=20, wrap="word")
        self.details_text.pack(fill="both", expand=True, pady=(4, 8))

        ttk.Label(right, text="Statistics").pack(anchor="w")

        self.stats_text = tk.Text(right, height=8, wrap="word")
        self.stats_text.pack(fill="x", expand=False, pady=(4, 0))

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=8, pady=(0, 8))

        ttk.Button(bottom, text="Previous", command=self.prev_page).pack(side="left")
        ttk.Button(bottom, text="Next", command=self.next_page).pack(
            side="left",
            padx=(6, 0),
        )

        self.page_var = tk.StringVar(value="Page 1")
        ttk.Label(bottom, textvariable=self.page_var).pack(side="left", padx=12)

    def refresh(self):
        event_type = self.event_type_var.get().strip() or None
        severity = self.severity_var.get().strip() or None
        search = self.search_var.get().strip() or None

        offset = self.current_page * self.PAGE_SIZE

        self.current_rows = self.audit_logger.query_logs(
            event_type=event_type,
            severity=severity,
            search=search,
            limit=self.PAGE_SIZE,
            offset=offset,
        )

        self._render_rows()
        self._render_stats()
        self.page_var.set(f"Page {self.current_page + 1}")

    def _render_rows(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for row in self.current_rows:
            self.tree.insert(
                "",
                "end",
                iid=str(row["sequence_number"]),
                values=(
                    row["sequence_number"],
                    row["timestamp"],
                    row["severity"],
                    row["event_type"],
                    row["source"],
                    row["entry_id"] or "",
                ),
            )

    def _render_stats(self):
        total = self.audit_logger.count_logs()

        severity_counts = {}

        for severity in ["INFO", "WARN", "ERROR", "CRITICAL"]:
            count = len(
                self.audit_logger.query_logs(
                    severity=severity,
                    limit=10_000,
                    offset=0,
                )
            )
            severity_counts[severity] = count

        text = {
            "total_logs": total,
            "severity_counts": severity_counts,
            "current_page_rows": len(self.current_rows),
        }

        self.stats_text.delete("1.0", "end")
        self.stats_text.insert(
            "1.0",
            json.dumps(text, ensure_ascii=False, indent=2),
        )

    def clear_filters(self):
        self.event_type_var.set("")
        self.severity_var.set("")
        self.search_var.set("")
        self.current_page = 0
        self.refresh()

    def sort_by(self, column: str):
        self.current_rows.sort(
            key=lambda row: str(row.get(column, "")),
            reverse=False,
        )
        self._render_rows()

    def on_select(self, event=None):
        selected = self.tree.selection()

        if not selected:
            return

        sequence_number = int(selected[0])
        row = self._find_current_row(sequence_number)

        if row is None:
            return

        self.details_text.delete("1.0", "end")
        self.details_text.insert(
            "1.0",
            json.dumps(row, ensure_ascii=False, indent=2),
        )

    def _find_current_row(self, sequence_number: int) -> dict | None:
        for row in self.current_rows:
            if int(row["sequence_number"]) == int(sequence_number):
                return row

        return None

    def verify_integrity(self):
        result = self.audit_verifier.verify_integrity()

        if result.verified:
            self.status_var.set(
                f"Integrity: OK, entries={result.total_entries}"
            )
            messagebox.showinfo(
                "Audit integrity",
                f"Audit log verified successfully.\nEntries: {result.total_entries}",
            )
        else:
            self.status_var.set(
                f"Integrity: FAILED, invalid={len(result.invalid_entries)}"
            )
            messagebox.showerror(
                "Audit integrity",
                "Audit log integrity check failed.\n"
                f"Invalid entries: {len(result.invalid_entries)}\n"
                f"Chain breaks: {len(result.chain_breaks)}",
            )

    def export_json(self):
        path = filedialog.asksaveasfilename(
            title="Export signed JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )

        if not path:
            return

        self.audit_exporter.export_signed_json(path)
        self._log_export("json", path)
        messagebox.showinfo("Export", "Signed JSON exported.")

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
        )

        if not path:
            return

        self.audit_exporter.export_csv(path)
        self._log_export("csv", path)
        messagebox.showinfo("Export", "CSV exported.")

    def export_pdf(self):
        path = filedialog.asksaveasfilename(
            title="Export PDF",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
        )

        if not path:
            return

        self.audit_exporter.export_pdf(path)
        self._log_export("pdf", path)
        messagebox.showinfo("Export", "PDF exported.")

    def _log_export(self, export_type: str, path: str):
        self.audit_logger.log_event(
            event_type="AUDIT_LOG_EXPORTED",
            severity="INFO",
            source="secure_audit_log_viewer",
            details={
                "export_type": export_type,
                "path": "[REDACTED]",
            },
        )

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.refresh()

    def next_page(self):
        if len(self.current_rows) == self.PAGE_SIZE:
            self.current_page += 1
            self.refresh()

    def show_context_menu(self, event):
        row_id = self.tree.identify_row(event.y)

        if row_id:
            self.tree.selection_set(row_id)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def investigate_selected(self):
        selected = self.tree.selection()

        if not selected:
            return

        sequence_number = int(selected[0])
        row = self._find_current_row(sequence_number)

        if row is None:
            return

        messagebox.showinfo(
            "Investigation",
            "Selected audit event:\n"
            f"Event: {row['event_type']}\n"
            f"Time: {row['timestamp']}\n"
            f"Entry ID: {row.get('entry_id') or 'N/A'}",
        )

    def copy_selected_json(self):
        selected = self.tree.selection()

        if not selected:
            return

        sequence_number = int(selected[0])
        row = self._find_current_row(sequence_number)

        if row is None:
            return

        text = json.dumps(row, ensure_ascii=False, indent=2)

        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()