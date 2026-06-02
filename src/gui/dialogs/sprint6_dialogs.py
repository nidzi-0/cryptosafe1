import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import customtkinter as ctk
import qrcode
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox

from src.core.import_export.exporter import VaultExporter, ExportOptions
from src.core.import_export.importer import VaultImporter
from src.core.import_export.sharing_service import SharingService
from src.core.import_export.key_exchange import QRCodeService


class Sprint6DialogError(Exception):
    pass


class ExportDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        entry_manager: Any,
        audit_logger: Optional[Any] = None,
        master_password_verifier: Optional[Callable[[str], bool]] = None,
    ):
        super().__init__(parent)

        self.title("Export Vault")
        self.geometry("900x650")
        self.resizable(True, True)

        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.master_password_verifier = master_password_verifier
        self.exporter = VaultExporter(
            entry_manager=entry_manager,
            audit_logger=audit_logger,
            master_password_verifier=master_password_verifier,
        )

        self.entries = self._load_entries()
        self.entry_vars: Dict[str, ctk.BooleanVar] = {}

        self.format_var = ctk.StringVar(value="encrypted_json")
        self.encryption_bits_var = ctk.StringVar(value="256")
        self.include_notes_var = ctk.BooleanVar(value=True)
        self.compress_var = ctk.BooleanVar(value=False)
        self.full_export_var = ctk.BooleanVar(value=True)
        self.master_password_var = ctk.StringVar()
        self.export_password_var = ctk.StringVar()
        self.output_path_var = ctk.StringVar()

        self._build_ui()
        self._refresh_entry_state()
        self._refresh_preview()

        self.transient(parent)
        self.grab_set()
        self.focus()

    def _build_ui(self):
        root = ctk.CTkFrame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        left = ctk.CTkFrame(root)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        right = ctk.CTkFrame(root)
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))

        ctk.CTkLabel(left, text="Export settings", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=12, pady=(12, 8))

        format_frame = ctk.CTkFrame(left)
        format_frame.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(format_frame, text="Format").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        format_menu = ctk.CTkOptionMenu(
            format_frame,
            variable=self.format_var,
            values=["encrypted_json", "csv", "bitwarden_json"],
            command=lambda _: self._refresh_preview(),
        )
        format_menu.grid(row=0, column=1, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(
            format_frame,
            text="encrypted_json — secure native backup; csv — migration; bitwarden_json — password manager format",
            wraplength=500,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=8, pady=(0, 8))

        format_frame.grid_columnconfigure(1, weight=1)

        encryption_frame = ctk.CTkFrame(left)
        encryption_frame.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(encryption_frame, text="Encryption", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=8)

        ctk.CTkLabel(encryption_frame, text="Strength").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkOptionMenu(
            encryption_frame,
            variable=self.encryption_bits_var,
            values=["128", "256"],
            command=lambda _: self._refresh_preview(),
        ).grid(row=1, column=1, sticky="ew", padx=8, pady=6)

        ctk.CTkLabel(encryption_frame, text="Export password").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkEntry(encryption_frame, textvariable=self.export_password_var, show="*").grid(row=2, column=1, sticky="ew", padx=8, pady=6)

        ctk.CTkLabel(encryption_frame, text="Master password").grid(row=3, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkEntry(encryption_frame, textvariable=self.master_password_var, show="*").grid(row=3, column=1, sticky="ew", padx=8, pady=6)

        ctk.CTkCheckBox(encryption_frame, text="Include notes", variable=self.include_notes_var, command=self._refresh_preview).grid(row=4, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkCheckBox(encryption_frame, text="GZIP compression", variable=self.compress_var, command=self._refresh_preview).grid(row=4, column=1, sticky="w", padx=8, pady=6)

        encryption_frame.grid_columnconfigure(1, weight=1)

        file_frame = ctk.CTkFrame(left)
        file_frame.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(file_frame, text="Output file").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkEntry(file_frame, textvariable=self.output_path_var).grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        ctk.CTkButton(file_frame, text="Browse", command=self._select_output_file).grid(row=0, column=2, padx=8, pady=8)

        file_frame.grid_columnconfigure(1, weight=1)

        entries_frame = ctk.CTkFrame(left)
        entries_frame.pack(fill="both", expand=True, padx=12, pady=6)

        header = ctk.CTkFrame(entries_frame)
        header.pack(fill="x", padx=8, pady=8)

        ctk.CTkCheckBox(header, text="Full vault export", variable=self.full_export_var, command=self._refresh_entry_state).pack(side="left")

        scroll = ctk.CTkScrollableFrame(entries_frame)
        scroll.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        for entry in self.entries:
            entry_id = str(entry.get("id") or entry.get("entry_id") or entry.get("title"))
            var = ctk.BooleanVar(value=True)
            self.entry_vars[entry_id] = var
            title = self._entry_label(entry)
            cb = ctk.CTkCheckBox(scroll, text=title, variable=var, command=self._refresh_preview)
            cb.pack(anchor="w", padx=6, pady=4)

        ctk.CTkLabel(right, text="Preview before export", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=12, pady=(12, 8))

        self.preview_box = ctk.CTkTextbox(right, height=460)
        self.preview_box.pack(fill="both", expand=True, padx=12, pady=6)

        buttons = ctk.CTkFrame(right)
        buttons.pack(fill="x", padx=12, pady=12)

        ctk.CTkButton(buttons, text="Refresh preview", command=self._refresh_preview).pack(side="left", padx=6)
        ctk.CTkButton(buttons, text="Export", command=self._export).pack(side="right", padx=6)
        ctk.CTkButton(buttons, text="Cancel", fg_color="gray", command=self.destroy).pack(side="right", padx=6)

    def _load_entries(self) -> List[Dict[str, Any]]:
        try:
            entries = self.entry_manager.list_entries()
        except Exception:
            entries = []

        result = []
        for entry in entries:
            if isinstance(entry, dict):
                result.append(dict(entry))
            elif hasattr(entry, "__dict__"):
                result.append(dict(entry.__dict__))

        return result

    def _entry_label(self, entry: Dict[str, Any]) -> str:
        title = entry.get("title") or entry.get("name") or "Untitled"
        username = entry.get("username") or ""
        url = entry.get("url") or entry.get("website") or ""

        parts = [str(title)]

        if username:
            parts.append(str(username))

        if url:
            parts.append(str(url))

        return " | ".join(parts)

    def _selected_entry_ids(self) -> Optional[List[str]]:
        if self.full_export_var.get():
            return None

        selected = []

        for entry_id, var in self.entry_vars.items():
            if var.get():
                selected.append(entry_id)

        return selected

    def _refresh_entry_state(self):
        state = "disabled" if self.full_export_var.get() else "normal"

        for child in self.children.values():
            pass

        self._refresh_preview()

    def _select_output_file(self):
        selected_format = self.format_var.get()

        if selected_format == "csv":
            extension = ".csv"
        else:
            extension = ".json"

        path = filedialog.asksaveasfilename(
            title="Export vault",
            defaultextension=extension,
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )

        if path:
            self.output_path_var.set(path)

    def _refresh_preview(self):
        selected_ids = self._selected_entry_ids()
        selected_entries = self.entries if selected_ids is None else [
            entry for entry in self.entries
            if str(entry.get("id") or entry.get("entry_id") or entry.get("title")) in selected_ids
        ]

        preview = {
            "format": self.format_var.get(),
            "entry_count": len(selected_entries),
            "selected_mode": "full_vault" if selected_ids is None else "selected_entries",
            "include_notes": self.include_notes_var.get(),
            "encryption_bits": int(self.encryption_bits_var.get()),
            "compress": self.compress_var.get(),
            "entries": [
                {
                    "title": entry.get("title") or entry.get("name") or "Untitled",
                    "username": entry.get("username") or "",
                    "url": entry.get("url") or entry.get("website") or "",
                    "notes_included": self.include_notes_var.get(),
                }
                for entry in selected_entries
            ],
        }

        self.preview_box.delete("1.0", "end")
        self.preview_box.insert("1.0", json.dumps(preview, ensure_ascii=False, indent=2))

    def _export(self):
        output_path = self.output_path_var.get().strip()
        export_password = self.export_password_var.get()
        master_password = self.master_password_var.get()

        if not output_path:
            messagebox.showerror("Export error", "Choose output file")
            return

        if not export_password:
            messagebox.showerror("Export error", "Enter export password")
            return

        options = ExportOptions(
            format=self.format_var.get(),
            include_notes=self.include_notes_var.get(),
            encryption_bits=int(self.encryption_bits_var.get()),
            compress=self.compress_var.get(),
            plaintext_allowed=False,
            require_master_confirmation=self.master_password_verifier is not None,
        )

        try:
            self.exporter.export_to_file(
                output_path=output_path,
                password=export_password,
                entry_ids=self._selected_entry_ids(),
                options=options,
                master_password=master_password if self.master_password_verifier else None,
            )

            messagebox.showinfo("Export", "Vault exported successfully")
            self.destroy()

        except Exception as exc:
            messagebox.showerror("Export error", str(exc))


class ImportDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        entry_manager: Any,
        audit_logger: Optional[Any] = None,
    ):
        super().__init__(parent)

        self.title("Import Vault")
        self.geometry("850x620")
        self.resizable(True, True)

        self.entry_manager = entry_manager
        self.audit_logger = audit_logger
        self.importer = VaultImporter(entry_manager=entry_manager, audit_logger=audit_logger)

        self.file_path_var = ctk.StringVar()
        self.password_var = ctk.StringVar()
        self.format_var = ctk.StringVar(value="auto")
        self.mode_var = ctk.StringVar(value="merge")
        self.duplicate_var = ctk.StringVar(value="update")

        self.preview_result: Optional[Dict[str, Any]] = None

        self._build_ui()

        self.transient(parent)
        self.grab_set()
        self.focus()

    def _build_ui(self):
        root = ctk.CTkFrame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        top = ctk.CTkFrame(root)
        top.pack(fill="x", padx=12, pady=12)

        ctk.CTkLabel(top, text="Import settings", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=8)

        ctk.CTkLabel(top, text="File").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkEntry(top, textvariable=self.file_path_var).grid(row=1, column=1, sticky="ew", padx=8, pady=6)
        ctk.CTkButton(top, text="Browse", command=self._select_file).grid(row=1, column=2, padx=8, pady=6)

        ctk.CTkLabel(top, text="Format").grid(row=2, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkOptionMenu(top, variable=self.format_var, values=["auto", "encrypted_json", "csv", "lastpass_csv", "bitwarden_json"]).grid(row=2, column=1, sticky="ew", padx=8, pady=6)

        ctk.CTkLabel(top, text="Password").grid(row=3, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkEntry(top, textvariable=self.password_var, show="*").grid(row=3, column=1, sticky="ew", padx=8, pady=6)

        ctk.CTkLabel(top, text="Mode").grid(row=4, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkOptionMenu(top, variable=self.mode_var, values=["merge", "replace"]).grid(row=4, column=1, sticky="ew", padx=8, pady=6)

        ctk.CTkLabel(top, text="Conflicts").grid(row=5, column=0, sticky="w", padx=8, pady=6)
        ctk.CTkOptionMenu(top, variable=self.duplicate_var, values=["update", "skip", "error"]).grid(row=5, column=1, sticky="ew", padx=8, pady=6)

        top.grid_columnconfigure(1, weight=1)

        mid = ctk.CTkFrame(root)
        mid.pack(fill="both", expand=True, padx=12, pady=6)

        ctk.CTkLabel(mid, text="Preview of entries to be imported", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=8, pady=8)

        self.preview_box = ctk.CTkTextbox(mid)
        self.preview_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        bottom = ctk.CTkFrame(root)
        bottom.pack(fill="x", padx=12, pady=12)

        ctk.CTkButton(bottom, text="Preview", command=self._preview).pack(side="left", padx=6)
        ctk.CTkButton(bottom, text="Import", command=self._import).pack(side="right", padx=6)
        ctk.CTkButton(bottom, text="Cancel", fg_color="gray", command=self.destroy).pack(side="right", padx=6)

    def _select_file(self):
        path = filedialog.askopenfilename(
            title="Import vault",
            filetypes=[
                ("Supported files", "*.json *.csv"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )

        if path:
            self.file_path_var.set(path)

    def _preview(self):
        file_path = self.file_path_var.get().strip()

        if not file_path:
            messagebox.showerror("Import error", "Choose import file")
            return

        import_format = None if self.format_var.get() == "auto" else self.format_var.get()
        password = self.password_var.get() or None

        try:
            result = self.importer.import_file(
                file_path=file_path,
                password=password,
                mode=self.mode_var.get(),
                dry_run=True,
                import_format=import_format,
                duplicate_handling=self.duplicate_var.get(),
            )

            self.preview_result = result
            self.preview_box.delete("1.0", "end")
            self.preview_box.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))

        except Exception as exc:
            messagebox.showerror("Import preview error", str(exc))

    def _import(self):
        file_path = self.file_path_var.get().strip()

        if not file_path:
            messagebox.showerror("Import error", "Choose import file")
            return

        import_format = None if self.format_var.get() == "auto" else self.format_var.get()
        password = self.password_var.get() or None

        try:
            result = self.importer.import_file(
                file_path=file_path,
                password=password,
                mode=self.mode_var.get(),
                dry_run=False,
                import_format=import_format,
                duplicate_handling=self.duplicate_var.get(),
            )

            summary = json.dumps(result, ensure_ascii=False, indent=2)
            messagebox.showinfo("Import summary", summary)
            self.destroy()

        except Exception as exc:
            messagebox.showerror("Import error", str(exc))


class SharingDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        db_connection: Any,
        audit_logger: Optional[Any] = None,
        qr_service: Optional[QRCodeService] = None,
    ):
        super().__init__(parent)

        self.title("Share Entry")
        self.geometry("900x640")
        self.resizable(True, True)

        self.db_connection = db_connection
        self.audit_logger = audit_logger
        self.sharing_service = SharingService(db_connection=db_connection, audit_logger=audit_logger)
        self.qr_service = qr_service or QRCodeService()

        self.entries = self._load_entries()
        self.selected_entry_var = ctk.StringVar(value=self._default_entry_value())
        self.recipient_var = ctk.StringVar()
        self.method_var = ctk.StringVar(value="password_file")
        self.password_var = ctk.StringVar()
        self.expires_var = ctk.StringVar(value="7")
        self.read_var = ctk.BooleanVar(value=True)
        self.edit_var = ctk.BooleanVar(value=False)
        self.include_password_var = ctk.BooleanVar(value=True)

        self.current_share_package: Optional[Dict[str, Any]] = None

        self._build_ui()

        self.transient(parent)
        self.grab_set()
        self.focus()

    def _build_ui(self):
        root = ctk.CTkFrame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        left = ctk.CTkFrame(root)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        right = ctk.CTkFrame(root)
        right.pack(side="right", fill="both", expand=True, padx=(8, 0))

        ctk.CTkLabel(left, text="Sharing settings", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=12, pady=(12, 8))

        form = ctk.CTkFrame(left)
        form.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(form, text="Entry").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkOptionMenu(
            form,
            variable=self.selected_entry_var,
            values=[self._entry_option(entry) for entry in self.entries] or ["No entries"],
        ).grid(row=0, column=1, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(form, text="Recipient").grid(row=1, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkEntry(form, textvariable=self.recipient_var).grid(row=1, column=1, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(form, text="Delivery method").grid(row=2, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkOptionMenu(
            form,
            variable=self.method_var,
            values=["password_file", "password_qr", "plain_file"],
        ).grid(row=2, column=1, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(form, text="Share password").grid(row=3, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkEntry(form, textvariable=self.password_var, show="*").grid(row=3, column=1, sticky="ew", padx=8, pady=8)

        ctk.CTkLabel(form, text="Expiration days").grid(row=4, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkOptionMenu(form, variable=self.expires_var, values=[str(i) for i in range(1, 31)]).grid(row=4, column=1, sticky="ew", padx=8, pady=8)

        form.grid_columnconfigure(1, weight=1)

        permissions = ctk.CTkFrame(left)
        permissions.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(permissions, text="Permissions", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=8, pady=8)
        ctk.CTkCheckBox(permissions, text="Read", variable=self.read_var).pack(anchor="w", padx=8, pady=4)
        ctk.CTkCheckBox(permissions, text="Edit", variable=self.edit_var).pack(anchor="w", padx=8, pady=4)
        ctk.CTkCheckBox(permissions, text="Include password", variable=self.include_password_var).pack(anchor="w", padx=8, pady=4)

        actions = ctk.CTkFrame(left)
        actions.pack(fill="x", padx=12, pady=12)

        ctk.CTkButton(actions, text="Generate share package", command=self._generate_share).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="Save package to file", command=self._save_share_file).pack(side="left", padx=6)
        ctk.CTkButton(actions, text="Open QR viewer", command=self._open_qr_viewer).pack(side="left", padx=6)

        ctk.CTkLabel(right, text="Share history and status", font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=12, pady=(12, 8))

        self.status_box = ctk.CTkTextbox(right)
        self.status_box.pack(fill="both", expand=True, padx=12, pady=6)

        bottom = ctk.CTkFrame(right)
        bottom.pack(fill="x", padx=12, pady=12)
        ctk.CTkButton(bottom, text="Close", fg_color="gray", command=self.destroy).pack(side="right", padx=6)

    def _load_entries(self) -> List[Dict[str, Any]]:
        entries = []

        if hasattr(self.db_connection, "list_entries"):
            try:
                raw_entries = self.db_connection.list_entries()
            except Exception:
                raw_entries = []
        elif hasattr(self.db_connection, "entry_manager") and hasattr(self.db_connection.entry_manager, "list_entries"):
            try:
                raw_entries = self.db_connection.entry_manager.list_entries()
            except Exception:
                raw_entries = []
        else:
            raw_entries = []

        for entry in raw_entries:
            if isinstance(entry, dict):
                entries.append(dict(entry))
            elif hasattr(entry, "__dict__"):
                entries.append(dict(entry.__dict__))

        return entries

    def _entry_option(self, entry: Dict[str, Any]) -> str:
        entry_id = str(entry.get("id") or entry.get("entry_id") or entry.get("title"))
        title = str(entry.get("title") or entry.get("name") or "Untitled")
        username = str(entry.get("username") or "")
        return f"{entry_id} | {title} | {username}"

    def _default_entry_value(self) -> str:
        if not self.entries:
            return "No entries"
        return self._entry_option(self.entries[0])

    def _selected_entry_id(self) -> str:
        value = self.selected_entry_var.get()

        if value == "No entries":
            raise Sprint6DialogError("No entry selected")

        return value.split("|")[0].strip()

    def _permissions(self) -> Dict[str, Any]:
        return {
            "read": self.read_var.get(),
            "edit": self.edit_var.get(),
            "include_password": self.include_password_var.get(),
        }

    def _generate_share(self):
        try:
            recipient = self.recipient_var.get().strip()

            if not recipient:
                raise Sprint6DialogError("Recipient is required")

            method = self.method_var.get()

            if method in {"password_file", "password_qr"}:
                password = self.password_var.get()

                if not password:
                    raise Sprint6DialogError("Share password is required")

                result = self.sharing_service.share_entry_with_password(
                    entry_id=self._selected_entry_id(),
                    recipient=recipient,
                    password=password,
                    permissions=self._permissions(),
                    expires_in=int(self.expires_var.get()),
                )

            else:
                result = self.sharing_service.share_entry(
                    entry_id=self._selected_entry_id(),
                    recipient=recipient,
                    permissions=self._permissions(),
                    expires_in=int(self.expires_var.get()),
                )

            self.current_share_package = result["package"]

            self.status_box.delete("1.0", "end")
            self.status_box.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))

            messagebox.showinfo("Share", "Share package generated")

        except Exception as exc:
            messagebox.showerror("Share error", str(exc))

    def _save_share_file(self):
        if self.current_share_package is None:
            messagebox.showerror("Share error", "Generate share package first")
            return

        path = filedialog.asksaveasfilename(
            title="Save share package",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )

        if not path:
            return

        try:
            Path(path).write_text(json.dumps(self.current_share_package, ensure_ascii=False, indent=2), encoding="utf-8")
            messagebox.showinfo("Share", "Share package saved")
        except Exception as exc:
            messagebox.showerror("Share error", str(exc))

    def _open_qr_viewer(self):
        if self.current_share_package is None:
            messagebox.showerror("Share error", "Generate share package first")
            return

        payload = json.dumps(self.current_share_package, ensure_ascii=False, sort_keys=True).encode("utf-8")

        QRCodeViewerDialog(
            parent=self,
            qr_service=self.qr_service,
            payload=payload,
            payload_type="encrypted_entry",
            payload_info={
                "type": "encrypted_entry",
                "size": len(payload),
                "ttl_seconds": 300,
            },
        )


class QRCodeViewerDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        qr_service: QRCodeService,
        payload: bytes,
        payload_type: str = "generic",
        payload_info: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 300,
    ):
        super().__init__(parent)

        self.title("QR Code Viewer")
        self.geometry("700x760")
        self.resizable(True, True)

        self.qr_service = qr_service
        self.payload = payload
        self.payload_type = payload_type
        self.payload_info = payload_info or {}
        self.ttl_seconds = ttl_seconds
        self.remaining_seconds = ttl_seconds
        self.qr_photo = None
        self.qr_text_chunks: List[str] = []

        self._build_ui()
        self._generate_qr()
        self._tick()

        self.transient(parent)
        self.grab_set()
        self.focus()

    def _build_ui(self):
        root = ctk.CTkFrame(self)
        root.pack(fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(root, text="QR Code", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(12, 8))

        self.qr_label = ctk.CTkLabel(root, text="")
        self.qr_label.pack(pady=12)

        self.info_box = ctk.CTkTextbox(root, height=150)
        self.info_box.pack(fill="x", padx=12, pady=8)

        self.timer_label = ctk.CTkLabel(root, text="")
        self.timer_label.pack(pady=8)

        buttons = ctk.CTkFrame(root)
        buttons.pack(fill="x", padx=12, pady=12)

        ctk.CTkButton(buttons, text="Copy payload info", command=self._copy_info).pack(side="left", padx=6)
        ctk.CTkButton(buttons, text="Refresh QR", command=self._refresh_qr).pack(side="left", padx=6)
        ctk.CTkButton(buttons, text="Close", fg_color="gray", command=self.destroy).pack(side="right", padx=6)

    def _generate_qr(self):
        self.qr_text_chunks = self._build_qr_chunks_for_display()
        qr_data = self.qr_text_chunks[0] if self.qr_text_chunks else ""

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )

        qr.add_data(qr_data)
        qr.make(fit=True)

        image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        image = image.resize((420, 420))

        self.qr_photo = ImageTk.PhotoImage(image)
        self.qr_label.configure(image=self.qr_photo)

        info = {
            "payload_type": self.payload_type,
            "payload_size": len(self.payload),
            "chunks": len(self.qr_text_chunks),
            "ttl_seconds": self.ttl_seconds,
            "payload_info": self.payload_info,
        }

        self.info_box.delete("1.0", "end")
        self.info_box.insert("1.0", json.dumps(info, ensure_ascii=False, indent=2))

    def _build_qr_chunks_for_display(self) -> List[str]:
        import base64
        import hashlib
        import time

        timestamp = int(time.time())
        nonce = os.urandom(8).hex()

        payload = {
            "type": self.payload_type,
            "timestamp": timestamp,
            "ttl": self.ttl_seconds,
            "nonce": nonce,
            "data": base64.b64encode(self.payload).decode("ascii"),
        }

        checksum_data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload["checksum"] = hashlib.sha256(checksum_data).hexdigest()

        serialized = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        chunk_size = 1200
        chunks = []

        for i in range(0, len(serialized), chunk_size):
            chunk = serialized[i:i + chunk_size]
            chunk_num = i // chunk_size + 1
            total = (len(serialized) + chunk_size - 1) // chunk_size

            chunk_data = {
                "chunk": chunk_num,
                "total": total,
                "data": base64.b64encode(chunk).decode("ascii"),
                "checksum": hashlib.sha256(chunk).hexdigest()[:8],
            }

            chunks.append(json.dumps(chunk_data))

        return chunks

    def _copy_info(self):
        data = self.info_box.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(data)
        messagebox.showinfo("QR", "Payload information copied")

    def _refresh_qr(self):
        self.remaining_seconds = self.ttl_seconds
        self._generate_qr()

    def _tick(self):
        self.timer_label.configure(text=f"Auto-refresh in {self.remaining_seconds} seconds")

        if self.remaining_seconds <= 0:
            self._refresh_qr()

        self.remaining_seconds -= 1
        self.after(1000, self._tick)