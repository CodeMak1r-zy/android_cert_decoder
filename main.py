from __future__ import annotations

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from keystore_parser import CertInfo, KeystoreError, parse_keystore

ctk.set_appearance_mode("system")
ctk.set_default_color_theme("blue")

FONT_MONO = "Menlo" if sys.platform == "darwin" else "Consolas"

APPEARANCE_LABELS = {"跟随系统": "system", "浅色": "light", "深色": "dark"}


class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent: ctk.CTk, filename: str) -> None:
        super().__init__(parent)
        self.title("输入 Storepass")
        self.resizable(False, False)
        self.result: str | None = None
        self._show_password = False

        self.transient(parent)
        self.lift()

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)

        ctk.CTkLabel(
            container, text="Keystore 文件", font=ctk.CTkFont(size=12, weight="bold"), anchor="w"
        ).pack(fill=tk.X)
        ctk.CTkLabel(
            container,
            text=filename,
            text_color=("gray30", "gray70"),
            wraplength=340,
            justify=tk.LEFT,
            anchor="w",
        ).pack(fill=tk.X, pady=(2, 16))

        ctk.CTkLabel(
            container, text="Storepass", font=ctk.CTkFont(size=12, weight="bold"), anchor="w"
        ).pack(fill=tk.X)

        entry_row = ctk.CTkFrame(container, fg_color="transparent")
        entry_row.pack(fill=tk.X, pady=(4, 20))

        self.password_var = tk.StringVar()
        self._entry = ctk.CTkEntry(entry_row, textvariable=self.password_var, show="*", width=240)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._toggle_btn = ctk.CTkButton(
            entry_row, text="显示", width=52, command=self._toggle_visibility
        )
        self._toggle_btn.pack(side=tk.LEFT, padx=(8, 0))

        btn_row = ctk.CTkFrame(container, fg_color="transparent")
        btn_row.pack(fill=tk.X)

        ctk.CTkButton(btn_row, text="确定", width=80, command=self._confirm).pack(
            side=tk.RIGHT
        )
        ctk.CTkButton(
            btn_row,
            text="取消",
            width=80,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "gray90"),
            command=self._cancel,
        ).pack(side=tk.RIGHT, padx=(0, 8))

        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self.update_idletasks()
        self._center(parent)
        self.after(50, self._activate_modal)

    def _toggle_visibility(self) -> None:
        self._show_password = not self._show_password
        self._entry.configure(show="" if self._show_password else "*")
        self._toggle_btn.configure(text="隐藏" if self._show_password else "显示")

    def _activate_modal(self) -> None:
        self.focus_force()
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self._entry.focus_set()

    def _center(self, parent: ctk.CTk) -> None:
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        w, h = self.winfo_width(), self.winfo_height()
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
        self.geometry(f"+{x}+{y}")

    def _confirm(self) -> None:
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("提示", "请输入 storepass", parent=self)
            return
        self.result = password
        self.grab_release()
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.grab_release()
        self.destroy()


class App(ctk.CTk):
    _DROP_BORDER_DEFAULT = ("gray70", "gray35")
    _DROP_BORDER_ACTIVE = ("#3B8ED0", "#3B8ED0")
    _DROP_BG_DEFAULT = ("gray95", "gray17")
    _DROP_BG_ACTIVE = ("#DCEAFB", "#1B3A57")

    def __init__(self) -> None:
        super().__init__()
        self.title("Android Keystore Decoder")
        self.minsize(560, 580)
        self.geometry("640x660")

        self._pending_drop_after: str | None = None
        self._dnd_enabled = self._enable_dnd()

        self._build_ui()
        self._center_window()

    def _enable_dnd(self) -> bool:
        try:
            from tkinterdnd2 import TkinterDnD

            TkinterDnD._require(self)
            return True
        except (ImportError, RuntimeError, tk.TclError, AttributeError):
            return False

    def _center_window(self) -> None:
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- header -----------------------------------------------------
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky=tk.EW, padx=28, pady=(24, 8))
        header.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky=tk.W)

        ctk.CTkLabel(
            title_box, text="Keystore 证书解析", font=ctk.CTkFont(size=22, weight="bold")
        ).pack(anchor=tk.W)
        ctk.CTkLabel(
            title_box,
            text="选择或拖入 .keystore 文件，输入 storepass 获取证书指纹",
            font=ctk.CTkFont(size=13),
            text_color=("gray35", "gray65"),
        ).pack(anchor=tk.W, pady=(2, 0))

        self.appearance_menu = ctk.CTkOptionMenu(
            header,
            values=list(APPEARANCE_LABELS.keys()),
            width=112,
            command=self._on_appearance_change,
        )
        self.appearance_menu.set("跟随系统")
        self.appearance_menu.grid(row=0, column=1, sticky=tk.E)

        # --- file card ----------------------------------------------------
        file_card = ctk.CTkFrame(self, corner_radius=14)
        file_card.grid(row=1, column=0, sticky=tk.EW, padx=28, pady=8)
        file_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            file_card, text="文件", font=ctk.CTkFont(size=13, weight="bold"), anchor=tk.W
        ).grid(row=0, column=0, sticky=tk.W, padx=20, pady=(16, 4))

        self.drop_zone = ctk.CTkFrame(
            file_card,
            corner_radius=10,
            border_width=2,
            border_color=self._DROP_BORDER_DEFAULT,
            fg_color=self._DROP_BG_DEFAULT,
        )
        self.drop_zone.grid(row=1, column=0, sticky=tk.EW, padx=20, pady=(0, 12))
        self.drop_zone.grid_columnconfigure(0, weight=1)

        drop_inner = ctk.CTkFrame(self.drop_zone, fg_color="transparent")
        drop_inner.grid(row=0, column=0, sticky=tk.EW, padx=16, pady=20)
        drop_inner.grid_columnconfigure(0, weight=1)

        self.drop_hint_label = ctk.CTkLabel(
            drop_inner,
            text="将 .keystore 文件拖放到此处",
            font=ctk.CTkFont(size=13),
            text_color=("gray40", "gray60"),
        )
        self.drop_hint_label.grid(row=0, column=0, pady=(0, 6))

        self.file_path_var = tk.StringVar(value="未选择文件")
        self.file_path_label = ctk.CTkLabel(
            drop_inner,
            textvariable=self.file_path_var,
            font=ctk.CTkFont(size=12),
            text_color=("gray20", "gray85"),
            wraplength=520,
            justify=tk.LEFT,
        )
        self.file_path_label.grid(row=1, column=0)

        button_row = ctk.CTkFrame(file_card, fg_color="transparent")
        button_row.grid(row=2, column=0, sticky=tk.W, padx=20, pady=(0, 16))
        ctk.CTkButton(
            button_row, text="选择 .keystore 文件", command=self._select_file
        ).pack(side=tk.LEFT)

        if self._dnd_enabled:
            for widget in (self.drop_zone, drop_inner, self.drop_hint_label, self.file_path_label):
                self._register_drop_target(widget)
        else:
            self.drop_hint_label.configure(text="点击下方按钮选择 .keystore 文件")

        # --- result card ----------------------------------------------------
        result_card = ctk.CTkFrame(self, corner_radius=14)
        result_card.grid(row=2, column=0, sticky=tk.NSEW, padx=28, pady=(8, 24))
        result_card.grid_columnconfigure(0, weight=1)
        result_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            result_card, text="解析结果", font=ctk.CTkFont(size=13, weight="bold"), anchor=tk.W
        ).grid(row=0, column=0, sticky=tk.W, padx=20, pady=(16, 8))

        self.result_scroll = ctk.CTkScrollableFrame(result_card, fg_color="transparent")
        self.result_scroll.grid(row=1, column=0, sticky=tk.NSEW, padx=12, pady=(0, 16))

        self.placeholder = ctk.CTkLabel(
            self.result_scroll,
            text="选择 keystore 文件后将在此显示证书信息",
            font=ctk.CTkFont(size=13),
            text_color=("gray40", "gray60"),
        )
        self.placeholder.pack(anchor=tk.W, padx=8, pady=8)

    def _on_appearance_change(self, choice: str) -> None:
        ctk.set_appearance_mode(APPEARANCE_LABELS.get(choice, "system"))

    def _register_drop_target(self, widget: tk.Misc) -> None:
        from tkinterdnd2 import DND_FILES

        widget.drop_target_register(DND_FILES)
        widget.dnd_bind("<<Drop>>", self._on_drop)
        widget.dnd_bind("<<DragEnter>>", self._on_drag_enter)
        widget.dnd_bind("<<DragLeave>>", self._on_drag_leave)

    def _dnd_action(self) -> str:
        from tkinterdnd2 import COPY

        return COPY

    def _set_drop_zone_active(self, active: bool) -> None:
        if not self._dnd_enabled:
            return
        border = self._DROP_BORDER_ACTIVE if active else self._DROP_BORDER_DEFAULT
        bg = self._DROP_BG_ACTIVE if active else self._DROP_BG_DEFAULT
        self.drop_zone.configure(border_color=border, fg_color=bg)
        hint = "松开以导入 .keystore 文件" if active else "将 .keystore 文件拖放到此处"
        self.drop_hint_label.configure(text=hint)

    def _on_drag_enter(self, _event: tk.Event) -> str:
        self._set_drop_zone_active(True)
        return self._dnd_action()

    def _on_drag_leave(self, _event: tk.Event) -> str:
        self._set_drop_zone_active(False)
        return self._dnd_action()

    def _on_drop(self, event: tk.Event) -> str:
        self._set_drop_zone_active(False)
        paths = self.tk.splitlist(event.data)
        if not paths:
            return self._dnd_action()
        path = self._normalize_dropped_path(paths[0])
        if self._pending_drop_after is not None:
            self.after_cancel(self._pending_drop_after)
        self._pending_drop_after = self.after(0, lambda: self._process_keystore(path))
        return self._dnd_action()

    @staticmethod
    def _normalize_dropped_path(raw: str) -> str:
        path = raw.strip()
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        if path.startswith("file://"):
            from urllib.parse import unquote, urlparse

            path = unquote(urlparse(path).path)
        return path

    @staticmethod
    def _basename(path: str) -> str:
        return os.path.basename(path)

    def _process_keystore(self, path: str) -> None:
        self._pending_drop_after = None

        if not path.lower().endswith(".keystore"):
            messagebox.showwarning("提示", "仅支持 .keystore 文件", parent=self)
            return

        if not os.path.isfile(path):
            messagebox.showerror("错误", "文件不存在", parent=self)
            return

        self.file_path_var.set(path)
        dialog = PasswordDialog(self, self._basename(path))
        self.wait_window(dialog)

        if dialog.result is None:
            return

        try:
            certs = parse_keystore(path, dialog.result)
        except KeystoreError as exc:
            messagebox.showerror("解析失败", str(exc), parent=self)
            return

        self._show_results(certs)

    def _select_file(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 Keystore 文件",
            filetypes=[("Keystore 文件", "*.keystore"), ("所有文件", "*.*")],
        )
        if not path:
            return

        self._process_keystore(path)

    def _clear_results(self) -> None:
        for widget in self.result_scroll.winfo_children():
            widget.destroy()

    def _show_results(self, certs: list[CertInfo]) -> None:
        self._clear_results()

        for cert in certs:
            card = ctk.CTkFrame(self.result_scroll, corner_radius=10, fg_color=("gray92", "gray20"))
            card.pack(fill=tk.X, padx=4, pady=6)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill=tk.X, padx=18, pady=16)

            ctk.CTkLabel(
                inner, text=f"别名  {cert.alias}", font=ctk.CTkFont(size=14, weight="bold"), anchor=tk.W
            ).pack(fill=tk.X, pady=(0, 10))

            fields = [
                ("SHA256", cert.sha256, True),
                ("SHA1", cert.sha1, True),
                ("MD5", cert.md5, True),
                ("Subject", cert.subject, False),
                ("Issuer", cert.issuer, False),
                ("有效期", f"{cert.not_before:%Y-%m-%d} ~ {cert.not_after:%Y-%m-%d}", False),
            ]

            for label, value, copyable in fields:
                row = ctk.CTkFrame(inner, fg_color="transparent")
                row.pack(fill=tk.X, pady=(6, 0))

                ctk.CTkLabel(
                    row,
                    text=label,
                    width=70,
                    anchor=tk.NW,
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=("gray30", "gray70"),
                ).pack(side=tk.LEFT, anchor=tk.N)

                ctk.CTkLabel(
                    row,
                    text=value,
                    anchor=tk.W,
                    justify=tk.LEFT,
                    font=ctk.CTkFont(family=FONT_MONO, size=12),
                    wraplength=380,
                ).pack(side=tk.LEFT, fill=tk.X, expand=True)

                if copyable:
                    btn = ctk.CTkButton(row, text="复制", width=56, height=24, font=ctk.CTkFont(size=11))
                    btn.configure(command=lambda v=value, b=btn: self._copy(v, b))
                    btn.pack(side=tk.RIGHT, padx=(8, 0))

            self._add_public_key_block(inner, cert.public_key_pem)

    def _add_public_key_block(self, inner: ctk.CTkFrame, pem: str) -> None:
        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkLabel(
            header,
            text="公钥 (PEM)",
            anchor=tk.W,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("gray30", "gray70"),
        ).pack(side=tk.LEFT)

        btn = ctk.CTkButton(header, text="复制", width=56, height=24, font=ctk.CTkFont(size=11))
        btn.configure(command=lambda v=pem, b=btn: self._copy(v, b))
        btn.pack(side=tk.RIGHT)

        box = ctk.CTkTextbox(
            inner,
            height=118,
            wrap="none",
            font=ctk.CTkFont(family=FONT_MONO, size=11),
            fg_color=("gray98", "gray14"),
        )
        box.pack(fill=tk.X, pady=(4, 0))
        box.insert("1.0", pem.strip())
        box.configure(state=tk.DISABLED)

    def _copy(self, text: str, button: ctk.CTkButton) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        button.configure(text="已复制")
        self.after(1200, lambda: button.configure(text="复制"))


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
