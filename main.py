from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from keystore_parser import CertInfo, KeystoreError, parse_keystore


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, filename: str) -> None:
        super().__init__(parent)
        self.title("输入 Storepass")
        self.resizable(False, False)
        self.result: str | None = None

        self.transient(parent)
        self.lift(parent)
        self.focus_force()

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Keystore 文件:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(frame, text=filename, wraplength=360).grid(
            row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 12)
        )

        ttk.Label(frame, text="Storepass:").grid(row=2, column=0, sticky=tk.W)
        self.password_var = tk.StringVar()
        self._entry = ttk.Entry(frame, textvariable=self.password_var, show="*", width=40)
        self._entry.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=(0, 16))

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, sticky=tk.E)

        ttk.Button(btn_frame, text="取消", command=self._cancel).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(btn_frame, text="确定", command=self._confirm).pack(side=tk.RIGHT)

        self.bind("<Return>", lambda _: self._confirm())
        self.bind("<Escape>", lambda _: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self.update_idletasks()
        self._center(parent)
        self.after(1, self._activate_modal)

    def _activate_modal(self) -> None:
        try:
            self.grab_set()
        except tk.TclError:
            pass
        self._entry.focus_set()

    def _center(self, parent: tk.Tk) -> None:
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


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Android Keystore Decoder")
        self.minsize(520, 480)
        self.geometry("600x560")
        self._drop_zone_default_bg = "#f5f5f5"
        self._drop_zone_active_bg = "#e8f0fe"
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
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("Title.TLabel", font=("", 16, "bold"))
        style.configure("Subtitle.TLabel", foreground="#666666")
        style.configure("Field.TLabel", font=("", 10, "bold"))
        style.configure("Value.TLabel", font=("Menlo", 10) if self._is_macos() else ("Consolas", 10))

        container = ttk.Frame(self, padding=24)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(container, text="Keystore 证书解析", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            container,
            text="选择或拖入 .keystore 文件，输入 storepass 获取 SHA1 / SHA256 指纹",
            style="Subtitle.TLabel",
        ).pack(anchor=tk.W, pady=(4, 20))

        file_frame = ttk.LabelFrame(container, text="文件", padding=12)
        file_frame.pack(fill=tk.X, pady=(0, 16))

        self.drop_zone = tk.Frame(
            file_frame,
            bg=self._drop_zone_default_bg,
            highlightthickness=2,
            highlightbackground="#cccccc",
            highlightcolor="#4a90e2",
        )
        self.drop_zone.pack(fill=tk.X, pady=(0, 8))

        drop_inner = tk.Frame(self.drop_zone, bg=self._drop_zone_default_bg)
        drop_inner.pack(fill=tk.X, padx=16, pady=20)

        self.drop_hint_label = tk.Label(
            drop_inner,
            text="将 .keystore 文件拖放到此处",
            bg=self._drop_zone_default_bg,
            fg="#666666",
            font=("", 11),
        )
        self.drop_hint_label.pack()

        self.file_path_var = tk.StringVar(value="未选择文件")
        self.file_path_label = tk.Label(
            drop_inner,
            textvariable=self.file_path_var,
            bg=self._drop_zone_default_bg,
            fg="#333333",
            font=("", 10),
            wraplength=500,
            justify=tk.LEFT,
        )
        self.file_path_label.pack(pady=(8, 0))

        ttk.Button(file_frame, text="选择 .keystore 文件", command=self._select_file).pack(anchor=tk.W)

        if self._dnd_enabled:
            self._register_drop_target(self.drop_zone)
            self._register_drop_target(drop_inner)
            self._register_drop_target(self.drop_hint_label)
            self._register_drop_target(self.file_path_label)
        else:
            self.drop_hint_label.configure(text="点击上方按钮选择 .keystore 文件")

        result_frame = ttk.LabelFrame(container, text="解析结果", padding=12)
        result_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(result_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=canvas.yview)
        self.result_inner = ttk.Frame(canvas)

        self.result_inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=self.result_inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.placeholder = ttk.Label(
            self.result_inner,
            text="选择 keystore 文件后将在此显示证书信息",
            style="Subtitle.TLabel",
        )
        self.placeholder.pack(anchor=tk.W)

        self.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        self.bind("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        self.bind("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

    @staticmethod
    def _is_macos() -> bool:
        import sys

        return sys.platform == "darwin"

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
        bg = self._drop_zone_active_bg if active else self._drop_zone_default_bg
        for widget in (self.drop_zone, self.drop_hint_label, self.file_path_label):
            widget.configure(bg=bg)
        hint = "松开以导入 .keystore 文件" if active else "将 .keystore 文件拖放到此处"
        self.drop_hint_label.configure(text=hint, fg="#1a73e8" if active else "#666666")

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
        for widget in self.result_inner.winfo_children():
            widget.destroy()

    def _show_results(self, certs: list[CertInfo]) -> None:
        self._clear_results()

        for i, cert in enumerate(certs):
            if i > 0:
                ttk.Separator(self.result_inner, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=12)

            block = ttk.Frame(self.result_inner)
            block.pack(fill=tk.X, anchor=tk.W)

            ttk.Label(block, text=f"别名: {cert.alias}", style="Field.TLabel").pack(anchor=tk.W)

            fields = [
                ("SHA256", cert.sha256),
                ("SHA1", cert.sha1),
                ("MD5", cert.md5),
                ("Subject", cert.subject),
                ("Issuer", cert.issuer),
                ("有效期", f"{cert.not_before:%Y-%m-%d} ~ {cert.not_after:%Y-%m-%d}"),
            ]

            for label, value in fields:
                row = ttk.Frame(block)
                row.pack(fill=tk.X, pady=(8, 0))

                ttk.Label(row, text=f"{label}:", width=10, style="Field.TLabel").pack(side=tk.LEFT, anchor=tk.N)
                ttk.Label(row, text=value, style="Value.TLabel", wraplength=420).pack(
                    side=tk.LEFT, fill=tk.X, expand=True
                )

                if label in ("SHA256", "SHA1", "MD5"):
                    ttk.Button(
                        row,
                        text="复制",
                        width=6,
                        command=lambda v=value: self._copy(v),
                    ).pack(side=tk.RIGHT, padx=(8, 0))

    def _copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
