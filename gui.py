#!/usr/bin/env python3
"""
DeQode GUI — QR Phishing Detector
A dark-themed desktop GUI with drag-and-drop QR scanning.
Run: python3 gui.py
"""

import os
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, font as tkfont

# ── Fix import path so modules/ is found ────────────────────────────────────
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# ── Load API key ─────────────────────────────────────────────────────────────
VT_API_KEY = ""
env_path = BASE_DIR / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            if line.startswith("VT_API_KEY="):
                VT_API_KEY = line.split("=", 1)[1].strip().strip('"').strip("'")
                break
if not VT_API_KEY:
    VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()

from modules.decoder       import decode_qr_from_image
from modules.network       import resolve_url
from modules.url_inspector import analyze_url
from modules.reputation    import check_virustotal

# ── Palette ──────────────────────────────────────────────────────────────────
BG        = "#0a0e1a"       # deep navy black
PANEL     = "#111827"       # dark panel
BORDER    = "#1e2d40"       # subtle border
ACCENT    = "#00d4ff"       # electric cyan
ACCENT2   = "#7c3aed"       # purple
DANGER    = "#ef4444"       # red
WARNING   = "#f59e0b"       # amber
SUCCESS   = "#10b981"       # emerald
TEXT      = "#e2e8f0"       # near-white
MUTED     = "#64748b"       # slate
GRID_LINE = "#0f172a"       # darker grid

FONT_MONO  = ("Courier New", 10)
FONT_TITLE = ("Courier New", 22, "bold")
FONT_BODY  = ("Courier New", 10)
FONT_SMALL = ("Courier New", 9)
FONT_BIG   = ("Courier New", 13, "bold")


def run_scan(image_path, log, verdict_var, status_var, scan_btn):
    """Run full DeQode scan pipeline in background thread."""

    def out(msg, tag="normal"):
        log.config(state="normal")
        log.insert("end", msg + "\n", tag)
        log.see("end")
        log.config(state="disabled")

    def set_status(msg):
        status_var.set(msg)

    log.config(state="normal")
    log.delete("1.0", "end")
    log.config(state="disabled")
    verdict_var.set("")

    set_status("Decoding QR code...")
    out(f"[*] Scanning: {Path(image_path).name}", "info")
    out("─" * 58, "divider")

    # ── Decode ────────────────────────────────────────────────────────────────
    urls = decode_qr_from_image(image_path)
    if not urls:
        out("[!] No QR code found in this image.", "error")
        verdict_var.set("NO QR FOUND")
        set_status("Ready")
        scan_btn.config(state="normal")
        return

    out(f"[+] Found {len(urls)} QR payload(s)\n", "success")

    overall_results = []

    for i, raw_url in enumerate(urls, 1):
        out(f"  PAYLOAD {i}", "header")
        out(f"  Original : {raw_url}", "info")

        # ── Network ───────────────────────────────────────────────────────────
        set_status("Tracing redirects...")
        out("\n[*] Tracing redirects...", "info")
        net = resolve_url(raw_url)
        final_url  = net.get("final_url") or raw_url
        net_error  = net.get("error")
        status_code = net.get("status_code")

        if net_error:
            out(f"  [!] Site unreachable — extracted: {final_url}", "warning")
        else:
            out(f"  Final URL : {final_url}", "normal")
            out(f"  Status    : {status_code}", "normal")
            if final_url != raw_url:
                out("  [!] Redirect detected — shortened URL unmasked!", "warning")

        # ── Heuristic ─────────────────────────────────────────────────────────
        set_status("Running heuristic scan...")
        out("\n[*] Local Heuristic Scan...", "info")
        h = analyze_url(final_url)
        h_verdict = h.get("verdict", "UNKNOWN")
        h_score   = h.get("risk_score", 0)
        flags     = h.get("flags", [])

        score_color = "success" if h_score < 20 else ("warning" if h_score < 50 else "error")
        out(f"  Verdict    : {h_verdict}", score_color)
        out(f"  Risk Score : {h_score}/100", score_color)
        if flags:
            for flag in flags:
                out(f"  ⚑  {flag}", "warning")
        else:
            out("  No structural red flags found.", "success")

        # ── VirusTotal ────────────────────────────────────────────────────────
        out("\n[*] VirusTotal Threat Intelligence...", "info")
        vt_verdict = "UNKNOWN"
        if not VT_API_KEY or len(VT_API_KEY) < 32:
            out("  [SKIP] No API key configured.", "muted")
        else:
            set_status("Querying VirusTotal (may take ~15s)...")
            vt = check_virustotal(final_url, VT_API_KEY)
            if vt.get("error"):
                out(f"  [ERROR] {vt['error']}", "error")
            else:
                vt_verdict = vt["verdict"]
                vt_color   = "success" if vt_verdict == "CLEAN" else ("warning" if vt_verdict == "SUSPICIOUS" else "error")
                out(f"  VT Verdict : {vt_verdict}", vt_color)
                out(f"  Malicious  : {vt['malicious']} / {vt['total_engines']} engines", vt_color)
                out(f"  Suspicious : {vt['suspicious']}", "normal")
                out(f"  Harmless   : {vt['harmless']}", "normal")

        # ── Final verdict ─────────────────────────────────────────────────────
        if h_verdict == "MALICIOUS" or vt_verdict == "MALICIOUS":
            overall = "MALICIOUS"
        elif h_verdict == "SUSPICIOUS" or vt_verdict == "SUSPICIOUS":
            overall = "SUSPICIOUS"
        else:
            overall = "SAFE"

        overall_results.append(overall)
        out("\n" + "─" * 58, "divider")

    # ── Show final verdict banner ─────────────────────────────────────────────
    if "MALICIOUS" in overall_results:
        verdict_var.set("MALICIOUS")
    elif "SUSPICIOUS" in overall_results:
        verdict_var.set("SUSPICIOUS")
    else:
        verdict_var.set("SAFE")

    set_status("Scan complete.")
    scan_btn.config(state="normal")


class DeQodeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DeQode — QR Phishing Detector")
        self.configure(bg=BG)
        self.geometry("820x680")
        self.resizable(True, True)
        self.minsize(700, 560)

        self._image_path = tk.StringVar()
        self._verdict    = tk.StringVar()
        self._status     = tk.StringVar(value="Ready")

        self._build_ui()
        self._apply_tags()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top header bar ────────────────────────────────────────────────────
        header = tk.Frame(self, bg=PANEL, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Cyan left accent bar
        tk.Frame(header, bg=ACCENT, width=4).pack(side="left", fill="y")

        tk.Label(
            header, text="DeQode", bg=PANEL, fg=ACCENT,
            font=FONT_TITLE
        ).pack(side="left", padx=(16, 6), pady=12)

        tk.Label(
            header, text="QR Phishing Detector",
            bg=PANEL, fg=MUTED, font=("Courier New", 11)
        ).pack(side="left", pady=20)

        # API key badge
        api_status = "API KEY ✓" if (VT_API_KEY and len(VT_API_KEY) >= 32) else "NO API KEY"
        api_color  = SUCCESS if "✓" in api_status else DANGER
        tk.Label(
            header, text=f"  {api_status}  ",
            bg=api_color, fg=BG, font=("Courier New", 9, "bold")
        ).pack(side="right", padx=16, pady=20)

        # ── Drop zone ─────────────────────────────────────────────────────────
        drop_frame = tk.Frame(self, bg=BG, pady=14)
        drop_frame.pack(fill="x", padx=20)

        self._drop_zone = tk.Label(
            drop_frame,
            text="[ DROP QR IMAGE HERE  or  CLICK TO BROWSE ]",
            bg=PANEL, fg=ACCENT,
            font=("Courier New", 11, "bold"),
            relief="flat",
            bd=0,
            pady=28,
            cursor="hand2"
        )
        self._drop_zone.pack(fill="x")
        self._drop_zone.bind("<Button-1>", self._browse_file)
        self._drop_zone.bind("<Enter>", lambda e: self._drop_zone.config(bg=BORDER, fg=TEXT))
        self._drop_zone.bind("<Leave>", lambda e: self._drop_zone.config(bg=PANEL, fg=ACCENT))

        # Dashed border effect via canvas overlay label
        self._drop_zone.config(
            highlightbackground=ACCENT, highlightthickness=1
        )

        # File path display
        path_frame = tk.Frame(self, bg=BG)
        path_frame.pack(fill="x", padx=20)

        tk.Label(path_frame, text="FILE:", bg=BG, fg=MUTED,
                 font=FONT_SMALL).pack(side="left")
        tk.Label(path_frame, textvariable=self._image_path,
                 bg=BG, fg=ACCENT, font=FONT_SMALL).pack(side="left", padx=6)

        # ── Scan button ───────────────────────────────────────────────────────
        btn_frame = tk.Frame(self, bg=BG, pady=10)
        btn_frame.pack(fill="x", padx=20)

        self._scan_btn = tk.Button(
            btn_frame,
            text="▶  RUN SCAN",
            bg=ACCENT, fg=BG,
            font=("Courier New", 12, "bold"),
            relief="flat", bd=0,
            padx=28, pady=10,
            cursor="hand2",
            activebackground="#00b8d9",
            activeforeground=BG,
            command=self._start_scan
        )
        self._scan_btn.pack(side="left")

        tk.Button(
            btn_frame,
            text="CLEAR",
            bg=PANEL, fg=MUTED,
            font=("Courier New", 10),
            relief="flat", bd=0,
            padx=16, pady=10,
            cursor="hand2",
            activebackground=BORDER,
            activeforeground=TEXT,
            command=self._clear
        ).pack(side="left", padx=(10, 0))

        # ── Verdict banner ────────────────────────────────────────────────────
        self._verdict_label = tk.Label(
            self, textvariable=self._verdict,
            bg=BG, fg=BG,
            font=("Courier New", 15, "bold"),
            pady=8
        )
        self._verdict_label.pack(fill="x", padx=20)
        self._verdict.trace_add("write", self._update_verdict_style)

        # ── Log output ────────────────────────────────────────────────────────
        log_frame = tk.Frame(self, bg=BORDER, padx=1, pady=1)
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 6))

        inner = tk.Frame(log_frame, bg=PANEL)
        inner.pack(fill="both", expand=True)

        self._log = tk.Text(
            inner,
            bg=PANEL, fg=TEXT,
            font=FONT_MONO,
            relief="flat", bd=0,
            padx=14, pady=12,
            state="disabled",
            wrap="word",
            cursor="arrow",
            selectbackground=BORDER,
            insertbackground=ACCENT
        )
        scrollbar = tk.Scrollbar(inner, command=self._log.yview,
                                 bg=PANEL, troughcolor=PANEL,
                                 relief="flat", bd=0, width=10)
        self._log.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._log.pack(fill="both", expand=True)

        # ── Status bar ────────────────────────────────────────────────────────
        status_bar = tk.Frame(self, bg=GRID_LINE, height=26)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)

        tk.Label(status_bar, textvariable=self._status,
                 bg=GRID_LINE, fg=MUTED,
                 font=("Courier New", 9),
                 padx=12).pack(side="left", pady=4)

        tk.Label(status_bar, text="v1.1  |  DeQode",
                 bg=GRID_LINE, fg=MUTED,
                 font=("Courier New", 9),
                 padx=12).pack(side="right", pady=4)

    def _apply_tags(self):
        t = self._log
        t.tag_config("normal",  foreground=TEXT)
        t.tag_config("info",    foreground=ACCENT)
        t.tag_config("success", foreground=SUCCESS)
        t.tag_config("error",   foreground=DANGER)
        t.tag_config("warning", foreground=WARNING)
        t.tag_config("muted",   foreground=MUTED)
        t.tag_config("header",  foreground=ACCENT2, font=("Courier New", 11, "bold"))
        t.tag_config("divider", foreground=BORDER)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse_file(self, event=None):
        path = filedialog.askopenfilename(
            title="Select QR Code Image",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.gif *.webp"),
                       ("All Files", "*.*")]
        )
        if path:
            self._image_path.set(path)
            self._drop_zone.config(
                text=f"  ✓  {Path(path).name}",
                fg=SUCCESS
            )

    def _start_scan(self):
        path = self._image_path.get().strip()
        if not path:
            self._browse_file()
            path = self._image_path.get().strip()
        if not path:
            return

        self._scan_btn.config(state="disabled")
        self._verdict_var_clear()
        threading.Thread(
            target=run_scan,
            args=(path, self._log, self._verdict, self._status, self._scan_btn),
            daemon=True
        ).start()

    def _verdict_var_clear(self):
        self._verdict.set("")
        self._verdict_label.config(bg=BG, fg=BG)

    def _clear(self):
        self._image_path.set("")
        self._drop_zone.config(
            text="[ DROP QR IMAGE HERE  or  CLICK TO BROWSE ]",
            fg=ACCENT
        )
        self._verdict_var_clear()
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")
        self._status.set("Ready")

    def _update_verdict_style(self, *args):
        v = self._verdict.get()
        if v == "MALICIOUS":
            self._verdict_label.config(
                bg=DANGER, fg="white",
                text="  ⚠  MALICIOUS — DO NOT OPEN THIS LINK  ⚠  "
            )
        elif v == "SUSPICIOUS":
            self._verdict_label.config(
                bg=WARNING, fg=BG,
                text="  ⚑  SUSPICIOUS — Proceed with extreme caution  ⚑  "
            )
        elif v == "SAFE":
            self._verdict_label.config(
                bg=SUCCESS, fg=BG,
                text="  ✓  SAFE — No threats detected  ✓  "
            )
        elif v == "NO QR FOUND":
            self._verdict_label.config(
                bg=MUTED, fg=TEXT,
                text="  ?  No QR code detected in image  "
            )
        else:
            self._verdict_label.config(bg=BG, fg=BG, text="")


if __name__ == "__main__":
    app = DeQodeApp()
    app.mainloop()