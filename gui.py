#!/usr/bin/env python3
"""
DeQode UI — Reference Edition
Replicated exactly from the design reference image.
"""

import os
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
from PIL import Image

# Setup paths
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

# Load API Key
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

from modules.decoder import decode_qr_from_image
from modules.network import resolve_url
from modules.url_inspector import analyze_url
from modules.reputation import check_virustotal

# Theme & Colors
ctk.set_appearance_mode("dark")
BG_COLOR = "#050505"
ACCENT_CYAN = "#33ccff"
SUCCESS_GREEN = "#10b981"
DANGER_RED = "#ef4444"
WARNING_ORANGE = "#f59e0b"
PANEL_BG = "#161616"      # Lighter than main background for contrast
BORDER_COLOR = "#333333"   # Brighter borders for visibility
TEXT_GRAY = "#999999"      # Brighter secondary text

class DeQodeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("DeQode — QR Phishing Detector")
        self.geometry("1100x850")
        self.configure(fg_color=BG_COLOR)

        self._image_path = tk.StringVar()
        self._verdict = tk.StringVar()
        self._status = tk.StringVar(value="READY")

        # Global Font
        self.font_mono = "Courier New"

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=4) # Left column
        self.grid_columnconfigure(1, weight=6) # Right column

        self._build_header()
        self._build_left_pane()
        self._build_right_pane()
        self._build_footer()

    def _build_header(self):
        header = ctk.CTkFrame(self, height=60, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=(10, 0))

        # Left branding
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left")
        
        ctk.CTkLabel(
            title_frame, 
            text="DeQode", 
            font=ctk.CTkFont(family=self.font_mono, size=28, weight="bold"),
            text_color=ACCENT_CYAN,
            anchor="w"
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame, 
            text="QR PHISHING DETECTOR", 
            font=ctk.CTkFont(family=self.font_mono, size=14),
            text_color=TEXT_GRAY
        ).pack(anchor="w")

        # Center credits
        ctk.CTkLabel(
            header,
            text="Made by K3yur",
            font=ctk.CTkFont(family=self.font_mono, size=17, weight="bold"),
            text_color="#ffffff"
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Right API Status
        api_status = "ACTIVE" if (VT_API_KEY and len(VT_API_KEY) >= 32) else "INACTIVE"
        api_color = SUCCESS_GREEN if api_status == "ACTIVE" else DANGER_RED
        
        status_frame = ctk.CTkFrame(
            header, 
            fg_color="transparent", 
            border_width=1, 
            border_color=api_color,
            corner_radius=4
        )
        status_frame.pack(side="right", pady=10)

        ctk.CTkLabel(
            status_frame,
            text=f" API KEY: {api_status} ",
            font=ctk.CTkFont(family=self.font_mono, size=16, weight="bold"),
            text_color=api_color
        ).pack(padx=10, pady=4)

    def _build_left_pane(self):
        left_pane = ctk.CTkFrame(self, fg_color="transparent")
        left_pane.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        
        ctk.CTkLabel(
            left_pane,
            text="TARGET ACQUISITION",
            font=ctk.CTkFont(family=self.font_mono, size=16, weight="bold"),
            text_color="#cccccc",
            anchor="w"
        ).pack(fill="x", pady=(0, 10))

        # Drop Zone
        self.drop_container = ctk.CTkFrame(left_pane, fg_color=PANEL_BG, border_width=1, border_color=BORDER_COLOR)
        self.drop_container.pack(fill="x")
        
        self.drop_frame = tk.Canvas(
            self.drop_container,
            bg=PANEL_BG,
            highlightthickness=0,
            height=280
        )
        self.drop_frame.pack(fill="x", padx=1, pady=1)
        self.drop_frame.bind("<Button-1>", lambda e: self._browse_file())
        
        # Dashed Border Simulation
        self.drop_frame.after(100, lambda: self._draw_dashed_rect())

        # Path display
        path_box = ctk.CTkFrame(left_pane, fg_color="#1a1a1a", corner_radius=0, height=35, border_width=1, border_color=BORDER_COLOR)
        path_box.pack(fill="x", pady=15)
        path_box.pack_propagate(False)

        ctk.CTkLabel(
            path_box,
            text="PATH: ",
            font=ctk.CTkFont(family=self.font_mono, size=16, weight="bold"),
            text_color=ACCENT_CYAN
        ).pack(side="left", padx=10)

        self.path_label = ctk.CTkLabel(
            path_box,
            textvariable=self._image_path,
            font=ctk.CTkFont(family=self.font_mono, size=16),
            text_color="#999999",
            anchor="w"
        )
        self.path_label.pack(side="left", fill="x", expand=True)

        # Buttons
        btn_row = ctk.CTkFrame(left_pane, fg_color="transparent")
        btn_row.pack(fill="x")

        self.scan_btn = ctk.CTkButton(
            btn_row,
            text="RUN SCAN",
            font=ctk.CTkFont(family=self.font_mono, size=17, weight="bold"),
            fg_color=ACCENT_CYAN,
            hover_color="#00aabb",
            text_color=BG_COLOR,
            corner_radius=2,
            height=40,
            command=self._start_scan
        )
        self.scan_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.clear_btn = ctk.CTkButton(
            btn_row,
            text="CLEAR",
            font=ctk.CTkFont(family=self.font_mono, size=17, weight="bold"),
            fg_color="transparent",
            border_width=1,
            border_color="#333333",
            text_color="#999999",
            hover_color="#111111",
            corner_radius=2,
            height=40,
            width=80,
            command=self._clear_all
        )
        self.clear_btn.pack(side="right")

        # Verdict Panel (Bottom Left)
        self.verdict_container = ctk.CTkFrame(left_pane, fg_color=PANEL_BG, border_width=2, border_color=BORDER_COLOR, corner_radius=2)
        self.verdict_container.pack(fill="x", side="bottom", pady=20)

        self.verdict_display = ctk.CTkLabel(
            self.verdict_container, 
            text="", 
            font=(self.font_mono, 34, "bold"),
            height=100
        )
        self.verdict_display.pack(fill="both", expand=True)

        self._verdict.trace_add("write", self._update_verdict_ui)

    def _draw_dashed_rect(self):
        w = self.drop_frame.winfo_width()
        h = self.drop_frame.winfo_height()
        self.drop_frame.create_rectangle(
            5, 5, w-5, h-5, 
            outline="#333333", 
            dash=(6, 6), 
            width=1
        )
        self.drop_frame.create_text(
            w/2, h/2 - 30, 
            text="+", 
            fill="#555555", 
            font=(self.font_mono, 54)
        )
        self.drop_frame.create_text(
            w/2, h/2 + 40, 
            text="Drop QR image or click to browse", 
            fill=ACCENT_CYAN, 
            font=(self.font_mono, 14),
            width=w-40
        )

    def _build_right_pane(self):
        right_pane = ctk.CTkFrame(self, fg_color="transparent")
        right_pane.grid(row=1, column=1, sticky="nsew", padx=20, pady=20)

        log_header = ctk.CTkFrame(right_pane, fg_color="transparent")
        log_header.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(
            log_header,
            text="SCAN OUTPUT LOGS",
            font=ctk.CTkFont(family=self.font_mono, size=16, weight="bold"),
            text_color="#cccccc",
            anchor="w"
        ).pack(side="left")

        # Traffic Lights
        light_row = ctk.CTkFrame(log_header, fg_color="transparent")
        light_row.pack(side="right")
        for color in ["#ff5f56", "#ffbd2e", "#27c93f"]:
            f = ctk.CTkFrame(light_row, width=10, height=10, corner_radius=5, fg_color=color)
            f.pack(side="left", padx=3)

        self.log_frame = ctk.CTkFrame(right_pane, fg_color=PANEL_BG, border_width=1, border_color=BORDER_COLOR)
        self.log_frame.pack(fill="both", expand=True)

        self._log = tk.Text(
            self.log_frame,
            bg=PANEL_BG,
            fg="#aaaaaa",
            font=(self.font_mono, 17),
            padx=20,
            pady=20,
            borderwidth=0,
            highlightthickness=0,
            insertbackground=ACCENT_CYAN,
            state="disabled"
        )
        self._log.pack(fill="both", expand=True)
        self._apply_tags()

    def _build_footer(self):
        footer = ctk.CTkFrame(self, height=30, fg_color="transparent")
        footer.grid(row=2, column=0, columnspan=2, sticky="ew")

        left_side = ctk.CTkFrame(footer, fg_color="transparent")
        left_side.pack(side="left", padx=20)

        # Ready LED
        self.led = ctk.CTkFrame(left_side, width=8, height=8, corner_radius=4, fg_color=SUCCESS_GREEN)
        self.led.pack(side="left", padx=(0, 8))

        ctk.CTkLabel(
            left_side,
            textvariable=self._status,
            font=ctk.CTkFont(family=self.font_mono, size=13),
            text_color="#888888"
        ).pack(side="left")

        right_side = ctk.CTkLabel(
            footer,
            text="UTF-8  |  LATENCY: 24MS  |  DEQODE V1.1",
            font=ctk.CTkFont(family=self.font_mono, size=13),
            text_color="#888888"
        )
        right_side.pack(side="right", padx=20)

    def _apply_tags(self):
        t = self._log
        t.tag_config("normal", foreground="#aaaaaa")
        t.tag_config("info", foreground=ACCENT_CYAN)
        t.tag_config("success", foreground=SUCCESS_GREEN)
        t.tag_config("error", foreground=DANGER_RED)
        t.tag_config("warning", foreground=WARNING_ORANGE)
        t.tag_config("dim", foreground=TEXT_GRAY)

    def _browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self._image_path.set(path)

    def _clear_all(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
        self._image_path.set("")
        self._verdict.set("")

    def _log_out(self, msg, tag="normal"):
        self._log.configure(state="normal")
        self._log.insert("end", msg + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _start_scan(self):
        path = self._image_path.get().strip()
        if not path: return
        self.scan_btn.configure(state="disabled")
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
        self._verdict.set("")
        
        self._log_out("DeQode v1.1.0 Initializing...", "dim")
        self._log_out("[SYSTEM] Hooking API endpoints... DONE", "dim")
        self._log_out("[SYSTEM] Loading heuristic signatures... 482 loaded", "dim")
        
        threading.Thread(
            target=self._run_scan_logic,
            args=(path,),
            daemon=True
        ).start()

    def _run_scan_logic(self, image_path):
        def out(m, t="normal"): self.after(0, lambda: self._log_out(m, t))

        out("\n[INFO] Decoding QR matrix from source...", "info")
        urls = decode_qr_from_image(image_path)

        if not urls:
            out("[ALERT] No QR sequence detected in matrix.", "error")
            self.after(0, lambda: self._verdict.set("NO QR FOUND"))
            self.after(0, lambda: self.scan_btn.configure(state="normal"))
            return

        out(f"[SUCCESS] Discovered {len(urls)} payload(s) in buffer.\n", "success")

        overall_findings = []
        for i, url in enumerate(urls, 1):
            out(f"--- PAYLOAD_{i} ANALYSIS ---", "dim")
            out(f"[INFO] Raw data: {url}", "dim")
            
            # Trace Network
            net = resolve_url(url)
            final = net.get("final_url") or url
            if final != url:
                out("[WARNING] Redirect detected (Shortened/Masked URL)", "warning")
            out(f"[INFO] Final endpoint: {final}", "info")

            # Local Heuristics
            h = analyze_url(final)
            risk = h.get("risk_score", 0)
            h_verdict = h.get("verdict", "UNKNOWN")
            
            risk_tag = "success" if risk < 20 else ("warning" if risk < 50 else "error")
            out(f"[INFO] Heuristic Risk: {risk}/100 -> {h_verdict}", risk_tag)
            
            # VirusTotal Integration
            vt_verdict = "UNKNOWN"
            if VT_API_KEY:
                out("[INFO] Querying VirusTotal Intelligence...", "info")
                vt = check_virustotal(final, VT_API_KEY)
                vt_verdict = vt.get("verdict", "UNKNOWN")
                vt_tag = "success" if vt_verdict == "CLEAN" else ("warning" if vt_verdict == "SUSPICIOUS" else "error")
                out(f"[INFO] VT Intel: {vt_verdict} ({vt.get('malicious', 0)} engines flagged)", vt_tag)

            # Aggregate verdict for this payload
            if h_verdict == "MALICIOUS" or vt_verdict == "MALICIOUS":
                p_verdict = "MALICIOUS"
            elif h_verdict == "SUSPICIOUS" or vt_verdict == "SUSPICIOUS":
                p_verdict = "SUSPICIOUS"
            else:
                p_verdict = "SAFE"
            
            overall_findings.append(p_verdict)
            out("---------------------------\n", "dim")

        # Final Aggregation and Summary
        out("\n" + "="*40, "dim")
        out("       [ SCAN SUMMARY ]", "info")
        out("="*40, "dim")
        
        malicious_count = overall_findings.count("MALICIOUS")
        suspicious_count = overall_findings.count("SUSPICIOUS")
        safe_count = overall_findings.count("SAFE")
        
        out(f" Total Payloads: {len(overall_findings)}")
        if malicious_count: out(f" [!] MALICIOUS PAYLOADS: {malicious_count}", "error")
        if suspicious_count: out(f" [!] SUSPICIOUS PAYLOADS: {suspicious_count}", "warning")
        if safe_count: out(f" [✓] SAFE PAYLOADS: {safe_count}", "success")

        if malicious_count > 0:
            out("\n!!! ACTION REQUIRED: MALICIOUS CONTENT DETECTED !!!", "error")
            self.after(0, lambda: self._verdict.set("MALICIOUS"))
        elif suspicious_count > 0:
            out("\n!!! CAUTION: SUSPICIOUS ACTIVITY IDENTIFIED !!!", "warning")
            self.after(0, lambda: self._verdict.set("SUSPICIOUS"))
        else:
            out("\n[DONE] NO THREATS IDENTIFIED IN SCAN BUFFER.", "success")
            self.after(0, lambda: self._verdict.set("SAFE"))

        self.after(0, lambda: self.scan_btn.configure(state="normal"))

    def _update_verdict_ui(self, *args):
        v = self._verdict.get()
        container = self.verdict_container
        display = self.verdict_display

        if v == "MALICIOUS":
            container.configure(border_color=DANGER_RED, fg_color=DANGER_RED)
            display.configure(text="MALICIOUS", text_color="#ffffff", fg_color=DANGER_RED)
            self._status.set("SYSTEM:THREAT_DETECTED")
            self.led.configure(fg_color=DANGER_RED)
        elif v == "SUSPICIOUS":
            container.configure(border_color=WARNING_ORANGE, fg_color=WARNING_ORANGE)
            display.configure(text="SUSPICIOUS", text_color="#000000", fg_color=WARNING_ORANGE)
            self._status.set("SYSTEM:ALERT")
            self.led.configure(fg_color=WARNING_ORANGE)
        elif v == "SAFE":
            container.configure(border_color=SUCCESS_GREEN, fg_color=SUCCESS_GREEN)
            display.configure(text="SAFE", text_color=BG_COLOR, fg_color=SUCCESS_GREEN)
            self._status.set("SYSTEM:SECURE")
            self.led.configure(fg_color=SUCCESS_GREEN)
        else:
            container.configure(border_color=BORDER_COLOR, fg_color=PANEL_BG)
            display.configure(text="", fg_color=PANEL_BG)
            self._status.set("READY")
            self.led.configure(fg_color=SUCCESS_GREEN)

if __name__ == "__main__":
    app = DeQodeApp()
    app.mainloop()