#!/usr/bin/env python3
"""
NetMind Desktop — Windows Edition
Fully Native PyQt6 Application for Windows.

Run: python NetMindDesktop.py  (as Administrator for network features)
"""
import sys, os, time, signal, webbrowser, pathlib, shutil, threading

_ROOT = os.path.dirname(os.path.abspath(__file__))
# Add core/ to path so all engine modules are importable without change
sys.path.insert(0, os.path.join(_ROOT, 'core'))
sys.path.insert(0, _ROOT)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QPushButton, QTextEdit, QLineEdit,
    QFrame, QStackedWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QSplitter, QProgressBar,
    QSystemTrayIcon, QMenu, QSizePolicy, QMessageBox,
    QSplashScreen, QAbstractItemView, QDialog,
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSize, QUrl,
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QColor, QPainter, QFont, QAction,
    QGuiApplication, QPen, QBrush, QLinearGradient,
    QFontDatabase,
)

# ── Base dir ────────────────────────────────────────────────────────
if getattr(sys, 'frozen', False):
    BASE = sys._MEIPASS          # type: ignore
else:
    BASE = os.path.dirname(os.path.abspath(__file__))

# ── Colours ─────────────────────────────────────────────────────────
BG0, BG1, BG2, BG3 = "#07090f", "#0d1117", "#141922", "#1c2333"
C1, C2, C3, C4     = "#00d4ff", "#7c3aed", "#00ffa3", "#f59e0b"
DANGER, TEXT, TEXT2 = "#ef4444", "#e2e8f0", "#94a3b8"

DARK_STYLE = f"""
QWidget {{ background:{BG0}; color:{TEXT}; font-family:Inter,system-ui,sans-serif; font-size:13px; }}
QFrame  {{ background:transparent; }}
QLabel  {{ background:transparent; }}
QLineEdit, QTextEdit {{
    background:{BG2}; border:1px solid rgba(255,255,255,.08);
    border-radius:8px; color:{TEXT}; padding:8px 12px; font-size:13px;
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color:{C1}; outline:none;
}}
QScrollBar:vertical {{
    background:{BG1}; width:6px; border:none; border-radius:3px;
}}
QScrollBar::handle:vertical {{
    background:#242d3e; border-radius:3px; min-height:20px;
}}
QScrollBar::handle:vertical:hover {{ background:{C1}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal {{ height:0; }}
QTableWidget {{
    background:{BG1}; border:none; gridline-color:rgba(255,255,255,.05);
    selection-background-color:rgba(0,212,255,.12);
}}
QTableWidget::item {{ padding:6px 10px; border-bottom:1px solid rgba(255,255,255,.04); }}
QTableWidget::item:selected {{ background:rgba(0,212,255,.12); color:{TEXT}; }}
QHeaderView::section {{
    background:{BG2}; color:{C1}; font-size:11px; font-weight:700;
    text-transform:uppercase; letter-spacing:0.8px;
    padding:8px 10px; border:none; border-bottom:1px solid rgba(255,255,255,.07);
}}
QToolTip {{
    background:{BG2}; color:{TEXT}; border:1px solid rgba(0,212,255,.3);
    border-radius:6px; padding:6px 10px;
}}
QMenu {{
    background:{BG2}; border:1px solid rgba(255,255,255,.1); border-radius:8px; padding:4px;
}}
QMenu::item {{ padding:8px 20px; border-radius:4px; }}
QMenu::item:selected {{ background:rgba(0,212,255,.15); }}
QSplitter::handle {{ background:rgba(255,255,255,.05); width:1px; height:1px; }}
QMessageBox {{ background:{BG1}; }}
"""

# ── Helpers ─────────────────────────────────────────────────────────
def btn(text, style="primary", small=False):
    b = QPushButton(text)
    pad = "5px 13px" if small else "9px 18px"
    sz  = "12px" if small else "13px"
    base = f"font-size:{sz};font-weight:600;border-radius:8px;padding:{pad};border:none;"
    styles = {
        "primary": f"{base}background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C1},stop:1 {C2});color:#fff;",
        "success": f"{base}background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C3},stop:1 #00cc82);color:#0a0f1a;",
        "danger":  f"{base}background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {DANGER},stop:1 #c02020);color:#fff;",
        "outline": f"{base}background:transparent;color:{TEXT2};border:1px solid rgba(255,255,255,.12);",
        "ghost":   f"{base}background:rgba(255,255,255,.05);color:{TEXT2};",
    }
    b.setStyleSheet(styles.get(style, styles["ghost"]))
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b

def card(parent=None):
    f = QFrame(parent)
    f.setStyleSheet(f"""
        QFrame {{
            background:{BG2}; border:1px solid rgba(255,255,255,.07);
            border-radius:14px;
        }}
    """)
    return f

def lbl(text, size=13, bold=False, color=TEXT):
    l = QLabel(text)
    w = 700 if bold else 400
    l.setStyleSheet(f"color:{color};font-size:{size}px;font-weight:{w};background:transparent;")
    return l

def sep():
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet("background:rgba(255,255,255,.06);margin:4px 0;max-height:1px;")
    return f

def make_icon(size=64):
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    g = QLinearGradient(0, 0, size, size)
    g.setColorAt(0, QColor(C1)); g.setColorAt(1, QColor(C2))
    p.setBrush(QBrush(g)); p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(4, 4, size-8, size-8, size//4, size//4)
    p.setPen(QPen(QColor("white")))
    f = QFont("Inter", size//3, QFont.Weight.Black)
    p.setFont(f)
    p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "N")
    p.end()
    return QIcon(px)

GRAFANA_URL = "http://localhost:3000"

# ═══════════════════════════════════════════════════════════════════
# Worker threads
# ═══════════════════════════════════════════════════════════════════

class InitWorker(QThread):
    done   = pyqtSignal(dict)
    error  = pyqtSignal(str)
    def run(self):
        try:
            from core.platform_win import (
                get_default_interface, get_gateway_ip, get_local_ip,
                discover_devices_arp, WinTrafficMonitor, WinBandwidthLimiter,
                enable_ip_forwarding,
            )
            iface   = get_default_interface()
            gw_ip   = get_gateway_ip()
            my_ip   = get_local_ip()
            gw_mac  = ""
            my_mac  = ""
            raw_devs = discover_devices_arp()
            devices = {}
            for _, info in raw_devs.items():
                ip = info["ip"]; mac = info.get("mac", "")
                if ip in (gw_ip, my_ip):
                    continue
                devices[ip] = {"mac": mac, "name": info.get("hostname", f"Device-{ip.split('.')[-1]}")}
            device_ips = {ip: info for ip, info in devices.items()}
            monitor    = WinTrafficMonitor(device_ips)
            controller = WinBandwidthLimiter()
            controller.attach_monitor(monitor)   # wire blocking/limiting
            enable_ip_forwarding()

            self.done.emit({"iface": iface, "gw_ip": gw_ip, "gw_mac": gw_mac,
                            "my_ip": my_ip, "devices": devices,
                            "monitor": monitor, "tracker": None,
                            "controller": controller})
        except Exception as e:
            self.error.emit(str(e))

class ProfileWorker(QThread):
    done  = pyqtSignal(dict)
    error = pyqtSignal(str)
    def __init__(self, text, ollama_host):
        super().__init__(); self.text = text; self.host = ollama_host
    def run(self):
        try:
            from core.onboarding import OnboardingManager
            p = OnboardingManager(self.host).run_setup(self.text)
            self.done.emit(p)
        except Exception as e:
            self.error.emit(str(e))

class ChatWorker(QThread):
    reply = pyqtSignal(str)
    def __init__(self, agent, msg):
        super().__init__(); self.agent = agent; self.msg = msg
    def run(self):
        try:
            r = self.agent.chat(self.msg)
            self.reply.emit(r)
        except Exception as e:
            self.reply.emit(f"[Error] {e}")

class DiscoveryWorker(QThread):
    """Scans subnet for new devices periodically."""
    new_devices = pyqtSignal(dict)

    def __init__(self, iface, gw_ip, my_ip, gw_mac, my_mac, known_ips):
        super().__init__()
        self.iface = iface; self.gw_ip = gw_ip; self.my_ip = my_ip
        self.gw_mac = gw_mac; self.my_mac = my_mac; self.known_ips = set(known_ips)

    def run(self):
        try:
            from core.platform_win import discover_devices_arp
            raw_devs = discover_devices_arp()
            found = {}
            for _, info in raw_devs.items():
                ip = info["ip"]; mac = info.get("mac", "")
                if ip in (self.gw_ip, self.my_ip): continue
                if ip not in self.known_ips:
                    found[ip] = {"mac": mac, "name": info.get("hostname", f"Device-{ip.split('.')[-1]}")}
            if found:
                self.new_devices.emit(found)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
# Onboarding Page
# ═══════════════════════════════════════════════════════════════════

class OnboardingPage(QWidget):
    confirmed = pyqtSignal(dict)   # emits profile when user clicks Confirm

    def __init__(self, ollama_host, parent=None):
        super().__init__(parent)
        self.host    = ollama_host
        self.profile = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.setContentsMargins(60, 40, 60, 40)
        root.setSpacing(20)

        # ── Logo + title ──────────────────────────────────────────
        ico = QLabel("🧠"); ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ico.setStyleSheet("font-size:64px;background:transparent;")
        root.addWidget(ico)

        title = lbl("Welcome to NetMind", 32, bold=True)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"font-size:32px;font-weight:900;background:transparent;"
            f"color:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C1},stop:1 {C2});")
        root.addWidget(title)

        sub = lbl("Describe your network in plain language — AI generates your policy automatically.", 14, color=TEXT2)
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setWordWrap(True)
        root.addWidget(sub)

        # ── Input card ────────────────────────────────────────────
        c = card(); cl = QVBoxLayout(c); cl.setSpacing(12)
        root.addWidget(c)

        cl.addWidget(lbl("Describe your situation", 11, bold=True, color=C1))
        self.txt = QTextEdit()
        self.txt.setPlaceholderText(
            "Examples:\n"
            "• We're a coffee shop — customers need fast WiFi, staff PCs secondary\n"
            "• Small office with VoIP — protect call quality above everything\n"
            "• Home network — fair sharing, kids' streaming shouldn't lag gaming")
        self.txt.setFixedHeight(130)
        cl.addWidget(self.txt)

        row = QHBoxLayout(); row.setSpacing(10)
        self.btn_voice = btn("🎤  Voice Input", "ghost")
        self.btn_voice.clicked.connect(self._voice)
        self.btn_gen   = btn("Generate My Policy  →", "primary")
        self.btn_gen.clicked.connect(self._generate)
        row.addWidget(self.btn_voice); row.addStretch(); row.addWidget(self.btn_gen)
        cl.addLayout(row)

        self.err_lbl = lbl("", 12, color=DANGER)
        self.err_lbl.setWordWrap(True)
        self.err_lbl.hide()
        cl.addWidget(self.err_lbl)

        # ── Spinner label ─────────────────────────────────────────
        self.spin_lbl = lbl("⟳  Llama 3.1 is generating your policy…", 13, color=C1)
        self.spin_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spin_lbl.hide()
        root.addWidget(self.spin_lbl)

        # ── Profile preview ───────────────────────────────────────
        self.preview = card(); self.preview.hide()
        pl = QVBoxLayout(self.preview); pl.setSpacing(12)
        root.addWidget(self.preview)

        pl.addWidget(lbl("AI-Generated Policy", 11, bold=True, color=C1))
        self.prof_lbl = lbl("", 13); self.prof_lbl.setWordWrap(True)
        pl.addWidget(self.prof_lbl)

        prow = QHBoxLayout()
        b_redo    = btn("← Redo", "outline")
        b_confirm = btn("Confirm & Start  →", "success")
        b_redo.clicked.connect(self._redo)
        b_confirm.clicked.connect(self._confirm)
        prow.addWidget(b_redo); prow.addStretch(); prow.addWidget(b_confirm)
        pl.addLayout(prow)

    def _generate(self):
        text = self.txt.toPlainText().strip()
        if not text:
            self._show_err("Please describe your network situation first.")
            return
        self.err_lbl.hide()
        self.btn_gen.setEnabled(False)
        self.spin_lbl.show()
        self.preview.hide()
        self._worker = ProfileWorker(text, self.host)
        self._worker.done.connect(self._on_profile)
        self._worker.error.connect(self._on_err)
        self._worker.start()

    def _on_profile(self, profile):
        self.profile = profile
        self.spin_lbl.hide()
        self.btn_gen.setEnabled(True)
        # Build summary text
        bp = profile.get("bandwidth_policy", {})
        rules = profile.get("priority_rules", {})
        on  = [k.replace("_", " ") for k, v in rules.items() if v]
        txt = (f"<b>{profile.get('summary','')}</b><br>"
               f"<i>\"{profile.get('objective','')}\"</i><br><br>"
               f"<b>Rules:</b> {', '.join(on) or 'general'}<br>"
               f"<b>Max/device:</b> {bp.get('max_per_device_kbps',5120)} KB/s  |  "
               f"<b>Min:</b> {bp.get('min_guaranteed_kbps',256)} KB/s  |  "
               f"<b>Type:</b> {profile.get('business_type','general')}")
        self.prof_lbl.setText(txt)
        self.preview.show()

    def _on_err(self, msg):
        self.spin_lbl.hide()
        self.btn_gen.setEnabled(True)
        self._show_err(f"Error: {msg}")

    def _show_err(self, msg):
        self.err_lbl.setText(msg); self.err_lbl.show()

    def _redo(self):
        self.preview.hide()

    def _confirm(self):
        if self.profile:
            self.confirmed.emit(self.profile)

    def _voice(self):
        """Use browser Web Speech or SpeechRecognition."""
        try:
            import speech_recognition as sr
            rec = sr.Recognizer()
            with sr.Microphone() as src:
                self.btn_voice.setText("🔴  Listening…")
                QApplication.processEvents()
                audio = rec.listen(src, timeout=8, phrase_time_limit=10)
            text = rec.recognize_google(audio)
            self.txt.setPlainText(text)
            self.btn_voice.setText("🎤  Voice Input")
        except Exception as e:
            self.btn_voice.setText("🎤  Voice Input")
            self._show_err(f"Voice error: {e}")


# ═══════════════════════════════════════════════════════════════════
# Dashboard Page
# ═══════════════════════════════════════════════════════════════════

class DashboardPage(QWidget):
    request_reconfigure = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitor = self.controller = self.tracker = None
        self.autopilot = self.agent = None
        self.metrics_exporter = None      # Prometheus metrics exporter
        self._api_token = None             # Local REST API token
        self._api_server = None            # API server handle
        self.devices = {}; self.gw_ip = self.my_ip = self.iface = None
        self.gw_mac = self.my_mac = ""
        self.trusted_ips = set()          # IPs excluded from spoofing/monitoring
        self.monitoring = False; self.ollama = "http://localhost:11434"
        self._build()
        self._dev_timer  = QTimer(self); self._dev_timer.timeout.connect(self._refresh_devices)
        self._ap_timer   = QTimer(self); self._ap_timer.timeout.connect(self._refresh_autopilot)
        self._disc_timer = QTimer(self); self._disc_timer.timeout.connect(self._run_discovery)

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        # ── Header ──────────────────────────────────────────────
        hdr = QFrame(); hdr.setFixedHeight(56)
        hdr.setStyleSheet(f"QFrame{{background:{BG1};border-bottom:1px solid rgba(255,255,255,.07);}}")
        hl = QHBoxLayout(hdr); hl.setContentsMargins(20,0,16,0); hl.setSpacing(12)
        logo = QLabel("🧠  <b>NetMind</b>")
        logo.setStyleSheet(f"font-size:16px;color:{TEXT};background:transparent;")
        logo.setTextFormat(Qt.TextFormat.RichText)
        hl.addWidget(logo)
        self.profile_badge = QLabel()
        self.profile_badge.setStyleSheet(f"font-size:11px;color:{TEXT2};background:{BG3};border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:3px 12px;")
        hl.addWidget(self.profile_badge); hl.addStretch()
        self.pill_sys = self._pill("System")
        self.pill_mon = self._pill("Monitor")
        self.pill_ap  = self._pill("AutoPilot")
        for p in (self.pill_sys, self.pill_mon, self.pill_ap): hl.addWidget(p)
        hl.addSpacing(8)
        self.btn_init  = btn("Initialize","ghost",small=True);  self.btn_init.clicked.connect(self._init)
        self.btn_start = btn("▶ Start","success",small=True);   self.btn_start.setEnabled(False); self.btn_start.clicked.connect(self._start)
        self.btn_stop  = btn("■ Stop","danger",small=True);     self.btn_stop.setEnabled(False);  self.btn_stop.clicked.connect(self._stop)
        self.btn_graf  = btn("📊 Grafana","outline",small=True); self.btn_graf.clicked.connect(lambda: webbrowser.open(GRAFANA_URL))
        self.btn_recfg = btn("⚙ Config","outline",small=True);  self.btn_recfg.clicked.connect(self.request_reconfigure)
        self.btn_token = btn("🔗 API Token","outline",small=True); self.btn_token.clicked.connect(self._show_token_dialog)
        self.btn_token.setToolTip("Show the API token to link this tool to the NetMind website dashboard")
        for b in (self.btn_init, self.btn_start, self.btn_stop, self.btn_graf, self.btn_recfg, self.btn_token):
            hl.addWidget(b)
        root.addWidget(hdr)
        # ── Body ────────────────────────────────────────────────
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;}")
        body = QWidget(); bl = QVBoxLayout(body)
        bl.setContentsMargins(16,16,16,16); bl.setSpacing(12)
        scroll.setWidget(body); root.addWidget(scroll)
        # Stats row
        sr = QHBoxLayout(); sr.setSpacing(10)
        self.s_dev  = self._stat("0","Devices")
        self.s_down = self._stat("0","↓ MB/s",C1)
        self.s_up   = self._stat("0","↑ MB/s",C2)
        self.s_lim  = self._stat("0","Limited",C4)
        self.s_blk  = self._stat("0","Blocked",DANGER)
        self.s_ai   = self._stat("0","AI Cycles",C3)
        for s in (self.s_dev,self.s_down,self.s_up,self.s_lim,self.s_blk,self.s_ai):
            sr.addWidget(s[0])
        bl.addLayout(sr)
        # AutoPilot card
        apc = card(); apl = QVBoxLayout(apc)
        ah = QHBoxLayout(); ah.addWidget(lbl("🤖  AutoPilot",13,bold=True)); ah.addStretch()
        baps = btn("Start AP","success",small=True); baps.clicked.connect(self._ap_start)
        bapx = btn("Stop AP","danger",small=True);  bapx.clicked.connect(self._ap_stop)
        ah.addWidget(baps); ah.addWidget(bapx); apl.addLayout(ah)
        self.ap_lbl = QLabel("Initialize and start monitoring to activate AutoPilot.")
        self.ap_lbl.setStyleSheet(f"color:{TEXT2};font-size:12px;background:transparent;")
        self.ap_lbl.setWordWrap(True); apl.addWidget(self.ap_lbl)
        bl.addWidget(apc)
        # Device table
        dc = card(); dvl = QVBoxLayout(dc)
        dh = QHBoxLayout(); dh.addWidget(lbl("📡  Connected Devices",13,bold=True)); dh.addStretch()
        rb = btn("⟳ Scan",  "ghost",small=True); rb.clicked.connect(self._run_discovery); dh.addWidget(rb)
        dvl.addLayout(dh)
        self.tbl = QTableWidget(0, 7)
        self.tbl.setHorizontalHeaderLabels(
            ["IP / Name", "↓ KB/s", "↑ KB/s", "Status", "Activity", "Actions", "Trust"])
        self.tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for i in (1,2,3,5,6):
            self.tbl.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.setShowGrid(False)
        self.tbl.setStyleSheet(
            f"QTableWidget {{background:{BG2};gridline-color:transparent;}}"
            f"QTableWidget::item {{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.05);}}"
            f"QTableWidget::item:selected {{background:rgba(0,212,255,.12);}}"
            f"QHeaderView::section {{background:{BG3};color:{TEXT2};font-size:11px;"
            f"font-weight:700;padding:8px;border:none;border-bottom:2px solid rgba(0,212,255,.3);}}")
        self.tbl.setFixedHeight(300); dvl.addWidget(self.tbl)
        bl.addWidget(dc)
        # Bottom split
        bot = QHBoxLayout(); bot.setSpacing(12)
        # Decisions feed
        decc = card(); decl = QVBoxLayout(decc)
        drow = QHBoxLayout(); drow.addWidget(lbl("📋  AI Decision Log",13,bold=True))
        live = QLabel("● LIVE"); live.setStyleSheet(f"color:{C3};font-size:10px;font-weight:700;background:transparent;")
        drow.addWidget(live); drow.addStretch(); decl.addLayout(drow)
        self.dec_feed = QTextEdit(); self.dec_feed.setReadOnly(True)
        self.dec_feed.setStyleSheet(f"background:{BG1};border:none;font-size:11px;color:{TEXT2};")
        self.dec_feed.setFixedHeight(260); decl.addWidget(self.dec_feed)
        bot.addWidget(decc,1)
        # Chat
        cc = card(); cl = QVBoxLayout(cc)
        cl.addWidget(lbl("💬  AI Agent Chat",13,bold=True))
        self.chat_log = QTextEdit(); self.chat_log.setReadOnly(True)
        self.chat_log.setStyleSheet(f"background:{BG1};border:none;font-size:12px;")
        self.chat_log.setFixedHeight(200)
        self.chat_log.append(f'<span style="color:{C1}"><b>NetMind:</b></span> Hello! Ask me about your network.')
        cl.addWidget(self.chat_log)
        ci = QHBoxLayout(); ci.setSpacing(8)
        self.chat_in = QLineEdit(); self.chat_in.setPlaceholderText("Ask the AI agent… (Enter)")
        self.chat_in.returnPressed.connect(self._chat_send)
        bsend = btn("Send","primary",small=True); bsend.clicked.connect(self._chat_send)
        bana  = btn("Analyze","ghost",small=True); bana.clicked.connect(lambda: self._chat_run("Analyze the current network state briefly."))
        ci.addWidget(self.chat_in); ci.addWidget(bsend); ci.addWidget(bana); cl.addLayout(ci)
        bot.addWidget(cc,1); bl.addLayout(bot)
        # Override
        ovc = card(); ovl = QVBoxLayout(ovc)
        oh = QHBoxLayout(); oh.addWidget(lbl("🎛  Manual Override",13,bold=True)); oh.addStretch()
        brst = btn("Restore All","danger",small=True); brst.clicked.connect(self._restore_all); oh.addWidget(brst)
        ovl.addLayout(oh)
        fg = QHBoxLayout(); fg.setSpacing(8)
        self.ov_ip   = QLineEdit(); self.ov_ip.setPlaceholderText("Device IP  e.g. 192.168.1.50")
        self.ov_down = QLineEdit("1024"); self.ov_down.setFixedWidth(85); self.ov_down.setPlaceholderText("↓ KB/s")
        self.ov_up   = QLineEdit("512");  self.ov_up.setFixedWidth(85);   self.ov_up.setPlaceholderText("↑ KB/s")
        blim = btn("Limit","primary",small=True); blim.clicked.connect(self._ov_limit)
        bblk = btn("Block","danger",small=True);  bblk.clicked.connect(self._ov_block)
        bfre = btn("Free","success",small=True);  bfre.clicked.connect(self._ov_unblock)
        for w in (self.ov_ip,self.ov_down,self.ov_up,blim,bblk,bfre): fg.addWidget(w)
        fg.addStretch(); ovl.addLayout(fg)
        self.ov_msg = lbl("",12); ovl.addWidget(self.ov_msg)
        bl.addWidget(ovc)

    def _pill(self,t):
        l=QLabel(f"● {t}"); l.setStyleSheet(f"color:{TEXT2};font-size:11px;font-weight:600;padding:3px 10px;background:transparent;"); return l
    def _set_pill(self,l,on,col=C3):
        l.setStyleSheet(f"color:{col if on else TEXT2};font-size:11px;font-weight:{'700' if on else '600'};padding:3px 10px;background:transparent;")
    def _stat(self,v,lb,col=TEXT):
        c=card(); cl=QVBoxLayout(c); cl.setSpacing(2)
        vl=QLabel(v); vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.setStyleSheet(f"font-size:26px;font-weight:800;color:{col};background:transparent;")
        ll=QLabel(lb); ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ll.setStyleSheet(f"font-size:10px;color:{TEXT2};font-weight:600;background:transparent;")
        cl.addWidget(vl); cl.addWidget(ll); return c,vl
    def _sv(self,s,v): s[1].setText(str(v))

    def _init(self):
        self.btn_init.setEnabled(False); self.btn_init.setText("Scanning…")
        self._iw=InitWorker(); self._iw.done.connect(self._on_init); self._iw.error.connect(self._on_init_err); self._iw.start()

    def _on_init(self,d):
        self.monitor=d["monitor"]; self.controller=d["controller"]; self.tracker=d["tracker"]
        self.devices=d["devices"]; self.gw_ip=d["gw_ip"]; self.my_ip=d["my_ip"]
        self.gw_mac=d.get("gw_mac",""); self.my_mac=d.get("my_mac","")
        self.iface=d["iface"]
        self.btn_init.setText("✓ Ready"); self._set_pill(self.pill_sys,True); self.btn_start.setEnabled(True)
        self._sv(self.s_dev,len(self.devices))
        try:
            from core.net_agent import NetMindAgent; from core.tool import Config
            self.agent=NetMindAgent(self.monitor,self.controller,Config,ollama_host=self.ollama)
            self.agent.set_protected_ips(self.gw_ip,self.my_ip)
        except: self.agent=None

    def _on_init_err(self,e):
        self.btn_init.setEnabled(True); self.btn_init.setText("Initialize"); self._toast(f"Error: {e}",True)

    def _start(self):
        if not self.monitor: return
        # ── Step 1: Windows — no iptables/tc to flush ──
        # Windows controller has no TC state to reset
        # ── Step 2: Start monitors ────────────────────────────────────────────────
        self.monitor.start()
        if self.tracker: self.tracker.start()
        # Windows: no ARP spoofing — passive monitoring only
        # ── Step 4: Start Prometheus metrics exporter on port 9090 ───────────────
        try:
            # Windows: no site-packages hack needed
            from core.metrics_exporter import MetricsExporter
            # DashboardPage has .monitor, .devices, .controller — use it as adapter.
            self.metrics_exporter = MetricsExporter(self, port=9090)
            self.metrics_exporter.start()
            self._toast("📊 Metrics exporter started on :9090 — Grafana is receiving data")
        except Exception as _me:
            self._toast(f"⚠ Metrics exporter failed: {_me}", err=True)
            print(f"[!] Could not start metrics exporter: {_me}")
        # ── Step 5: Start local REST API for website integration ──────────────────
        try:
            import sys as _sys, os as _os
            _core_dir = _os.path.dirname(_os.path.abspath(__file__))
            # When frozen/run from project root, core/ may not be in sys.path
            if _core_dir not in _sys.path:
                _sys.path.insert(0, _core_dir)
            from core.api_server import create_api
            self._api_token = create_api(self)
            self._toast(f"🔗 API ready on :7070 — click 'API Token' to copy")
        except Exception as _ae:
            self._toast(f"⚠ API server failed: {_ae}", err=True)
            print(f"[!] Could not start API server: {_ae}")
        self.monitoring=True; self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        self._set_pill(self.pill_mon,True)
        self._dev_timer.start(3000)
        self._ap_timer.start(5000)
        self._disc_timer.start(30000)   # scan for new devices every 30 s
        from core.onboarding import load_profile
        if load_profile(): self._ap_start()

    def _stop(self):
        if QMessageBox.question(self,"Stop","Stop monitoring and restore the network?",
            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
        self._dev_timer.stop(); self._ap_timer.stop(); self._disc_timer.stop()
        if self.autopilot: self.autopilot.stop()
        if self.metrics_exporter:
            try: self.metrics_exporter.stop()
            except: pass
            self.metrics_exporter = None
        if self.tracker and hasattr(self.tracker, 'running'): self.tracker.running.set()
        if self.monitor: self.monitor.stop()
        if self.controller: self.controller.cleanup()
        from core.platform_win import disable_ip_forwarding; disable_ip_forwarding()
        self._api_token = None
        self.monitoring=False; self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self._set_pill(self.pill_mon,False); self._set_pill(self.pill_ap,False)

    def _ap_start(self):
        if not self.monitoring: self._toast("Start monitoring first.",True); return
        from core.onboarding import load_profile
        if not load_profile(): self._toast("Complete onboarding first.",True); return
        if self.autopilot and self.autopilot._running: return
        from core.autopilot import AutoPilot
        self.autopilot=AutoPilot(monitor=self.monitor,controller=self.controller,
            conn_tracker=self.tracker,devices=self.devices,
            protected_ips={self.gw_ip,self.my_ip},ollama_host=self.ollama)
        self.autopilot.start(); self._set_pill(self.pill_ap,True,C4)

    def _ap_stop(self):
        if self.autopilot: self.autopilot.stop()
        self._set_pill(self.pill_ap,False)

    def _tbl_btn(self, label, fg_hex, bg_hex):
        """Table action button — uses QPalette so Qt table can't override colors."""
        import re
        b = QPushButton(label)
        b.setFixedHeight(28)
        b.setFont(QFont("Inter", 11, QFont.Weight.Bold))
        # Strip rgba/hex and build a solid color for palette
        b.setStyleSheet(
            f"QPushButton {{background-color:{bg_hex}; color:{fg_hex};"
            f" border:2px solid {fg_hex}; border-radius:5px; padding:0 10px;"
            f" font-size:11px; font-weight:700;}}"
            f"QPushButton:hover {{background-color:{fg_hex}; color:#ffffff;}}"
            f"QPushButton:pressed {{background-color:{fg_hex}; color:#ffffff; border-color:{fg_hex};}}")
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        return b

    def _refresh_devices(self):
        if not self.monitor: return
        stats  = self.monitor.get_current_stats() if self.monitor.running else {}
        limits = self.controller.limits if self.controller else {}
        rows=[]; td=tu=0
        for ip, info in self.devices.items():
            u  = stats.get(ip, {"up":0,"down":0})
            dk = round(u.get("down",0), 1); uk = round(u.get("up",0), 1)
            td += dk; tu += uk
            il = ip in limits; ib = il and limits[ip].get("down",999)<=1
            trusted = ip in self.trusted_ips
            if trusted:
                st = "🔒 Trusted"
            elif ib:
                st = "⛔ Blocked"
            elif il:
                st = "🔴 Limited"
            elif dk > 10:
                st = "🟢 Active"
            else:
                st = "⚪ Idle"
            activity = "—"
            if not trusted:
                if self.tracker:
                    try: activity = self.tracker.get_summary(ip)
                    except: pass
                elif self.monitor:
                    try: activity = self.monitor.get_summary(ip)
                    except: pass

            rows.append((ip, info.get("name", ip), dk, uk, st, il, ib, activity, trusted))

        self.tbl.setRowCount(len(rows))
        self.tbl.setRowHeight(0, 36)
        for r, (ip, nm, dk, uk, st, il, ib, act, trusted) in enumerate(rows):
            self.tbl.setRowHeight(r, 36)
            # IP/Name
            name_item = QTableWidgetItem(f"{ip}\n{nm}")
            name_item.setFont(QFont("Inter", 10))
            self.tbl.setItem(r, 0, name_item)
            # Bandwidth
            for col, val in [(1, f"{dk}"), (2, f"{uk}")]:
                it = QTableWidgetItem(val)
                it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.tbl.setItem(r, col, it)
            # Status
            st_item = QTableWidgetItem(st)
            st_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.tbl.setItem(r, 3, st_item)
            # Activity
            act_item = QTableWidgetItem(act); act_item.setToolTip(act)
            self.tbl.setItem(r, 4, act_item)
            # ── Action buttons ────────────────────────────────────
            if not trusted:
                aw = QWidget(); aw.setStyleSheet(f"background:{BG2};")
                al = QHBoxLayout(aw); al.setContentsMargins(3,3,3,3); al.setSpacing(4)
                b_lim = self._tbl_btn("Limit",  "#f59e0b", "#3d2f00")
                b_blk = self._tbl_btn("Block",  "#ef4444", "#3d0000")
                b_fre = self._tbl_btn("Free",   "#00ffa3", "#003d26")
                b_lim.clicked.connect(lambda _, i=ip: self._quick_limit(i))
                b_blk.clicked.connect(lambda _, i=ip: self._quick_block(i))
                b_fre.clicked.connect(lambda _, i=ip: self._quick_free(i))
                al.addWidget(b_lim); al.addWidget(b_blk); al.addWidget(b_fre)
                self.tbl.setCellWidget(r, 5, aw)
            else:
                self.tbl.setItem(r, 5, QTableWidgetItem("—"))
            # ── Trust button ──────────────────────────────────────
            tw = QWidget(); tw.setStyleSheet(f"background:{BG2};")
            tl = QHBoxLayout(tw); tl.setContentsMargins(3,3,3,3)
            if trusted:
                b_tr = self._tbl_btn("Untrust", "#94a3b8", "#1c2333")
                b_tr.clicked.connect(lambda _, i=ip: self._untrust(i))
            else:
                b_tr = self._tbl_btn("Trust", "#00d4ff", "#001a26")
                b_tr.clicked.connect(lambda _, i=ip: self._trust(i))
            tl.addWidget(b_tr)
            self.tbl.setCellWidget(r, 6, tw)

        self._sv(self.s_dev, len(rows))
        self._sv(self.s_down, f"{td/1024:.1f}")
        self._sv(self.s_up,   f"{tu/1024:.1f}")
        self._sv(self.s_lim,  sum(1 for *_,il,ib,_,_ in rows if il and not ib))
        self._sv(self.s_blk,  sum(1 for *_,il,ib,_,_ in rows if ib))

    # ── Auto-discovery ────────────────────────────────────────────
    def _run_discovery(self):
        if not self.monitoring: return
        w = DiscoveryWorker(self.iface, self.gw_ip, self.my_ip,
                            self.gw_mac, self.my_mac, self.devices.keys())
        w.new_devices.connect(self._on_new_devices)
        w.start()
        self._dw = w   # keep reference

    def _on_new_devices(self, found: dict):
        """Called when DiscoveryWorker finds new IPs."""
        for ip, info in found.items():
            if ip in self.devices: continue
            self.devices[ip] = info
            # Add to TrafficMonitor and ConnectionTracker
            if self.monitor:
                self.monitor.devices[ip] = info
            if self.tracker:
                from collections import defaultdict
                self.tracker.connections[ip] = {
                    "domains": [], "ips": [], "ports": defaultdict(int),
                    "last_activity": 0}
            # Start spoofing if not trusted
            # Windows: add device to monitor (no iptables needed)
            if self.monitor:
                self.monitor.add_device(ip, info)
        self._sv(self.s_dev, len(self.devices))
        self._refresh_devices()

    # ── Trusted list ──────────────────────────────────────────────
    def _trust(self, ip):
        """Add device to trusted list — stop spoofing and monitoring it."""
        self.trusted_ips.add(ip)
        # Stop ARP spoofer
        if self.controller and ip in self.controller.spoofers:
            try: self.controller.spoofers[ip].stop()
            except: pass
            self.controller.spoofers.pop(ip, None)
        # Remove any limit
        if self.controller and ip in self.controller.limits:
            self.controller.remove_limit(ip)
        self._toast(f"✓ {ip} is now trusted — not monitored")
        self._refresh_devices()

    def _untrust(self, ip):
        """Remove device from trusted list — resume monitoring."""
        self.trusted_ips.discard(ip)
        if self.monitoring and self.controller and ip in self.devices:
            self.controller.start_spoofing(
                {"ip": ip, "mac": self.devices[ip].get("mac","")})
        self._toast(f"✓ {ip} removed from trusted list")
        self._refresh_devices()


    def _refresh_autopilot(self):
        if not self.autopilot: return
        s=self.autopilot.get_status()
        ago=f"{s.get('last_decision_ago_s','?')}s ago" if s.get('last_decision_ago_s') is not None else "never"
        self.ap_lbl.setText(f"<b>{'🟢 Running' if s.get('running') else '⏸ Stopped'}</b>  ·  "
            f"Decisions: {s.get('decision_count',0)}  ·  Interval: {s.get('interval_seconds',30)}s  ·  Last: {ago}")
        self._sv(self.s_ai,s.get("decision_count",0))
        from core.autopilot import load_decision_log
        decisions=load_decision_log(15)
        if decisions:
            parts=[]
            for d in reversed(decisions):
                ts=d.get("timestamp","")[-8:]
                acts=[a.get("type","") for a in d.get("actions_taken",[]) if a.get("type")!="get_network_stats"]
                act_s="  ".join(f'<b style="color:{C4}">[{a}]</b>' for a in acts) if acts else "—"
                reason=d.get("reasoning","")[:160]
                parts.append(f'<p style="margin:3px 0"><span style="color:{TEXT2};font-size:10px">{ts}</span>  {act_s}'
                             f'<br><span style="color:{TEXT2};font-size:11px">{reason}</span></p>'
                             f'<hr style="border-color:rgba(255,255,255,.05);margin:2px 0">')
            self.dec_feed.setHtml("".join(parts))

    def _chat_send(self):
        msg=self.chat_in.text().strip()
        if msg: self.chat_in.clear(); self._chat_run(msg)

    def _chat_run(self,msg):
        if not self.agent: self.chat_log.append(f'<span style="color:{DANGER}">Agent not initialized.</span>'); return
        self.chat_log.append(f'<span style="color:{C2}"><b>You:</b></span> {msg}')
        self._cw=ChatWorker(self.agent,msg); self._cw.reply.connect(self._chat_reply); self._cw.start()

    def _chat_reply(self,r):
        self.chat_log.append(f'<span style="color:{C1}"><b>NetMind:</b></span> {r}')
        self.chat_log.verticalScrollBar().setValue(self.chat_log.verticalScrollBar().maximum())

    def _ov_limit(self):
        ip = self.ov_ip.text().strip()
        if not ip: return
        try:
            d, u = int(self.ov_down.text()), int(self.ov_up.text())
            if not self.controller:
                self._ov_msg("Not initialized", True); return
            ok = self.controller.apply_limit(ip, d, u)
            self._ov_msg(f"✓ Limited {ip}" if ok else f"⚠ Limit failed for {ip}", not ok)
        except Exception as e:
            self._ov_msg(str(e), True)

    def _ov_block(self):
        ip = self.ov_ip.text().strip()
        try:
            ok = self.controller.apply_limit(ip, 1, 1) if self.controller and ip else False
            self._ov_msg(f"⛔ Blocked {ip}" if ok else "Failed", not ok)
        except Exception as e:
            self._ov_msg(str(e), True)

    def _ov_unblock(self):
        ip = self.ov_ip.text().strip()
        try:
            if self.controller and ip:
                self.controller.remove_limit(ip)
                self._ov_msg(f"✓ Freed {ip}")
        except Exception as e:
            self._ov_msg(str(e), True)

    def _restore_all(self):
        if not self.controller: return
        ips=list(self.controller.limits.keys())
        [self.controller.remove_limit(i) for i in ips]; self._ov_msg(f"✓ Restored {len(ips)} devices")

    def _quick_limit(self,ip): self.ov_ip.setText(ip); self._ov_limit()
    def _quick_block(self,ip): self.ov_ip.setText(ip); self._ov_block()
    def _quick_free(self,ip):  self.ov_ip.setText(ip); self._ov_unblock()

    def _ov_msg(self,t,err=False):
        self.ov_msg.setText(t)
        self.ov_msg.setStyleSheet(f"color:{DANGER if err else C3};font-size:12px;background:transparent;")
        QTimer.singleShot(4000,lambda:self.ov_msg.clear())

    def _toast(self,t,err=False): self._ov_msg(t,err)

    def _show_token_dialog(self):
        """Show a dialog with the API token so the user can copy it to the website."""
        import os
        token_file = os.path.expanduser("~/.netmind_api_token")
        token = self._api_token
        if not token and os.path.exists(token_file):
            with open(token_file) as f:
                token = f.read().strip()
        if not token:
            QMessageBox.warning(self, "API Token",
                "No API token found.\n\nClick ▶ Start first — the token is created when monitoring starts.")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("NetMind API Token")
        dlg.setMinimumWidth(520)
        dlg.setStyleSheet(f"QDialog{{background:{BG2};color:{TEXT};}}")
        vl = QVBoxLayout(dlg); vl.setSpacing(12); vl.setContentsMargins(20,20,20,20)
        vl.addWidget(lbl("🔗  Link to Website Dashboard", 15, bold=True))
        desc = QLabel(
            "Copy this token and paste it in:\n"
            "netmind.io → Dashboard → Settings → Link NetMind Tool"
        )
        desc.setStyleSheet(f"color:{TEXT2};font-size:13px;background:transparent;")
        desc.setWordWrap(True)
        vl.addWidget(desc)
        tok_box = QLineEdit(token)
        tok_box.setReadOnly(True)
        tok_box.setStyleSheet(
            f"background:{BG3};color:{C1};border:1px solid {C1};border-radius:7px;"
            f"padding:10px;font-family:monospace;font-size:13px;letter-spacing:1px;"
        )
        vl.addWidget(tok_box)
        file_lbl = QLabel(f"Token file: {token_file}")
        file_lbl.setStyleSheet(f"color:{TEXT2};font-size:11px;background:transparent;")
        vl.addWidget(file_lbl)
        rl = QHBoxLayout()
        copy_btn = btn("Copy Token", "primary", small=True)
        def _copy():
            QGuiApplication.clipboard().setText(token)
            copy_btn.setText("✓ Copied!")
            QTimer.singleShot(2000, lambda: copy_btn.setText("Copy Token"))
        copy_btn.clicked.connect(_copy)
        close_btn = btn("Close", "ghost", small=True)
        close_btn.clicked.connect(dlg.accept)
        rl.addStretch(); rl.addWidget(copy_btn); rl.addWidget(close_btn)
        vl.addLayout(rl)
        dlg.exec()

    def set_profile(self,p):
        self.profile_badge.setText(f"⚙  {(p.get('summary') or p.get('objective',''))[:60]}")

    def set_ollama(self,h): self.ollama=h

    def cleanup(self):
        self._dev_timer.stop(); self._ap_timer.stop()
        try: self._ap_stop()
        except: pass
        try:
            if self.tracker: self.tracker.running.set()
            if self.monitor: self.monitor.stop()
            if self.controller: self.controller.cleanup()
            from core.platform_win import disable_ip_forwarding; disable_ip_forwarding()
        except: pass
        for d in pathlib.Path(BASE).rglob("__pycache__"): shutil.rmtree(d,ignore_errors=True)
        for f in pathlib.Path(BASE).rglob("*.pyc"): f.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════════
# Custom Frameless Title Bar
# ═══════════════════════════════════════════════════════════════════

class TitleBar(QFrame):
    def __init__(self, win):
        super().__init__(win)
        self._win = win; self._drag = None
        self.setFixedHeight(44)
        self.setStyleSheet(f"QFrame{{background:{BG1};border-bottom:1px solid rgba(255,255,255,.07);}}")
        hl = QHBoxLayout(self); hl.setContentsMargins(14, 0, 8, 0); hl.setSpacing(8)

        # Icon + title (only shown on onboarding; dashboard has its own header)
        self._ico = QLabel("🧠"); self._ico.setStyleSheet("font-size:22px;background:transparent;")
        self._ttl = QLabel("NetMind")
        self._ttl.setStyleSheet(f"font-size:14px;font-weight:800;color:{TEXT};background:transparent;letter-spacing:-0.3px;")
        self._badge = QLabel("AI Autopilot")
        self._badge.setStyleSheet(f"font-size:10px;font-weight:700;color:{C1};background:rgba(0,212,255,.1);"
                                   f"border:1px solid rgba(0,212,255,.25);border-radius:8px;padding:2px 8px;")
        hl.addWidget(self._ico); hl.addWidget(self._ttl); hl.addWidget(self._badge)
        hl.addStretch()

        bstyle = (f"QPushButton{{background:transparent;border:none;color:{TEXT2};"
                  f"font-size:13px;border-radius:5px;padding:3px 8px;min-width:26px;}}"
                  f"QPushButton:hover{{background:rgba(255,255,255,.08);color:{TEXT};}}")
        xstyle = (f"QPushButton{{background:transparent;border:none;color:{TEXT2};"
                  f"font-size:13px;border-radius:5px;padding:3px 8px;min-width:26px;}}"
                  f"QPushButton:hover{{background:#c02020;color:#fff;}}")

        for txt, slot, st in [("─", win.showMinimized, bstyle),
                               ("□", self._toggle_max,  bstyle),
                               ("✕", win.close,         xstyle)]:
            b = QPushButton(txt); b.setStyleSheet(st); b.clicked.connect(slot)
            hl.addWidget(b)

    def _toggle_max(self):
        self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()

    def set_onboarding_mode(self, yes):
        for w in (self._ico, self._ttl, self._badge):
            w.setVisible(yes)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self._win.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag and e.buttons() == Qt.MouseButton.LeftButton:
            self._win.move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, e): self._drag = None
    def mouseDoubleClickEvent(self, e): self._toggle_max()


# ═══════════════════════════════════════════════════════════════════
# Main Application Window
# ═══════════════════════════════════════════════════════════════════

class NetMindWindow(QMainWindow):
    def __init__(self, ollama_host="http://localhost:11434"):
        super().__init__()
        self.ollama = ollama_host
        self.setWindowTitle("NetMind")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setWindowIcon(make_icon(64))
        self.setMinimumSize(1100, 720)

        # Center on screen
        scr = QGuiApplication.primaryScreen().availableGeometry()
        self.resize(min(1500, scr.width() - 80), min(900, scr.height() - 60))
        self.move((scr.width() - self.width()) // 2, (scr.height() - self.height()) // 2)

        # Root
        root = QWidget(); self.setCentralWidget(root)
        root.setStyleSheet(f"QWidget{{background:{BG0};}}")
        vbox = QVBoxLayout(root); vbox.setContentsMargins(0,0,0,0); vbox.setSpacing(0)

        # Title bar
        self.tbar = TitleBar(self); vbox.addWidget(self.tbar)

        # Stacked pages
        self.stack = QStackedWidget(); vbox.addWidget(self.stack)

        # Check if onboarding already done
        from core.onboarding import load_profile
        profile = load_profile()

        self.ob_page   = OnboardingPage(ollama_host)
        self.dash_page = DashboardPage()
        self.dash_page.set_ollama(ollama_host)
        self.stack.addWidget(self.ob_page)    # index 0
        self.stack.addWidget(self.dash_page)  # index 1

        self.ob_page.confirmed.connect(self._on_onboarding_done)
        self.dash_page.request_reconfigure.connect(self._go_onboarding)

        if profile:
            self._show_dashboard(profile)
        else:
            self._go_onboarding()

        # System tray
        self._setup_tray()

    # ── Page navigation ──────────────────────────────────────────
    def _go_onboarding(self):
        self.stack.setCurrentIndex(0)
        self.tbar.set_onboarding_mode(True)

    def _on_onboarding_done(self, profile):
        self._show_dashboard(profile)

    def _show_dashboard(self, profile):
        self.dash_page.set_profile(profile)
        self.stack.setCurrentIndex(1)
        self.tbar.set_onboarding_mode(False)  # dashboard has its own header

    # ── System Tray ──────────────────────────────────────────────
    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable(): return
        self.tray = QSystemTrayIcon(make_icon(32), self)
        self.tray.setToolTip("NetMind — AI Bandwidth Manager")
        m = QMenu()
        m.setStyleSheet(f"QMenu{{background:{BG2};border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:4px;}}"
                        f"QMenu::item{{padding:8px 20px;border-radius:4px;}}"
                        f"QMenu::item:selected{{background:rgba(0,212,255,.15);}}")
        a_show = QAction("Show NetMind", self); a_show.triggered.connect(self._show_from_tray)
        a_graf = QAction("Open Grafana",  self); a_graf.triggered.connect(lambda: webbrowser.open(GRAFANA_URL))
        a_quit = QAction("Quit",          self); a_quit.triggered.connect(self._quit)
        m.addAction(a_show); m.addAction(a_graf); m.addSeparator(); m.addAction(a_quit)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self._show_from_tray() if r == QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def _show_from_tray(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    # ── Close / Quit ─────────────────────────────────────────────
    def closeEvent(self, e):
        if hasattr(self, 'tray') and self.tray.isVisible():
            self.hide()
            self.tray.showMessage("NetMind", "Running in background — right-click tray icon to quit.",
                                  QSystemTrayIcon.MessageIcon.Information, 2500)
            e.ignore()
        else:
            self._quit()

    def _quit(self):
        self.dash_page.cleanup()
        if hasattr(self, 'tray'): self.tray.hide()
        QApplication.quit()


# ═══════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    # SIGINT: graceful exit on Ctrl+C (works on Windows too)
    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    except (OSError, ValueError):
        pass  # signal handling may not work in all Windows contexts
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("NetMind")
    app.setApplicationDisplayName("NetMind")
    app.setOrganizationName("NetMind")
    app.setStyleSheet(DARK_STYLE)

    # Splash
    splash_px = QPixmap(480, 260)
    splash_px.fill(QColor(BG1))
    sp = QPainter(splash_px)
    sp.setRenderHint(QPainter.RenderHint.Antialiasing)
    g = QLinearGradient(0, 0, 480, 260)
    g.setColorAt(0, QColor(C1)); g.setColorAt(1, QColor(C2))
    sp.setPen(QPen(QColor(C1))); sp.setBrush(QBrush(g))
    sp.drawEllipse(190, 20, 100, 100)
    sp.setPen(QPen(QColor("white")))
    sp.setFont(QFont("Inter", 42, QFont.Weight.Black))
    sp.drawText(190, 20, 100, 100, Qt.AlignmentFlag.AlignCenter, "N")
    sp.setPen(QPen(QColor(TEXT)))
    sp.setFont(QFont("Inter", 24, QFont.Weight.Bold))
    sp.drawText(0, 130, 480, 40, Qt.AlignmentFlag.AlignCenter, "NetMind")
    sp.setPen(QPen(QColor(TEXT2)))
    sp.setFont(QFont("Inter", 12))
    sp.drawText(0, 172, 480, 30, Qt.AlignmentFlag.AlignCenter, "AI-Powered Bandwidth Management")
    sp.setPen(QPen(QColor(C1)))
    sp.setFont(QFont("Inter", 11))
    sp.drawText(0, 218, 480, 26, Qt.AlignmentFlag.AlignCenter, "Loading…")
    sp.end()

    splash = QSplashScreen(splash_px, Qt.WindowType.WindowStaysOnTopHint)
    splash.show(); app.processEvents()

    # Ollama host from env
    ollama = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    win = NetMindWindow(ollama_host=ollama)
    win.show()
    splash.finish(win)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
