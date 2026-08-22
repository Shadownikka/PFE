#!/usr/bin/env python3
"""
NetMind Local REST API
──────────────────────
Exposes live tool data (devices, bandwidth, status) to the website dashboard.
Runs on port 7070, protected by a shared secret token stored at ~/.netmind_api_token.

The website backend proxies requests here so the browser never calls localhost directly.
"""

import json
import os
import secrets
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

def _get_real_user_home():
    """
    Return the real user's home directory even when the process runs as root
    (via sudo or pkexec). Falls back to os.path.expanduser('~') if undetermined.
    """
    import pwd
    # pkexec sets PKEXEC_UID to the invoking user's UID (integer string)
    pkexec_uid = os.environ.get("PKEXEC_UID")
    if pkexec_uid and pkexec_uid.isdigit():
        try:
            return pwd.getpwuid(int(pkexec_uid)).pw_dir
        except KeyError:
            pass
    # sudo sets SUDO_USER to the invoking username
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    # Fallback: current process owner
    return os.path.expanduser("~")


TOKEN_FILE  = os.path.join(_get_real_user_home(), ".netmind_api_token")
CONFIG_FILE = os.path.join(_get_real_user_home(), ".netmind_config")
API_PORT    = 7070
API_VERSION = "1.0.0"
PUSH_INTERVAL = 5   # seconds between pushes to the server


def _get_or_create_token():
    """Read existing token or generate a new one (mode 600)."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            token = f.read().strip()
            if token:
                return token
    token = secrets.token_urlsafe(32)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return token


# Module-level reference set by create_api()
_ai_instance = None
_api_token = None
_start_time = None
_token_cache = {"value": None, "ts": 0}   # file-read cache (5s TTL)


class NetMindAPIHandler(BaseHTTPRequestHandler):
    """Lightweight HTTP handler — no framework dependency (no Flask needed)."""

    # Suppress default stderr logging for each request
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _get_current_token(self):
        """
        Read the token from disk with a 5-second in-memory cache.
        This is the authoritative source — avoids any module-load-time
        resolution issues (wrong user home, cached module, etc.).
        """
        now = time.time()
        if now - _token_cache["ts"] < 5 and _token_cache["value"]:
            return _token_cache["value"]
        try:
            with open(TOKEN_FILE, "r") as f:
                tok = f.read().strip()
            if tok:
                _token_cache["value"] = tok
                _token_cache["ts"] = now
                return tok
        except OSError:
            pass
        # Fallback: module-level variable set by create_api()
        return _api_token

    def _check_auth(self):
        """Returns True if the request carries a valid X-NetMind-Token header."""
        provided = self.headers.get("X-NetMind-Token", "")
        if not provided:
            return False
        expected = self._get_current_token()
        return bool(expected) and provided == expected

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-NetMind-Token, Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        # ── /api/health — public (no auth) ──
        if path == "/api/health":
            self._send_json({
                "status": "online",
                "version": API_VERSION,
                "uptime_seconds": round(time.time() - _start_time, 1) if _start_time else 0,
            })
            return

        # ── /api/debug/token_loaded — public, for diagnosing auth issues ──
        if path == "/api/debug/token_loaded":
            import pwd, stat
            token_exists = os.path.exists(TOKEN_FILE)
            file_stat = os.stat(TOKEN_FILE) if token_exists else None
            try:
                owner = pwd.getpwuid(file_stat.st_uid).pw_name if file_stat else "N/A"
            except Exception:
                owner = str(file_stat.st_uid) if file_stat else "N/A"
            self._send_json({
                "token_file": TOKEN_FILE,
                "token_file_exists": token_exists,
                "token_file_owner": owner,
                "token_loaded_prefix": (_api_token[:12] + "...") if _api_token else None,
                "token_loaded_length": len(_api_token) if _api_token else 0,
                "process_uid": os.getuid(),
                "process_user": pwd.getpwuid(os.getuid()).pw_name,
                "SUDO_USER": os.environ.get("SUDO_USER", "not set"),
                "PKEXEC_UID": os.environ.get("PKEXEC_UID", "not set"),
                "resolved_home": _get_real_user_home(),
                "note": "This endpoint is public (no auth). Remove in production."
            })
            return

        # All other endpoints require authentication
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return

        ai = _ai_instance

        # Helper: safely get attributes that differ between NetMindAI and DashboardPage
        def _attr(obj, *names, default=None):
            for name in names:
                val = getattr(obj, name, None)
                if val is not None:
                    return val
            return default

        # ── /api/status ──
        if path == "/api/status":
            running = _attr(ai, 'running', 'monitoring', default=False)
            self._send_json({
                "running": bool(running),
                "uptime_seconds": round(time.time() - _start_time, 1) if _start_time else 0,
                "interface": _attr(ai, 'iface', default='unknown'),
                "gateway": _attr(ai, 'gateway_ip', 'gw_ip', default='unknown'),
                "device_count": len(ai.devices) if ai and ai.devices else 0,
                "auto_balance": _attr(ai, '_auto_balance_enabled', default=True),
            })
            return

        # ── /api/devices ──
        if path == "/api/devices":
            if not ai or not ai.devices:
                self._send_json({"devices": [], "total": 0})
                return

            monitor     = _attr(ai, 'monitor')
            controller  = _attr(ai, 'controller')
            conn_tracker = _attr(ai, 'conn_tracker', 'tracker')

            stats  = monitor.get_current_stats() if monitor else {}
            limits = controller.limits if controller else {}
            result = []

            for ip, info in ai.devices.items():
                s = stats.get(ip, {"up": 0, "down": 0})
                lim = limits.get(ip)
                up_kbps   = round(s["up"], 1)
                down_kbps = round(s["down"], 1)

                if lim and lim["down"] <= 1 and lim["up"] <= 1:
                    status = "blocked"
                elif lim:
                    status = "limited"
                elif down_kbps > 1 or up_kbps > 1:
                    status = "active"
                else:
                    status = "idle"

                activity = "N/A"
                if conn_tracker:
                    try:
                        activity = conn_tracker.get_summary(ip)
                    except Exception:
                        pass

                result.append({
                    "ip": ip,
                    "mac": info.get("mac", ""),
                    "name": info.get("name", ip),
                    "upload_kbps": up_kbps,
                    "download_kbps": down_kbps,
                    "upload_mbps": round(up_kbps * 8 / 1000, 2),
                    "download_mbps": round(down_kbps * 8 / 1000, 2),
                    "status": status,
                    "limit": lim,
                    "activity": activity,
                })

            self._send_json({"devices": result, "total": len(result)})
            return

        # ── /api/bandwidth ──
        if path == "/api/bandwidth":
            monitor = _attr(ai, 'monitor')
            if not ai or not monitor:
                self._send_json({
                    "total_download_kbps": 0, "total_upload_kbps": 0,
                    "total_download_mbps": 0, "total_upload_mbps": 0,
                })
                return

            stats = monitor.get_current_stats()
            total_down = sum(s["down"] for s in stats.values())
            total_up   = sum(s["up"]   for s in stats.values())

            self._send_json({
                "total_download_kbps": round(total_down, 1),
                "total_upload_kbps":   round(total_up, 1),
                "total_download_mbps": round(total_down * 8 / 1000, 2),
                "total_upload_mbps":   round(total_up * 8 / 1000, 2),
                "device_count": len(stats),
            })
            return

        # ── /api/allocations ──
        if path == "/api/allocations":
            controller = _attr(ai, 'controller')
            limits = controller.limits if controller else {}
            allocs = []
            for ip, lim in limits.items():
                name = ai.devices.get(ip, {}).get("name", ip) if ai and ai.devices else ip
                allocs.append({
                    "ip": ip,
                    "name": name,
                    "download_limit_kbps": lim["down"],
                    "upload_limit_kbps":   lim["up"],
                })
            self._send_json({"allocations": allocs, "total_limited": len(allocs)})
            return

        # ── 404 ──
        self._send_json({"error": f"Not found: {path}"}, 404)


def _read_config():
    """Read ~/.netmind_config key=value file. Returns dict."""
    cfg = {}
    try:
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return cfg


def _collect_snapshot():
    """Gather current devices/bandwidth/status from the running AI instance."""
    ai = _ai_instance
    if not ai:
        return None

    def _attr(obj, name):
        return getattr(obj, name, None)

    # --- devices ---
    devices = []
    raw_devices = _attr(ai, 'devices') or {}
    monitor = _attr(ai, 'monitor')
    stats = monitor.get_current_stats() if monitor else {}
    for ip, info in raw_devices.items():
        s = stats.get(ip, {"down": 0, "up": 0})
        devices.append({
            "ip":             ip,
            "mac":            info.get("mac", ""),
            "name":           info.get("name", ip),
            "upload_kbps":    round(s["up"], 1),
            "download_kbps":  round(s["down"], 1),
            "upload_mbps":    round(s["up"]   * 8 / 1000, 2),
            "download_mbps":  round(s["down"] * 8 / 1000, 2),
            "status":         "active" if (s["up"] + s["down"]) > 0 else "idle",
            "activity":       info.get("activity", "No activity"),
        })

    # --- bandwidth ---
    total_down = sum(s["down"] for s in stats.values())
    total_up   = sum(s["up"]   for s in stats.values())
    bandwidth = {
        "total_download_kbps": round(total_down, 1),
        "total_upload_kbps":   round(total_up, 1),
        "total_download_mbps": round(total_down * 8 / 1000, 2),
        "total_upload_mbps":   round(total_up   * 8 / 1000, 2),
        "device_count":        len(stats),
    }

    # --- status ---
    running = _attr(ai, 'running') or False
    status = {
        "running":        running,
        "uptime_seconds": round(time.time() - (_start_time or time.time()), 1),
        "interface":      _attr(ai, 'interface') or "",
        "gateway":        _attr(ai, 'gateway') or "",
        "device_count":   len(raw_devices),
    }

    return {"devices": devices, "bandwidth": bandwidth, "status": status}


def _push_loop():
    """
    Background thread: reads server URL from ~/.netmind_config and pushes
    the latest snapshot every PUSH_INTERVAL seconds.
    """
    while True:
        time.sleep(PUSH_INTERVAL)
        try:
            cfg = _read_config()
            server_url = cfg.get("SERVER_URL", "").rstrip("/")
            if not server_url:
                continue

            token_path = TOKEN_FILE
            try:
                with open(token_path) as f:
                    token = f.read().strip()
            except FileNotFoundError:
                continue

            snap = _collect_snapshot()
            if snap is None:
                continue

            payload = json.dumps(snap).encode("utf-8")
            req = urllib.request.Request(
                f"{server_url}/api/tool/push",
                data=payload,
                headers={
                    "Content-Type":    "application/json",
                    "X-NetMind-Token": token,
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError:
            pass   # server unreachable — keep trying
        except Exception:
            pass   # never crash the loop


def create_api(ai_instance, port=API_PORT):
    """
    Start the local REST API server in a background thread.
    Also starts a push thread if SERVER_URL is set in ~/.netmind_config.
    Returns: str — the API token
    """
    global _ai_instance, _api_token, _start_time

    _ai_instance = ai_instance
    _api_token   = _get_or_create_token()
    _start_time  = time.time()

    # Reset token cache so _get_current_token() picks up fresh value
    _token_cache["value"] = _api_token
    _token_cache["ts"]    = _start_time

    # Start local REST API
    server = HTTPServer(("127.0.0.1", port), NetMindAPIHandler)
    threading.Thread(target=server.serve_forever, daemon=True, name="NetMindAPI").start()

    # Start server push thread (runs even if no server URL — sleeps harmlessly)
    threading.Thread(target=_push_loop, daemon=True, name="NetMindPush").start()

    try:
        from termcolor import colored
        _c = colored
    except ImportError:
        _c = lambda t, *a, **k: t

    cfg = _read_config()
    server_url = cfg.get("SERVER_URL", "not configured")

    print(_c(f"[+] Local REST API running at http://127.0.0.1:{port}", "green"))
    print(_c(f"    Token file : {TOKEN_FILE}", "green"))
    print(_c(f"    Token value: {_api_token}", "cyan"))
    print(_c(f"    Push server: {server_url}", "cyan"))

    return _api_token
