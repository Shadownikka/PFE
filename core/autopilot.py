#!/usr/bin/env python3
"""
NetMind AutoPilot — Autonomous LLM-driven bandwidth management loop.

Runs as a background thread. Every N seconds it:
  1. Collects a compact traffic snapshot from the existing monitors
  2. Calls Llama 3.2 via Ollama with the user's profile as system context
  3. Executes any tool calls (limit / unblock / block) the LLM decides
  4. Logs the decision for adaptive learning
  5. Feeds patterns from past decisions into future prompts (learning)
"""

import json
import os
import time
import threading
from datetime import datetime, timezone
from collections import deque
from termcolor import colored
from onboarding import OnboardingManager, load_profile

DECISION_LOG_PATH = os.path.expanduser("~/.netmind_decisions.jsonl")
MAX_LOG_LINES = 500         # Rolling log — keep last 500 decisions
MAX_PATTERN_CONTEXT = 5     # How many past patterns to inject into prompts


# ─────────────────────────────────────────────
# Decision Log
# ─────────────────────────────────────────────

def _append_decision_log(entry: dict):
    """Append a decision entry to the JSONL decision log."""
    try:
        # Keep log bounded
        if os.path.exists(DECISION_LOG_PATH):
            with open(DECISION_LOG_PATH, "r") as f:
                lines = f.readlines()
            if len(lines) >= MAX_LOG_LINES:
                lines = lines[-(MAX_LOG_LINES - 1):]
            with open(DECISION_LOG_PATH, "w") as f:
                f.writelines(lines)

        with open(DECISION_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def load_decision_log(n: int = 50) -> list[dict]:
    """Load the last N decision log entries."""
    if not os.path.exists(DECISION_LOG_PATH):
        return []
    try:
        with open(DECISION_LOG_PATH, "r") as f:
            lines = f.readlines()
        return [json.loads(l) for l in lines[-n:] if l.strip()]
    except Exception:
        return []


# ─────────────────────────────────────────────
# Pattern Extractor (Adaptive Learning)
# ─────────────────────────────────────────────

def _extract_patterns(n: int = MAX_PATTERN_CONTEXT) -> str:
    """
    Read recent decisions and produce a compact 'patterns observed' context
    string that gets injected into the next LLM system prompt.
    """
    entries = load_decision_log(30)
    if not entries:
        return ""

    # Summarize action types
    action_counts: dict[str, int] = {}
    device_histories: dict[str, list] = {}

    for entry in entries:
        for action in entry.get("actions_taken", []):
            atype = action.get("type", "unknown")
            action_counts[atype] = action_counts.get(atype, 0) + 1
            ip = action.get("ip")
            if ip:
                device_histories.setdefault(ip, []).append(atype)

    lines = [f"PATTERNS FROM LAST {len(entries)} DECISIONS:"]
    for atype, count in sorted(action_counts.items(), key=lambda x: -x[1])[:n]:
        lines.append(f"  - '{atype}' was taken {count} times")

    # Identify frequently-limited devices
    freq_limited = [(ip, hist.count("limit")) for ip, hist in device_histories.items() if hist.count("limit") > 2]
    if freq_limited:
        lines.append("  - Frequently limited devices: " + ", ".join(f"{ip}({c}x)" for ip, c in freq_limited[:3]))

    return "\n".join(lines)


# ─────────────────────────────────────────────
# Traffic Snapshot Builder
# ─────────────────────────────────────────────

def _build_snapshot(monitor, controller, conn_tracker, devices: dict) -> dict:
    """
    Build a compact, LLM-friendly snapshot of current network state.
    Only includes active devices to minimise token usage.
    """
    stats = monitor.get_current_stats() if monitor else {}
    limits = controller.limits if controller else {}

    device_list = []
    for ip, info in devices.items():
        usage = stats.get(ip, {"up": 0, "down": 0})
        avg = monitor.get_average_usage(ip, duration=30) if monitor else {"up": 0, "down": 0}

        # Skip truly idle devices (< 5 KB/s both directions and no limits)
        if (avg["up"] < 5 and avg["down"] < 5) and ip not in limits:
            continue

        activity = "unknown"
        if conn_tracker:
            try:
                activity = conn_tracker.get_summary(ip)
            except Exception:
                pass

        entry = {
            "ip": ip,
            "name": info.get("name", ip),
            "down_kbps": round(usage["down"], 1),
            "up_kbps": round(usage["up"], 1),
            "avg30s_down": round(avg["down"], 1),
            "avg30s_up": round(avg["up"], 1),
            "activity": activity,
            "limited": ip in limits,
        }
        if ip in limits:
            entry["limit_down"] = limits[ip].get("down")
            entry["limit_up"] = limits[ip].get("up")

        device_list.append(entry)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "active_devices": len(device_list),
        "devices": device_list,
    }


# ─────────────────────────────────────────────
# AutoPilot
# ─────────────────────────────────────────────

class AutoPilot:
    """
    Autonomous AI management loop.  After being started, it periodically:
      - snapshots network state
      - calls Llama 3.2 with the user's profile as context
      - executes tool calls (limit/unblock/block)
      - logs decisions for adaptive learning
    """

    def __init__(
        self,
        monitor,
        controller,
        conn_tracker,
        devices: dict,
        protected_ips: set | None = None,
        ollama_host: str = "http://localhost:11434",
    ):
        self.monitor = monitor
        self.controller = controller
        self.conn_tracker = conn_tracker
        self.devices = devices          # shared reference — updates automatically
        self.protected_ips = protected_ips or set()
        self.ollama_host = ollama_host

        # State
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Recent decisions — kept in memory for the UI
        self._recent_decisions: deque[dict] = deque(maxlen=50)
        self._last_decision_time: float = 0
        self._decision_count: int = 0
        self._last_error: str = ""

        # Profile — loaded from disk
        self._onboarding = OnboardingManager(ollama_host)
        self._profile: dict = self._onboarding.get_profile() or {}
        self._interval: int = self._profile.get("bandwidth_policy", {}).get(
            "autopilot_interval_seconds", 30
        )

        # Tool definitions (same schema as net_agent.py)
        self._tools = [
            {"type": "function", "function": {
                "name": "get_network_stats",
                "description": "Get current network statistics for all devices.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            }},
            {"type": "function", "function": {
                "name": "enforce_limit",
                "description": "Apply bandwidth limit to a device.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "download_kbps": {"type": "integer"},
                        "upload_kbps": {"type": "integer"},
                    },
                    "required": ["ip", "download_kbps", "upload_kbps"],
                },
            }},
            {"type": "function", "function": {
                "name": "remove_limit",
                "description": "Remove bandwidth limit from a device.",
                "parameters": {
                    "type": "object",
                    "properties": {"ip": {"type": "string"}},
                    "required": ["ip"],
                },
            }},
            {"type": "function", "function": {
                "name": "block_device",
                "description": "Completely block internet for a device.",
                "parameters": {
                    "type": "object",
                    "properties": {"ip": {"type": "string"}},
                    "required": ["ip"],
                },
            }},
            {"type": "function", "function": {
                "name": "unblock_device",
                "description": "Restore internet access for a blocked device.",
                "parameters": {
                    "type": "object",
                    "properties": {"ip": {"type": "string"}},
                    "required": ["ip"],
                },
            }},
        ]

    # ─── Public API ────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        # Reload profile in case it was updated
        self._profile = self._onboarding.get_profile() or self._profile
        self._interval = self._profile.get("bandwidth_policy", {}).get(
            "autopilot_interval_seconds", 30
        )
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="NetMindAutoPilot")
        self._thread.start()
        print(colored(f"[AutoPilot] Started (interval={self._interval}s)", "green"))

    def stop(self):
        self._running = False
        print(colored("[AutoPilot] Stopped", "yellow"))

    def reload_profile(self):
        """Reload the profile from disk (call after onboarding update)."""
        self._profile = self._onboarding.get_profile() or {}
        self._interval = self._profile.get("bandwidth_policy", {}).get(
            "autopilot_interval_seconds", 30
        )
        print(colored(f"[AutoPilot] Profile reloaded (interval={self._interval}s)", "cyan"))

    def get_status(self) -> dict:
        with self._lock:
            recent = list(self._recent_decisions)[-5:]
        return {
            "running": self._running,
            "interval_seconds": self._interval,
            "decision_count": self._decision_count,
            "last_decision_time": self._last_decision_time,
            "last_decision_ago_s": round(time.time() - self._last_decision_time, 1) if self._last_decision_time else None,
            "last_error": self._last_error,
            "recent_decisions": recent,
            "profile_summary": self._profile.get("summary", "No profile"),
            "objective": self._profile.get("objective", ""),
        }

    def get_decisions(self, n: int = 50) -> list[dict]:
        """Return recent decisions (in-memory + persisted)."""
        return load_decision_log(n)

    # ─── Main Loop ─────────────────────────────────────────────────────────

    def _loop(self):
        """Main autopilot loop."""
        # Wait one interval before the first run (let traffic accumulate)
        time.sleep(min(self._interval, 15))

        while self._running:
            try:
                self._run_once()
            except Exception as e:
                self._last_error = str(e)
                print(colored(f"[AutoPilot] Loop error: {e}", "red"))
            # Sleep in small increments so stop() is responsive
            for _ in range(self._interval * 2):
                if not self._running:
                    break
                time.sleep(0.5)

    def _run_once(self):
        """Execute one autopilot cycle."""
        import ollama

        snapshot = _build_snapshot(
            self.monitor, self.controller, self.conn_tracker, self.devices
        )

        if not snapshot["devices"]:
            return  # Nothing to manage

        # Build system prompt with adaptive patterns
        system_prompt = self._onboarding.get_system_prompt()
        patterns = _extract_patterns()
        if patterns:
            system_prompt += f"\n\n{patterns}"

        user_message = (
            f"Current network snapshot ({snapshot['timestamp']}):\n"
            f"{json.dumps(snapshot, indent=2)}\n\n"
            "Analyze the network and take any necessary actions. "
            "If the network is balanced, just say so."
        )

        client = ollama.Client(host=self.ollama_host)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        actions_taken = []
        reasoning = ""

        try:
            response = client.chat(
                model="llama3.1",
                messages=messages,
                tools=self._tools,
                options={
                    "temperature": 0.2,
                    "num_predict": 250,
                    "top_k": 5,
                    "top_p": 0.85,
                    "num_ctx": 3072,
                },
            )

            # Process tool calls in a loop (LLM may call multiple tools)
            max_rounds = 5
            round_num = 0
            while response["message"].get("tool_calls") and round_num < max_rounds:
                round_num += 1
                messages.append(response["message"])

                for tool_call in response["message"]["tool_calls"]:
                    fn_name = tool_call["function"]["name"]
                    fn_args = tool_call["function"]["arguments"]

                    result = self._execute_tool(fn_name, fn_args, snapshot)
                    action_entry = {"type": fn_name, "args": fn_args, "result": result}
                    actions_taken.append(action_entry)

                    messages.append({
                        "role": "tool",
                        "content": json.dumps(result),
                    })

                response = client.chat(
                    model="llama3.1",
                    messages=messages,
                    tools=self._tools,
                    options={
                        "temperature": 0.2,
                        "num_predict": 200,
                        "top_k": 5,
                        "top_p": 0.85,
                        "num_ctx": 3072,
                    },
                )

            reasoning = response["message"].get("content", "").strip()

        except Exception as e:
            self._last_error = str(e)
            print(colored(f"[AutoPilot] Ollama error: {e}", "red"))
            return

        # Build log entry
        entry = {
            "timestamp": snapshot["timestamp"],
            "snapshot_devices": len(snapshot["devices"]),
            "actions_taken": actions_taken,
            "reasoning": reasoning[:500],   # Cap to avoid huge log files
            "cycle": self._decision_count + 1,
        }

        _append_decision_log(entry)

        with self._lock:
            self._recent_decisions.append(entry)
            self._decision_count += 1
            self._last_decision_time = time.time()

        # Print summary to console
        if actions_taken:
            action_strs = [f"{a['type']}({a['args'].get('ip', '')})" for a in actions_taken if a["type"] != "get_network_stats"]
            if action_strs:
                print(colored(f"[AutoPilot] Cycle {self._decision_count}: {', '.join(action_strs)}", "cyan"))
        if reasoning and "no action" not in reasoning.lower()[:50]:
            short = reasoning[:120].replace("\n", " ")
            print(colored(f"[AutoPilot] Reasoning: {short}...", "white"))

    # ─── Tool Execution ────────────────────────────────────────────────────

    def _execute_tool(self, name: str, args: dict, snapshot: dict) -> dict:
        """Execute a tool call from the LLM."""
        if name == "get_network_stats":
            return snapshot  # Return the snapshot we already have

        ip = args.get("ip", "")

        # Safety guard — never touch protected IPs
        if ip in self.protected_ips:
            return {"success": False, "message": f"Cannot modify {ip} — it is a protected IP"}

        if name == "enforce_limit":
            down = int(args.get("download_kbps", 1024))
            up = int(args.get("upload_kbps", 512))
            if down <= 0 or up <= 0:
                return {"success": False, "message": "Invalid bandwidth values"}
            result = self.controller.apply_limit(ip, down, up)
            return {
                "success": bool(result),
                "message": f"Limit applied to {ip}: ↓{down}KB/s ↑{up}KB/s" if result else f"Failed to limit {ip}",
                "ip": ip,
            }

        elif name == "remove_limit":
            self.controller.remove_limit(ip)
            return {"success": True, "message": f"Limit removed from {ip}", "ip": ip}

        elif name == "block_device":
            result = self.controller.apply_limit(ip, 1, 1)
            return {
                "success": bool(result) or ip in self.controller.limits,
                "message": f"Blocked {ip}" if result else f"Failed to block {ip}",
                "ip": ip,
            }

        elif name == "unblock_device":
            self.controller.remove_limit(ip)
            return {"success": True, "message": f"Unblocked {ip}", "ip": ip}

        return {"error": f"Unknown tool: {name}"}
