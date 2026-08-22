#!/usr/bin/env python3
"""
NetMind Onboarding — User profile generation from natural language
Converts a plain-language business objective into a structured bandwidth policy.
"""

import json
import os
import time
from datetime import datetime
from termcolor import colored

PROFILE_PATH = os.path.expanduser("~/.netmind_profile.json")

# ─────────────────────────────────────────────
# Default profile structure
# ─────────────────────────────────────────────
DEFAULT_PROFILE = {
    "objective": "",
    "business_type": "general",
    "summary": "General-purpose bandwidth management",
    "priority_rules": {
        "voip_protection": False,
        "customer_priority": False,
        "gaming_deprioritize": False,
        "streaming_limit": False,
        "fair_share_enforcement": True,
    },
    "bandwidth_policy": {
        "max_per_device_kbps": 5120,       # 5 Mbps default max per device
        "min_guaranteed_kbps": 256,         # Minimum guaranteed per device
        "abuse_threshold_kbps": 5000,       # Auto-limit above this
        "voip_reserved_kbps": 256,          # Reserved for VoIP per device
        "autopilot_interval_seconds": 30,   # How often AI runs
    },
    "autopilot_system_prompt": "",          # LLM fills this during onboarding
    "created_at": "",
    "last_modified": "",
    "version": 1,
}

# ─────────────────────────────────────────────
# Profile persistence
# ─────────────────────────────────────────────

def load_profile() -> dict | None:
    """Load saved profile from disk. Returns None if not found."""
    if not os.path.exists(PROFILE_PATH):
        return None
    try:
        with open(PROFILE_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(colored(f"[Onboarding] Failed to load profile: {e}", "yellow"))
        return None


def save_profile(profile: dict) -> bool:
    """Persist profile to disk."""
    try:
        profile["last_modified"] = datetime.utcnow().isoformat()
        with open(PROFILE_PATH, "w") as f:
            json.dump(profile, f, indent=2)
        print(colored(f"[Onboarding] Profile saved to {PROFILE_PATH}", "green"))
        return True
    except Exception as e:
        print(colored(f"[Onboarding] Failed to save profile: {e}", "red"))
        return False


def delete_profile() -> bool:
    """Delete the saved profile (triggers re-onboarding)."""
    if os.path.exists(PROFILE_PATH):
        os.remove(PROFILE_PATH)
        return True
    return False


# ─────────────────────────────────────────────
# LLM Profile Generation
# ─────────────────────────────────────────────

ONBOARDING_SYSTEM_PROMPT = """You are a network configuration expert for NetMind, an intelligent bandwidth manager.

A user will describe their business/network situation in natural language.
Your job is to:
1. Understand their needs
2. Generate a structured JSON configuration profile
3. Write a clear autopilot_system_prompt they can use long-term

Return ONLY valid JSON — no markdown, no explanation, just the raw JSON object.

JSON schema to return:
{
  "business_type": "coffee_shop|office|home|voip_heavy|gaming|school|general",
  "summary": "One sentence description of what this profile does",
  "priority_rules": {
    "voip_protection": true/false,
    "customer_priority": true/false,
    "gaming_deprioritize": true/false,
    "streaming_limit": true/false,
    "fair_share_enforcement": true/false
  },
  "bandwidth_policy": {
    "max_per_device_kbps": integer (256-51200),
    "min_guaranteed_kbps": integer (64-2048),
    "abuse_threshold_kbps": integer (1024-20480),
    "voip_reserved_kbps": integer (64-512),
    "autopilot_interval_seconds": integer (15-120)
  },
  "autopilot_system_prompt": "A clear, specific system prompt for the autonomous AI agent that tells it how to manage this network. Include specific rules, priorities, what to protect, what to limit, and when to act. 3-6 sentences."
}"""


def generate_profile_from_text(user_text: str, ollama_host: str = "http://localhost:11434") -> dict:
    """
    Call Llama 3.2 to generate a structured profile from the user's description.
    Returns a merged profile dict (DEFAULT_PROFILE + LLM output).
    """
    try:
        import ollama
        client = ollama.Client(host=ollama_host)

        print(colored("[Onboarding] Generating configuration profile with Llama 3.2...", "cyan"))

        response = client.chat(
            model="llama3.1",
            messages=[
                {"role": "system", "content": ONBOARDING_SYSTEM_PROMPT},
                {"role": "user", "content": f"My network situation: {user_text}"},
            ],
            options={
                "temperature": 0.3,
                "num_predict": 600,
                "top_k": 10,
                "num_ctx": 2048,
            },
        )

        raw_content = response["message"]["content"].strip()

        # Strip markdown code fences if present
        if raw_content.startswith("```"):
            lines = raw_content.split("\n")
            raw_content = "\n".join(lines[1:-1])

        llm_data = json.loads(raw_content)

        # Merge LLM output with defaults
        profile = dict(DEFAULT_PROFILE)
        profile["objective"] = user_text
        profile["created_at"] = datetime.utcnow().isoformat()
        profile["last_modified"] = datetime.utcnow().isoformat()

        # Deep-merge policy fields
        for key in ("priority_rules", "bandwidth_policy"):
            if key in llm_data:
                profile[key] = {**profile[key], **llm_data[key]}

        for key in ("business_type", "summary", "autopilot_system_prompt"):
            if key in llm_data:
                profile[key] = llm_data[key]

        print(colored(f"[Onboarding] ✓ Profile generated: {profile['summary']}", "green"))
        return profile

    except json.JSONDecodeError as e:
        print(colored(f"[Onboarding] LLM returned invalid JSON: {e}", "red"))
        return _fallback_profile(user_text)
    except Exception as e:
        print(colored(f"[Onboarding] LLM call failed: {e}", "red"))
        return _fallback_profile(user_text)


def _fallback_profile(user_text: str) -> dict:
    """Return a sensible default profile when LLM is unavailable."""
    profile = dict(DEFAULT_PROFILE)
    profile["objective"] = user_text
    profile["summary"] = "Default balanced profile (LLM unavailable during setup)"
    profile["autopilot_system_prompt"] = (
        "You are a network bandwidth manager. Keep all devices within fair usage limits. "
        "If any device exceeds 5000 KB/s sustained, apply a limit of 2048 KB/s download and 512 KB/s upload. "
        "Remove limits when usage drops below 1000 KB/s for 60 seconds. "
        "Prioritize stability and fairness over speed."
    )
    profile["created_at"] = datetime.utcnow().isoformat()
    profile["last_modified"] = datetime.utcnow().isoformat()
    return profile


# ─────────────────────────────────────────────
# System Prompt Builder
# ─────────────────────────────────────────────

def build_autopilot_system_prompt(profile: dict) -> str:
    """
    Build the complete system prompt for the autopilot loop.
    Combines the LLM-generated instructions with concrete rules.
    """
    base = profile.get("autopilot_system_prompt", "")
    policy = profile.get("bandwidth_policy", {})
    rules = profile.get("priority_rules", {})

    rules_text = []
    if rules.get("voip_protection"):
        rules_text.append(f"ALWAYS protect VoIP traffic — reserve at least {policy.get('voip_reserved_kbps', 256)} KB/s for devices using voice/video calls (SIP, Zoom, Teams domains).")
    if rules.get("customer_priority"):
        rules_text.append("Customer-facing devices must always have bandwidth priority. Limit backend/admin devices first.")
    if rules.get("gaming_deprioritize"):
        rules_text.append("Devices doing gaming (high sustained upload) should be deprioritized if bandwidth is constrained.")
    if rules.get("streaming_limit"):
        rules_text.append("Limit video streaming devices to 2048 KB/s download to prevent bandwidth hogging.")
    if rules.get("fair_share_enforcement"):
        rules_text.append(f"Apply fair-share enforcement: no single device should use more than {policy.get('max_per_device_kbps', 5120)} KB/s for more than 30 seconds.")

    rules_text.append(f"Absolute minimum guaranteed speed: {policy.get('min_guaranteed_kbps', 256)} KB/s per device.")
    rules_text.append(f"Auto-limit threshold: {policy.get('abuse_threshold_kbps', 5000)} KB/s sustained.")

    prompt = (
        "You are NetMind's autonomous bandwidth manager running in autopilot mode.\n\n"
        f"USER OBJECTIVE: {profile.get('objective', 'Fair bandwidth management')}\n\n"
        f"YOUR MANDATE: {base}\n\n"
        "RULES:\n" + "\n".join(f"- {r}" for r in rules_text) + "\n\n"
        "TOOLS AVAILABLE: get_network_stats, enforce_limit, remove_limit, block_device, unblock_device\n\n"
        "INSTRUCTIONS:\n"
        "- Always call get_network_stats first to see current state.\n"
        "- Make decisions based on 30-second average usage, not instantaneous spikes.\n"
        "- State your reasoning briefly before each action.\n"
        "- If no action is needed, say 'Network is balanced. No action required.' and stop.\n"
        "- Be decisive but conservative — don't limit unless clearly necessary."
    )
    return prompt


# ─────────────────────────────────────────────
# OnboardingManager — main interface
# ─────────────────────────────────────────────

class OnboardingManager:
    def __init__(self, ollama_host: str = "http://localhost:11434"):
        self.ollama_host = ollama_host
        self.profile: dict | None = None

    def is_configured(self) -> bool:
        return load_profile() is not None

    def load(self) -> dict | None:
        self.profile = load_profile()
        return self.profile

    def run_setup(self, user_text: str) -> dict:
        """Run the full onboarding flow from user text."""
        profile = generate_profile_from_text(user_text, self.ollama_host)
        save_profile(profile)
        self.profile = profile
        return profile

    def reset(self):
        """Clear the profile and trigger re-onboarding."""
        delete_profile()
        self.profile = None

    def get_system_prompt(self) -> str:
        if not self.profile:
            self.profile = load_profile()
        if not self.profile:
            return _fallback_profile("general use")["autopilot_system_prompt"]
        return build_autopilot_system_prompt(self.profile)

    def get_profile(self) -> dict:
        if not self.profile:
            self.profile = load_profile()
        return self.profile or {}
