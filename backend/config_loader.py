"""
Config Loader
Loads port_rules.json and device_rules.json with caching and hot-reload.
All modules import from here — zero hardcoded constants anywhere else.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("config_loader")

CONFIG_DIR = Path(__file__).parent / "config"
PORT_RULES_PATH = CONFIG_DIR / "port_rules.json"
DEVICE_RULES_PATH = CONFIG_DIR / "device_rules.json"

# Cache with file modification tracking for hot-reload
_cache: Dict[str, Any] = {}
_mtime: Dict[str, float] = {}


def _load_json(path: Path) -> Dict:
    """Load a JSON config file, with modification-time-based cache."""
    key = str(path)
    try:
        mtime = path.stat().st_mtime
        if key not in _cache or _mtime.get(key) != mtime:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            _cache[key] = data
            _mtime[key] = mtime
            logger.debug(f"Loaded config: {path.name}")
        return _cache[key]
    except FileNotFoundError:
        logger.error(f"Config file not found: {path}")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {path.name}: {e}")
        return _cache.get(key, {})  # Return stale cache rather than crashing


def get_port_rules() -> Dict:
    return _load_json(PORT_RULES_PATH)


def get_device_rules() -> Dict:
    return _load_json(DEVICE_RULES_PATH)


# ─────────────────────────────────────────────
# Port helpers
# ─────────────────────────────────────────────

def get_port_info(port: int) -> Optional[Dict]:
    """Get full info dict for a port number. Returns None if not in config."""
    return get_port_rules().get("ports", {}).get(str(port))


def get_port_severity(port: int) -> str:
    """Get severity level string for a port. Defaults to 'info' if unknown."""
    info = get_port_info(port)
    return info["severity"] if info else "info"


def get_risky_ports() -> Dict[int, Dict]:
    """Return all ports with severity critical/high/medium as {port_num: info_dict}."""
    ports = get_port_rules().get("ports", {})
    return {
        int(p): info
        for p, info in ports.items()
        if info.get("severity") in ("critical", "high", "medium")
    }


def get_critical_ports() -> set:
    """Return set of port numbers with 'critical' severity."""
    ports = get_port_rules().get("ports", {})
    return {
        int(p) for p, info in ports.items()
        if info.get("severity") == "critical"
    }


def get_alert_ports() -> set:
    """Return set of port numbers that should trigger alerts."""
    ports = get_port_rules().get("ports", {})
    return {
        int(p) for p, info in ports.items()
        if info.get("should_alert", False)
    }


def get_weak_config_messages() -> Dict[int, str]:
    """Return {port: weak_config_message} for all configured ports."""
    ports = get_port_rules().get("ports", {})
    return {
        int(p): info["weak_config_message"]
        for p, info in ports.items()
        if info.get("weak_config_message")
    }


def get_port_recommendations() -> Dict[int, str]:
    """Return {port: recommendation} for all configured ports."""
    ports = get_port_rules().get("ports", {})
    return {
        int(p): info["recommendation"]
        for p, info in ports.items()
        if info.get("recommendation")
    }


def get_severity_score(severity: str) -> int:
    """Return risk score contribution for a given severity level."""
    scores = get_port_rules().get("severity_risk_scores", {
        "critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0
    })
    return scores.get(severity, 0)


def get_vulnerability_severity_score(severity: str) -> int:
    """Return risk score contribution for a vulnerability severity."""
    scores = get_port_rules().get("vulnerability_severity_scores", {
        "critical": 25, "high": 15, "medium": 8, "low": 3
    })
    return scores.get(severity, 0)


def get_firmware_patterns() -> List[Dict]:
    """Return list of vulnerable firmware regex patterns with severity."""
    return get_port_rules().get("vulnerable_firmware_patterns", [])


# ─────────────────────────────────────────────
# Device helpers
# ─────────────────────────────────────────────

def get_device_info(device_type: str) -> Dict:
    """Get full info for a device type. Falls back to 'unknown'."""
    devices = get_device_rules().get("device_types", {})
    return devices.get(device_type, devices.get("unknown", {}))


def get_device_base_risk(device_type: str) -> int:
    """Get base risk score for a device type."""
    return get_device_info(device_type).get("base_risk", 10)


def get_device_default_creds(device_type: str) -> Optional[str]:
    """Get default credential info for a device type."""
    return get_device_info(device_type).get("default_credentials")


def get_device_icon(device_type: str) -> str:
    """Get emoji icon for a device type."""
    return get_device_info(device_type).get("icon", "❓")


def get_risk_level(score: int) -> str:
    """Convert numeric risk score to level string."""
    levels = get_device_rules().get("risk_levels", {})
    # Sort by min_score descending and find first match
    for level, cfg in sorted(levels.items(), key=lambda x: x[1].get("min_score", 0), reverse=True):
        if score >= cfg.get("min_score", 0):
            return level
    return "low"


def get_attack_surface_score(port_count: int) -> int:
    """Get extra risk score contribution based on number of open ports."""
    thresholds = get_device_rules().get("attack_surface_risk", {}).get("port_count_thresholds", [])
    for threshold in sorted(thresholds, key=lambda x: x["min_ports"], reverse=True):
        if port_count >= threshold["min_ports"]:
            return threshold["extra_score"]
    return 0


def get_unknown_device_penalties() -> Dict[str, int]:
    """Get risk score penalties for missing device identification fields."""
    return get_device_rules().get("unknown_device_penalties", {
        "no_vendor": 5, "no_hostname": 3, "no_os": 4
    })


def get_all_port_device_hints() -> Dict[int, str]:
    """Return {port: device_type_hint} for port-based device type guessing."""
    ports = get_port_rules().get("ports", {})
    return {
        int(p): info.get("common_on", [None])[0]
        for p, info in ports.items()
        if info.get("common_on")
    }
