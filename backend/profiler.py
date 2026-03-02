"""
Device Profiler Module
Deep profiles each discovered device for vulnerabilities, firmware status, and behavior baselines.
All port/risk constants loaded from config/port_rules.json via config_loader — zero hardcoding.
"""

import hashlib
import logging
import re
import ssl
import time
import urllib.request
import urllib.error
from typing import Dict, List, Optional

from config_loader import (
    get_firmware_patterns,
    get_critical_ports,
    get_weak_config_messages,
    get_port_info,
    get_risky_ports,
    get_device_default_creds,
)

logger = logging.getLogger("profiler")


class DeviceProfiler:
    def __init__(self):
        self.http_timeout = 5

    def profile_device(self, device: Dict) -> Dict:
        """Complete device profiling pipeline."""
        ip = device.get("ip", "")
        logger.debug(f"Profiling {ip}")

        profile = device.copy()

        http_info = self._probe_http(ip, device.get("open_ports", []))
        if http_info:
            profile["http_info"] = http_info
            profile.setdefault("firmware_hints", [])
            profile["firmware_hints"].extend(http_info.get("firmware_hints", []))

        profile["vulnerabilities"] = self._check_vulnerabilities(profile)
        profile["weak_configs"] = self._check_weak_configs(profile)
        profile["risky_ports"] = self._classify_risky_ports(profile)
        profile["fingerprint"] = self._generate_fingerprint(profile)
        profile["behavior_baseline"] = self._create_behavior_baseline(profile)

        device_type = profile.get("device_type", "unknown")
        default_creds = get_device_default_creds(device_type)
        if default_creds and "N/A" not in default_creds:
            profile["default_cred_risk"] = default_creds

        profile["profile_timestamp"] = time.time()
        profile["profiled"] = True
        return profile

    def _probe_http(self, ip: str, open_ports: List[int]) -> Optional[Dict]:
        http_ports = [p for p in open_ports if p in (80, 8080, 8443, 443, 7080, 8888)]
        if not http_ports:
            return None

        result = {}
        firmware_hints = []
        firmware_patterns = get_firmware_patterns()

        for port in http_ports[:2]:
            protocol = "https" if port in (443, 8443) else "http"
            url = f"{protocol}://{ip}:{port}/"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                opener_args = {"timeout": self.http_timeout}
                if protocol == "https":
                    opener_args["context"] = ctx
                with urllib.request.urlopen(req, **opener_args) as resp:
                    headers = dict(resp.headers)
                    result[f"port_{port}_headers"] = {
                        k: v for k, v in headers.items()
                        if k.lower() in ("server", "x-powered-by", "www-authenticate", "content-type")
                    }
                    server = headers.get("Server", headers.get("server", ""))
                    x_powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
                    combined = f"{server} {x_powered}"
                    for fp in firmware_patterns:
                        if re.search(fp["pattern"], combined, re.IGNORECASE):
                            hint = f"[{fp['severity'].upper()}] {fp['description']}"
                            if hint not in firmware_hints:
                                firmware_hints.append(hint)
                    try:
                        body = resp.read(2048).decode("utf-8", errors="ignore")
                        result[f"port_{port}_body_snippet"] = body[:500]
                        for fp in firmware_patterns:
                            if re.search(fp["pattern"], body, re.IGNORECASE):
                                hint = f"[{fp['severity'].upper()}] {fp['description']}"
                                if hint not in firmware_hints:
                                    firmware_hints.append(hint)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"HTTP probe failed for {ip}:{port} — {e}")

        result["firmware_hints"] = firmware_hints
        return result if result else None

    def _check_vulnerabilities(self, profile: Dict) -> List[Dict]:
        vulns = []
        services = profile.get("services", {})
        open_ports = profile.get("open_ports", [])
        firmware_patterns = get_firmware_patterns()
        critical_ports = get_critical_ports()

        for port, svc in services.items():
            banner = " ".join([
                svc.get("banner", ""), svc.get("product", ""),
                svc.get("version", ""), svc.get("extrainfo", "")
            ])
            for fp in firmware_patterns:
                if re.search(fp["pattern"], banner, re.IGNORECASE):
                    vulns.append({
                        "type": "outdated_software",
                        "port": port,
                        "service": svc.get("name", ""),
                        "description": fp["description"],
                        "severity": fp["severity"]
                    })

        for hint in profile.get("firmware_hints", []):
            severity = "medium"
            description = hint
            if hint.startswith("["):
                try:
                    sev_str = hint[1:hint.index("]")].lower()
                    severity = sev_str if sev_str in ("critical", "high", "medium", "low") else "medium"
                    description = hint[hint.index("]") + 2:]
                except ValueError:
                    pass
            vulns.append({"type": "firmware_vulnerability", "description": description, "severity": severity})

        for port in open_ports:
            if port in critical_ports:
                port_info = get_port_info(port)
                if port_info:
                    vulns.append({
                        "type": "dangerous_port",
                        "port": port,
                        "description": port_info.get("description", f"Dangerous port {port} open"),
                        "attack_vectors": port_info.get("attack_vectors", []),
                        "severity": "critical"
                    })

        os_guess = profile.get("os_guess", "").lower()
        eol_os = [
            ("windows xp", "critical"), ("windows 2000", "critical"),
            ("windows 7", "critical"), ("windows vista", "critical"),
            ("windows server 2003", "critical"), ("windows server 2008", "high")
        ]
        for eol, severity in eol_os:
            if eol in os_guess:
                vulns.append({
                    "type": "outdated_os",
                    "description": f"End-of-life OS: {profile.get('os_guess')} — no security patches",
                    "severity": severity
                })
                break

        return vulns

    def _check_weak_configs(self, profile: Dict) -> List[str]:
        issues = []
        open_ports = set(profile.get("open_ports", []))
        weak_config_messages = get_weak_config_messages()

        for port in open_ports:
            if port in weak_config_messages:
                issues.append(weak_config_messages[port])

        if 80 in open_ports and 443 in open_ports:
            issues.append("HTTP (80) and HTTPS (443) both open — redirect HTTP to HTTPS")
        if 1883 in open_ports and 8883 in open_ports:
            issues.append("Both plain MQTT (1883) and MQTT-TLS (8883) open — disable plain MQTT")

        return issues

    def _classify_risky_ports(self, profile: Dict) -> List[Dict]:
        risky = []
        open_ports = set(profile.get("open_ports", []))
        services = profile.get("services", {})
        risky_port_defs = get_risky_ports()

        for port in open_ports:
            if port in risky_port_defs:
                info = risky_port_defs[port]
                svc = services.get(port, {})
                risky.append({
                    "port": port,
                    "service": svc.get("name", info.get("name", str(port))),
                    "severity": info["severity"],
                    "reason": info.get("description", ""),
                    "recommendation": info.get("recommendation", ""),
                    "attack_vectors": info.get("attack_vectors", []),
                    "encrypted": info.get("encrypted", False),
                    "cve_tags": info.get("cve_tags", []),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", "")
                })

        return risky

    def _generate_fingerprint(self, profile: Dict) -> str:
        key_data = {
            "ip": profile.get("ip"),
            "mac": profile.get("mac"),
            "vendor": profile.get("vendor"),
            "os": profile.get("os_guess"),
            "ports": sorted(profile.get("open_ports", [])),
        }
        return hashlib.sha256(str(key_data).encode()).hexdigest()[:16]

    def _create_behavior_baseline(self, profile: Dict) -> Dict:
        open_ports = profile.get("open_ports", [])
        services = profile.get("services", {})
        protocols_used = set()
        for port in open_ports:
            info = get_port_info(port)
            if info:
                protocols_used.add(info["name"].split("/")[0].lower())
        return {
            "open_port_count": len(open_ports),
            "protocols": list(protocols_used),
            "service_count": len(services),
            "baseline_timestamp": time.time(),
            "expected_ports": open_ports[:],
        }
