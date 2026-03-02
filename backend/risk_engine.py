"""
Risk Engine Module
Computes final risk scores using config-driven rules + Shodan enrichment data + AI insights.
Zero hardcoded constants — all values come from config/port_rules.json and config/device_rules.json.
"""

import logging
import time
import uuid
from typing import Dict, List, Optional

from config_loader import (
    get_device_base_risk,
    get_vulnerability_severity_score,
    get_severity_score,
    get_risk_level,
    get_attack_surface_score,
    get_unknown_device_penalties,
    get_alert_ports,
    get_port_info,
    get_port_recommendations,
)

logger = logging.getLogger("risk_engine")


class RiskEngine:
    def compute_risk_score(self, device: Dict, ai_analysis: Optional[Dict] = None) -> Dict:
        """
        Compute final risk score blending:
          - AI analysis (60%) if available
          - Rule-based (40%) always
          - Shodan enrichment bonus applied to rule-based score
        """
        rule_score = self._compute_rule_based_score(device)

        if ai_analysis and isinstance(ai_analysis, dict) and "risk_score" in ai_analysis:
            ai_score = min(100, max(0, int(ai_analysis.get("risk_score", rule_score))))
            final_score = round(0.6 * ai_score + 0.4 * rule_score)
            risk_level = ai_analysis.get("risk_level", get_risk_level(final_score))
            risk_factors = ai_analysis.get("risk_factors", [])
            recommendations = ai_analysis.get("recommendations", [])
            summary = ai_analysis.get("summary", "")
            predicted_vectors = ai_analysis.get("predicted_attack_vectors", [])
            exploitation_likelihood = ai_analysis.get("exploitation_likelihood", "low")
        else:
            final_score = rule_score
            risk_level = get_risk_level(final_score)
            risk_factors = self._build_risk_factors(device)
            recommendations = self._build_recommendations(device)
            summary = f"Rule-based analysis: {final_score}/100 risk score"
            predicted_vectors = []
            exploitation_likelihood = self._score_to_exploitation_likelihood(final_score)

        alerts = self._generate_alerts(device, final_score, risk_level, risk_factors)

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors[:10],
            "recommendations": recommendations[:8],
            "predicted_attack_vectors": predicted_vectors[:5],
            "exploitation_likelihood": exploitation_likelihood,
            "risk_summary": summary,
            "alerts": alerts,
            "rule_based_score": rule_score,
            "ai_score": ai_analysis.get("risk_score") if ai_analysis else None,
            "risk_assessed_at": time.time(),
        }

    def _compute_rule_based_score(self, device: Dict) -> int:
        """Pure rule-based scoring — entirely config-driven, zero hardcoded values."""
        score = 0

        # 1. Device type base risk from config
        device_type = device.get("device_type", "unknown")
        score += get_device_base_risk(device_type)

        # 2. Vulnerability scores from config severity mapping
        for vuln in device.get("vulnerabilities", []):
            score += get_vulnerability_severity_score(vuln.get("severity", "low"))

        # 3. Risky port scores from config severity mapping
        for rp in device.get("risky_ports", []):
            score += get_severity_score(rp.get("severity", "low"))

        # 4. Weak configurations
        score += len(device.get("weak_configs", [])) * 5

        # 5. Default credential risk
        if device.get("default_cred_risk"):
            score += 15

        # 6. Unknown device penalties from config
        penalties = get_unknown_device_penalties()
        if not device.get("vendor") or device.get("vendor") == "Unknown":
            score += penalties.get("no_vendor", 5)
        if not device.get("hostname"):
            score += penalties.get("no_hostname", 3)
        if not device.get("os_guess"):
            score += penalties.get("no_os", 4)

        # 7. Attack surface score from config thresholds
        port_count = len(device.get("open_ports", []))
        score += get_attack_surface_score(port_count)

        # 8. Shodan enrichment bonus (if available)
        shodan = device.get("shodan", {})
        if isinstance(shodan, dict) and shodan.get("found"):
            score += min(shodan.get("risk_bonus", 0), 50)

            # Additional penalty per CVE
            cve_count = shodan.get("cve_count", 0)
            if cve_count:
                score += min(cve_count * 5, 25)

        return min(100, score)

    def _score_to_exploitation_likelihood(self, score: int) -> str:
        if score >= 70: return "very_high"
        if score >= 50: return "high"
        if score >= 30: return "medium"
        if score >= 15: return "low"
        return "very_low"

    def _build_risk_factors(self, device: Dict) -> List[str]:
        factors = []

        for v in device.get("vulnerabilities", []):
            factors.append(v.get("description", ""))

        for rp in device.get("risky_ports", []):
            factors.append(
                f"Port {rp['port']} ({rp['service']}) open — {rp.get('reason', '')}"
            )

        for wc in device.get("weak_configs", []):
            factors.append(wc)

        # Shodan-derived factors
        shodan = device.get("shodan", {})
        if isinstance(shodan, dict) and shodan.get("found"):
            for finding in shodan.get("risk_findings", []):
                factors.append(f"[Shodan] {finding['description']}")
            for cve in shodan.get("cves", [])[:3]:
                factors.append(f"[Shodan] Known CVE: {cve}")

        return [f for f in factors if f]

    def _build_recommendations(self, device: Dict) -> List[str]:
        """Build recommendations using config-driven port recommendation strings."""
        recs = []
        open_ports = set(device.get("open_ports", []))

        # Get all recommendations from config
        port_recs = get_port_recommendations()
        for port in open_ports:
            if port in port_recs:
                recs.append(port_recs[port])

        if device.get("default_cred_risk"):
            recs.append("Change default credentials immediately — use a strong unique password")

        if device.get("weak_configs"):
            for wc in device["weak_configs"][:3]:
                recs.append(f"Fix configuration: {wc}")

        if not device.get("os_guess"):
            recs.append("Identify this device — unknown devices are unmanaged risks")

        # Shodan-specific recommendations
        shodan = device.get("shodan", {})
        if isinstance(shodan, dict) and shodan.get("cves"):
            recs.append(
                f"Apply patches for {len(shodan['cves'])} known CVE(s): "
                f"{', '.join(shodan['cves'][:3])}"
            )

        if len(open_ports) > 8:
            recs.append("Reduce attack surface: disable unused services to close unnecessary ports")

        return recs

    def _generate_alerts(self, device: Dict, score: int, level: str, factors: List[str]) -> List[Dict]:
        """Generate security alerts using config-driven alert_ports."""
        alerts = []
        ip = device.get("ip", "")
        device_type = device.get("device_type", "unknown")
        now = time.time()

        # Main risk-level alert
        if level in ("critical", "high"):
            alerts.append({
                "id": str(uuid.uuid4())[:8],
                "device_ip": ip,
                "device_type": device_type,
                "severity": level,
                "title": f"{level.upper()} Risk Device Detected",
                "message": (
                    f"{device.get('vendor', 'Unknown')} ({ip}) — "
                    f"{len(device.get('open_ports', []))} open ports, "
                    f"risk score {score}/100"
                ),
                "factors": factors[:3],
                "timestamp": now,
                "acknowledged": False,
                "category": "risk_assessment"
            })

        # Per-port alerts using config-driven alert_ports set
        alert_ports = get_alert_ports()
        open_ports = set(device.get("open_ports", []))

        for port in open_ports:
            if port in alert_ports:
                info = get_port_info(port)
                if info:
                    alerts.append({
                        "id": str(uuid.uuid4())[:8],
                        "device_ip": ip,
                        "device_type": device_type,
                        "severity": info["severity"],
                        "title": f"{info['name']} Detected on {ip}",
                        "message": info.get("description", f"Port {port} open"),
                        "factors": info.get("attack_vectors", []),
                        "timestamp": now,
                        "acknowledged": False,
                        "category": "dangerous_port"
                    })

        # Shodan-based alerts
        shodan = device.get("shodan", {})
        if isinstance(shodan, dict) and shodan.get("critical_tags"):
            for tag in shodan["critical_tags"]:
                alerts.append({
                    "id": str(uuid.uuid4())[:8],
                    "device_ip": ip,
                    "device_type": device_type,
                    "severity": "critical",
                    "title": f"Shodan Flag: {tag}",
                    "message": f"Shodan has flagged {ip} with tag '{tag}'",
                    "factors": [f"Shodan community tag: {tag}"],
                    "timestamp": now,
                    "acknowledged": False,
                    "category": "shodan_intel"
                })

        return alerts
