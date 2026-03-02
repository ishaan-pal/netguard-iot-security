"""
IoT Security AI Agent
Uses Groq Cloud API with Llama 3 70B for intelligent risk analysis,
vulnerability assessment, and actionable security recommendations.
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("ai_agent")

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

SYSTEM_PROMPT = """You are an expert IoT cybersecurity analyst specializing in home network security. 
Your role is to analyze network device profiles and identify security risks.

You ALWAYS respond with valid JSON only — no markdown, no explanation outside the JSON structure.

Your analysis must be precise, actionable, and tailored to the specific device profile provided."""

BATCH_ANALYSIS_PROMPT = """Analyze the following home network devices for security risks.

For each device, provide:
1. risk_score: Integer 0-100 (0=no risk, 100=critical risk)
2. risk_level: "low" | "medium" | "high" | "critical"
3. risk_factors: List of specific risk factors found
4. recommendations: List of specific, actionable security recommendations
5. predicted_attack_vectors: List of likely attack vectors if exploited
6. exploitation_likelihood: "very_low" | "low" | "medium" | "high" | "very_high"
7. summary: 1-2 sentence summary

Consider:
- Open ports and their security implications
- Device type and typical vulnerability patterns
- OS/firmware age indicators
- Protocol security (encrypted vs unencrypted)
- Default credential risks for device type
- Known CVEs for identified software versions
- Network exposure level

Devices to analyze:
{devices_json}

Respond with a JSON object where keys are IP addresses:
{{
  "192.168.1.x": {{
    "risk_score": 75,
    "risk_level": "high",
    "risk_factors": ["Telnet open on port 23", "No HTTPS enforcement"],
    "recommendations": ["Disable Telnet immediately", "Enable HTTPS redirect"],
    "predicted_attack_vectors": ["Credential interception via Telnet", "MITM attack"],
    "exploitation_likelihood": "high",
    "summary": "This router exposes an unencrypted Telnet interface..."
  }}
}}"""

DEEP_ANALYSIS_PROMPT = """Perform a comprehensive security audit for this specific IoT device.

Device Profile:
{device_json}

Provide an expert-level analysis covering:
1. executive_summary: 3-4 sentence executive summary for a non-technical homeowner
2. technical_summary: Technical summary for a security professional
3. critical_issues: List of issues requiring immediate action
4. vulnerability_details: Detailed breakdown of each vulnerability
5. remediation_steps: Step-by-step remediation guide (numbered, specific)
6. hardening_checklist: Security hardening checklist items
7. risk_timeline: How the risk could evolve if unaddressed (1 week, 1 month, 6 months)
8. cvss_estimate: Estimated CVSS base score (0.0-10.0)
9. compliance_notes: Relevant security standards/frameworks (NIST, CIS, etc.)
10. priority: "immediate" | "urgent" | "planned" | "informational"

Respond with a single JSON object."""

NETWORK_SUMMARY_PROMPT = """You are analyzing the complete security posture of a home network.

Network scan results:
{summary_json}

Provide a comprehensive network security assessment:
1. overall_security_grade: Letter grade (A+ to F) with reasoning
2. network_risk_score: Overall network risk 0-100
3. top_threats: Top 5 threats to the entire network
4. critical_devices: Devices requiring immediate attention (IPs + reasons)
5. attack_surface_analysis: Analysis of the network's attack surface
6. recommended_segmentation: Network segmentation recommendations
7. priority_actions: Ordered list of immediate actions (most critical first)
8. security_wins: What's already being done well
9. threat_intelligence: Relevant current threat landscape for home IoT networks

Respond with a single JSON object."""


class IoTSecurityAgent:
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model
        self.client = httpx.AsyncClient(timeout=60.0)
        self._request_count = 0
        self._last_request_time = 0

        if not api_key or api_key == "your_groq_api_key_here":
            logger.warning("⚠️  GROQ_API_KEY not configured — AI analysis will be limited")

    async def _call_groq(self, messages: List[Dict], max_tokens: int = 2048) -> Optional[str]:
        """Make a rate-limited call to Groq API"""
        if not self.api_key or self.api_key == "your_groq_api_key_here":
            logger.warning("Groq API key not set — returning mock analysis")
            return None

        # Basic rate limiting (Groq free tier: ~30 RPM)
        elapsed = time.time() - self._last_request_time
        if elapsed < 2.0:
            await asyncio.sleep(2.0 - elapsed)

        try:
            response = await self.client.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": 0.1,  # Low temp for consistent structured output
                    "response_format": {"type": "json_object"}
                }
            )

            self._last_request_time = time.time()
            self._request_count += 1

            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                logger.debug(f"Groq response ({len(content)} chars), tokens used: {data.get('usage', {})}")
                return content
            elif response.status_code == 429:
                logger.warning("Groq rate limit hit — waiting 60s")
                await asyncio.sleep(60)
                return None
            else:
                logger.error(f"Groq API error {response.status_code}: {response.text[:200]}")
                return None

        except httpx.TimeoutException:
            logger.error("Groq API timeout")
            return None
        except Exception as e:
            logger.error(f"Groq API call failed: {e}")
            return None

    async def analyze_devices(self, devices: List[Dict]) -> Dict[str, Dict]:
        """Batch analyze multiple devices for risk — called on every scan"""
        if not devices:
            return {}

        results = {}

        # Process in batches of 10 to stay within token limits
        batch_size = 10
        for i in range(0, len(devices), batch_size):
            batch = devices[i:i + batch_size]

            # Summarize each device for the prompt (keep tokens manageable)
            device_summaries = []
            for d in batch:
                summary = {
                    "ip": d.get("ip"),
                    "mac": d.get("mac", ""),
                    "vendor": d.get("vendor", "Unknown"),
                    "hostname": d.get("hostname", ""),
                    "device_type": d.get("device_type", "unknown"),
                    "os_guess": d.get("os_guess", ""),
                    "open_ports": d.get("open_ports", []),
                    "services": {
                        str(p): {
                            "name": s.get("name", ""),
                            "product": s.get("product", ""),
                            "version": s.get("version", "")
                        }
                        for p, s in list(d.get("services", {}).items())[:10]
                    },
                    "vulnerabilities_found": [v.get("description") for v in d.get("vulnerabilities", [])],
                    "weak_configs": d.get("weak_configs", [])[:5],
                }
                # Include Shodan enrichment if available
                shodan = d.get("shodan", {})
                if isinstance(shodan, dict) and shodan.get("found"):
                    summary["shodan_cves"] = shodan.get("cves", [])[:5]
                    summary["shodan_tags"] = shodan.get("tags", [])
                    summary["shodan_summary"] = shodan.get("summary", "")

                device_summaries.append(summary)

            prompt = BATCH_ANALYSIS_PROMPT.format(
                devices_json=json.dumps(device_summaries, indent=2)
            )

            response_text = await self._call_groq([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ], max_tokens=3000)

            if response_text:
                try:
                    parsed = json.loads(response_text)
                    results.update(parsed)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse AI batch response: {e}")
                    # Fallback: use rule-based analysis
                    for d in batch:
                        ip = d.get("ip")
                        if ip:
                            results[ip] = self._fallback_analysis(d)
            else:
                # Use rule-based fallback when API unavailable
                for d in batch:
                    ip = d.get("ip")
                    if ip:
                        results[ip] = self._fallback_analysis(d)

        return results

    async def deep_analyze_device(self, device: Dict) -> Dict:
        """Comprehensive single-device analysis"""
        device_summary = {
            "ip": device.get("ip"),
            "vendor": device.get("vendor", "Unknown"),
            "device_type": device.get("device_type", "unknown"),
            "os_guess": device.get("os_guess", ""),
            "hostname": device.get("hostname", ""),
            "open_ports": device.get("open_ports", []),
            "services": device.get("services", {}),
            "vulnerabilities": device.get("vulnerabilities", []),
            "weak_configs": device.get("weak_configs", []),
            "risky_ports": device.get("risky_ports", []),
            "http_info": device.get("http_info", {}),
        }

        prompt = DEEP_ANALYSIS_PROMPT.format(
            device_json=json.dumps(device_summary, indent=2)
        )

        response_text = await self._call_groq([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ], max_tokens=2500)

        if response_text:
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                pass

        return self._fallback_deep_analysis(device)

    async def generate_network_report(self, devices: List[Dict]) -> Dict:
        """Generate overall network security report"""
        summary = {
            "total_devices": len(devices),
            "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "device_types": {},
            "all_open_ports": [],
            "devices": []
        }

        for d in devices:
            lvl = d.get("risk_level", "low")
            summary["risk_distribution"][lvl] = summary["risk_distribution"].get(lvl, 0) + 1
            dtype = d.get("device_type", "unknown")
            summary["device_types"][dtype] = summary["device_types"].get(dtype, 0) + 1
            summary["all_open_ports"].extend(d.get("open_ports", []))
            summary["devices"].append({
                "ip": d.get("ip"),
                "device_type": dtype,
                "risk_level": lvl,
                "risk_score": d.get("risk_score", 0)
            })

        prompt = NETWORK_SUMMARY_PROMPT.format(
            summary_json=json.dumps(summary, indent=2)
        )

        response_text = await self._call_groq([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ], max_tokens=2000)

        if response_text:
            try:
                return json.loads(response_text)
            except json.JSONDecodeError:
                pass

        return {"error": "Could not generate network report", "devices_analyzed": len(devices)}

    def _fallback_analysis(self, device: Dict) -> Dict:
        """Rule-based risk analysis when AI is unavailable"""
        open_ports = set(device.get("open_ports", []))
        vulnerabilities = device.get("vulnerabilities", [])
        weak_configs = device.get("weak_configs", [])

        risk_score = 0
        risk_factors = []
        recommendations = []

        # Critical ports
        CRITICAL = {23: "Telnet", 21: "FTP", 3389: "RDP", 5900: "VNC"}
        for port, name in CRITICAL.items():
            if port in open_ports:
                risk_score += 30
                risk_factors.append(f"{name} (port {port}) is open — critical risk")
                recommendations.append(f"Immediately disable {name} on port {port}")

        # High risk ports
        HIGH = {1883: "MQTT", 6379: "Redis", 27017: "MongoDB"}
        for port, name in HIGH.items():
            if port in open_ports:
                risk_score += 20
                risk_factors.append(f"{name} (port {port}) exposed")
                recommendations.append(f"Restrict {name} access to trusted hosts only")

        # Vulnerabilities from profiler
        for v in vulnerabilities:
            if v.get("severity") == "critical":
                risk_score += 25
            elif v.get("severity") == "high":
                risk_score += 15
            elif v.get("severity") == "medium":
                risk_score += 8
            risk_factors.append(v.get("description", "Unknown vulnerability"))

        # Weak configs
        risk_score += len(weak_configs) * 5
        for wc in weak_configs:
            recommendations.append(f"Fix: {wc}")

        # Default credential risk
        if device.get("default_cred_risk"):
            risk_score += 15
            risk_factors.append(f"Possible default credentials: {device['default_cred_risk']}")
            recommendations.append("Change default credentials immediately")

        risk_score = min(100, risk_score)

        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors or ["No significant risks detected"],
            "recommendations": recommendations or ["Monitor device for unusual activity"],
            "predicted_attack_vectors": [],
            "exploitation_likelihood": "low" if risk_score < 25 else "medium" if risk_score < 50 else "high",
            "summary": f"{device.get('device_type', 'Device')} at {device.get('ip')} scored {risk_score}/100 risk (rule-based analysis).",
            "analysis_method": "rule_based"
        }

    def _fallback_deep_analysis(self, device: Dict) -> Dict:
        base = self._fallback_analysis(device)
        return {
            **base,
            "executive_summary": f"This {device.get('device_type', 'device')} has a risk score of {base['risk_score']}/100 based on {len(device.get('open_ports', []))} open ports and {len(device.get('vulnerabilities', []))} detected vulnerabilities.",
            "technical_summary": f"Device profile: {device.get('vendor', 'Unknown')} device running {device.get('os_guess', 'unknown OS')} with ports {device.get('open_ports', [])}.",
            "critical_issues": [f for f in base["risk_factors"] if "critical" in f.lower() or "telnet" in f.lower() or "rdp" in f.lower()],
            "remediation_steps": base["recommendations"],
            "hardening_checklist": [
                "Change default credentials",
                "Disable unused services and ports",
                "Enable encrypted protocols (HTTPS, SSH, MQTT-TLS)",
                "Update firmware to latest version",
                "Enable network firewall rules",
            ],
            "priority": "immediate" if base["risk_score"] >= 70 else "urgent" if base["risk_score"] >= 50 else "planned",
            "analysis_method": "rule_based"
        }
