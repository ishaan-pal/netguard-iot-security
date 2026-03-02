"""
Shodan InternetDB Enricher
Queries Shodan's free InternetDB API (no key required) to enrich device profiles
with real-world CVE data, known tags, and community-flagged risks.

API: https://internetdb.shodan.io/{ip}
Returns: open ports, hostnames, CPEs, CVEs, tags, vulns — all from Shodan's crawl data.
Rate limit: ~1 req/sec, free forever, no authentication.
"""

import asyncio
import logging
import time
from ipaddress import ip_address
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger("shodan_enricher")

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
REQUEST_TIMEOUT = 8.0
REQUEST_DELAY = 1.1  # Respect ~1 req/sec limit

# Tags that Shodan uses and what they mean for risk
SHODAN_TAG_RISK_MAP = {
    "self-signed":      ("medium", "Uses self-signed TLS certificate"),
    "default-login":    ("critical", "Shodan detected default credentials are active"),
    "honeypot":         ("info",    "Likely a honeypot — verify device legitimacy"),
    "scanner":          ("medium",  "Device is actively scanning the internet"),
    "tor":              ("high",    "Device is running a Tor exit/relay node"),
    "malware":          ("critical","Shodan has flagged this IP for malware activity"),
    "compromised":      ("critical","IP flagged as compromised in Shodan database"),
    "doublepulsar":     ("critical","DoublePulsar backdoor detected"),
    "eternalblue":      ("critical","EternalBlue (MS17-010) vulnerability detected"),
    "industrial":       ("high",    "Industrial control system (ICS/SCADA) device"),
    "ics":              ("high",    "ICS/SCADA device — high risk if internet-exposed"),
    "medical":          ("high",    "Medical device — HIPAA compliance risk"),
    "vpn":              ("info",    "VPN endpoint"),
    "starttls":         ("info",    "Supports STARTTLS"),
    "c2":               ("critical","Shodan flagged as Command & Control server"),
    "open-proxy":       ("high",    "Open proxy — may be abused"),
    "phishing":         ("critical","IP associated with phishing campaigns"),
    "spam":             ("high",    "IP listed on spam blacklists"),
}


class ShodanEnricher:
    def __init__(self):
        self._client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
        self._last_request_time: float = 0
        self._cache: Dict[str, Dict] = {}

    async def enrich_device(self, device: Dict) -> Dict:
        """
        Enrich a device dict with Shodan InternetDB data.
        Returns enrichment dict to merge into device profile.
        Skips private/local IPs (no Shodan data for RFC1918 addresses).
        """
        ip = device.get("ip", "")
        if not ip or not self._is_public_ip(ip):
            logger.debug(f"Skipping Shodan enrichment for private IP: {ip}")
            return {"shodan": {"skipped": "private_ip"}}

        # Return cached result if available
        if ip in self._cache:
            return self._cache[ip]

        # Rate limit
        elapsed = time.time() - self._last_request_time
        if elapsed < REQUEST_DELAY:
            await asyncio.sleep(REQUEST_DELAY - elapsed)

        try:
            url = INTERNETDB_URL.format(ip=ip)
            response = await self._client.get(url)
            self._last_request_time = time.time()

            if response.status_code == 404:
                # IP not in Shodan database — not necessarily bad
                result = {"shodan": {"found": False, "message": "IP not in Shodan database"}}
                self._cache[ip] = result
                return result

            if response.status_code != 200:
                logger.warning(f"Shodan InternetDB returned {response.status_code} for {ip}")
                return {"shodan": {"error": f"HTTP {response.status_code}"}}

            data = response.json()
            enrichment = self._parse_internetdb_response(ip, data)
            self._cache[ip] = enrichment

            if enrichment["shodan"].get("cves"):
                logger.info(f"Shodan: {ip} has {len(enrichment['shodan']['cves'])} known CVEs")
            if enrichment["shodan"].get("critical_tags"):
                logger.warning(f"Shodan: {ip} has critical tags: {enrichment['shodan']['critical_tags']}")

            return enrichment

        except httpx.TimeoutException:
            logger.warning(f"Shodan InternetDB timeout for {ip}")
            return {"shodan": {"error": "timeout"}}
        except Exception as e:
            logger.warning(f"Shodan enrichment failed for {ip}: {e}")
            return {"shodan": {"error": str(e)}}

    def _parse_internetdb_response(self, ip: str, data: Dict) -> Dict:
        """Parse InternetDB response into structured enrichment data."""
        cves = data.get("vulns", [])       # e.g. ["CVE-2021-44228", ...]
        tags = data.get("tags", [])         # e.g. ["self-signed", "default-login"]
        ports = data.get("ports", [])       # Open ports Shodan found
        hostnames = data.get("hostnames", [])
        cpes = data.get("cpes", [])         # Component versions e.g. "cpe:/a:apache:http_server:2.4.41"

        # Analyze tags for risk
        risk_findings = []
        critical_tags = []
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in SHODAN_TAG_RISK_MAP:
                severity, description = SHODAN_TAG_RISK_MAP[tag_lower]
                risk_findings.append({
                    "source": "shodan_tag",
                    "tag": tag,
                    "severity": severity,
                    "description": description
                })
                if severity == "critical":
                    critical_tags.append(tag)

        # Calculate shodan-derived risk bonus
        shodan_risk_bonus = 0
        for finding in risk_findings:
            severity_scores = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
            shodan_risk_bonus += severity_scores.get(finding["severity"], 0)

        # CVE severity estimation (basic — real severity needs NVD lookup)
        cve_risk = min(len(cves) * 8, 40)  # Cap at 40 points from CVEs
        shodan_risk_bonus += cve_risk

        # Ports Shodan found but we didn't (additional attack surface)
        additional_ports = [p for p in ports if p not in data.get("known_ports", [])]

        return {
            "shodan": {
                "found": True,
                "cves": cves,
                "cve_count": len(cves),
                "tags": tags,
                "critical_tags": critical_tags,
                "ports_found": ports,
                "hostnames": hostnames,
                "cpes": cpes,
                "risk_findings": risk_findings,
                "risk_bonus": min(shodan_risk_bonus, 50),  # Cap total Shodan bonus
                "summary": self._build_summary(ip, cves, tags, ports)
            }
        }

    def _build_summary(self, ip: str, cves: List, tags: List, ports: List) -> str:
        parts = []
        if cves:
            parts.append(f"{len(cves)} known CVE(s): {', '.join(cves[:3])}")
        if tags:
            risky = [t for t in tags if t.lower() in SHODAN_TAG_RISK_MAP]
            if risky:
                parts.append(f"Shodan tags: {', '.join(risky)}")
        if ports:
            parts.append(f"Shodan found {len(ports)} open port(s)")
        return ". ".join(parts) if parts else "No notable findings in Shodan database"

    def _is_public_ip(self, ip_str: str) -> bool:
        """Return True if the IP is a public (non-RFC1918) address."""
        try:
            ip = ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        except ValueError:
            return False

    async def enrich_devices_batch(self, devices: List[Dict]) -> Dict[str, Dict]:
        """Enrich multiple devices, respecting rate limits."""
        results = {}
        public_devices = [d for d in devices if self._is_public_ip(d.get("ip", ""))]

        if not public_devices:
            logger.info("All devices are on private network — Shodan enrichment skipped")
            return results

        logger.info(f"Shodan enrichment: checking {len(public_devices)} public IPs")
        for device in public_devices:
            ip = device.get("ip")
            enrichment = await self.enrich_device(device)
            results[ip] = enrichment.get("shodan", {})

        return results

    def get_cached_enrichment(self, ip: str) -> Optional[Dict]:
        """Return cached Shodan data for an IP if available."""
        cached = self._cache.get(ip, {})
        return cached.get("shodan")
