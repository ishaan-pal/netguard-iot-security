"""
Network Scanner Module
Discovers all devices using nmap + ARP scanning.
Port-to-device-type hints loaded from config — zero hardcoded port sets.
"""

import logging
import socket
import subprocess
import time
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

from config_loader import get_all_port_device_hints

logger = logging.getLogger("scanner")

# OUI vendor map — kept here as it's hardware-identity data, not security rules
OUI_VENDOR_MAP = {
    "00:50:56": "VMware", "00:0c:29": "VMware",
    "bc:9a:78": "Tuya Smart", "ac:84:c6": "Tuya Smart",
    "d8:f1:5b": "Amazon Technologies", "fc:65:de": "Amazon Technologies",
    "78:e1:03": "Amazon Technologies",
    "b4:7c:9c": "Google", "f4:f5:d8": "Google", "54:60:09": "Google",
    "70:3a:cb": "Apple", "a4:c3:f0": "Apple",
    "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "00:17:88": "Philips (Hue)", "ec:b5:fa": "Philips (Hue)",
    "f0:27:2d": "Samsung Electronics", "8c:77:12": "Samsung Electronics",
    "b0:be:76": "TP-Link", "50:c7:bf": "TP-Link", "c4:e9:84": "TP-Link",
    "18:d6:c7": "TP-Link", "14:cc:20": "TP-Link",
    "e8:65:d4": "Xiaomi", "00:9e:c8": "Xiaomi", "fc:64:ba": "Xiaomi",
    "68:cc:6e": "Xiaomi", "98:fa:e3": "Xiaomi",
    "10:02:b5": "D-Link", "00:26:b9": "Dell",
    "00:1a:2b": "Cisco", "00:1b:54": "Cisco",
    "d0:57:94": "Netgear", "30:46:9a": "Netgear", "a0:40:a0": "Netgear",
    "c8:3a:35": "Tenda", "c8:d3:a3": "Huawei", "58:2a:f7": "Huawei",
    "a4:8c:db": "LG Electronics", "78:5d:c8": "Sony", "f0:3e:90": "Sony",
    "00:1c:c0": "Ubiquiti", "04:18:d6": "Ubiquiti", "78:8a:20": "Ubiquiti",
}

# These are identity/classification hints, not security rules — appropriate to keep here
VENDOR_DEVICE_TYPE = {
    "philips": "smart_bulb", "hue": "smart_bulb",
    "amazon": "smart_speaker", "alexa": "smart_speaker",
    "google": "smart_speaker", "chromecast": "chromecast",
    "apple": "apple_device",
    "raspberry": "single_board_computer",
    "tp-link": "router", "netgear": "router", "asus": "router",
    "linksys": "router", "d-link": "router", "ubiquiti": "router",
    "cisco": "router", "tenda": "router",
    "samsung": "smart_tv", "lg": "smart_tv", "sony": "smart_tv",
    "hikvision": "ip_camera", "dahua": "ip_camera", "axis": "ip_camera",
    "tuya": "iot_hub",
}

OS_DEVICE_TYPE = {
    "windows": "windows_pc",
    "linux": "linux_device",
    "android": "android_device",
    "ios": "apple_device",
    "iphone": "apple_device",
    "macos": "apple_device",
}


class NetworkScanner:
    def __init__(self):
        self._check_nmap()

    def _check_nmap(self):
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            logger.info(result.stdout.split("\n")[0])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("nmap not found — install from https://nmap.org/download.html")

    def _get_local_network(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.rsplit(".", 1)
            network = f"{parts[0]}.0/24"
            logger.info(f"Auto-detected network: {network} (local IP: {local_ip})")
            return network
        except Exception as e:
            logger.error(f"Network detection failed: {e}")
            return "192.168.1.0/24"

    def discover_devices(self, network_range: str = "auto") -> List[Dict]:
        if network_range == "auto" or not network_range:
            network_range = self._get_local_network()

        logger.info(f"Starting device discovery on {network_range}")
        start = time.time()

        live_hosts = self._arp_ping_scan(network_range)
        logger.info(f"ARP ping found {len(live_hosts)} live hosts")

        if live_hosts:
            port_results = self._port_scan(live_hosts)
            devices = self._merge_results(live_hosts, port_results)
        else:
            devices = self._full_nmap_scan(network_range)

        elapsed = round(time.time() - start, 2)
        logger.info(f"Discovery complete: {len(devices)} devices in {elapsed}s")
        return devices

    def _arp_ping_scan(self, network: str) -> List[Dict]:
        try:
            cmd = ["nmap", "-sn", "-PR", "--send-eth", "--host-timeout", "5s", "-oX", "-", network]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return self._parse_nmap_xml(result.stdout, minimal=True)
        except Exception:
            return self._icmp_ping_scan(network)

    def _icmp_ping_scan(self, network: str) -> List[Dict]:
        try:
            result = subprocess.run(["nmap", "-sn", "-oX", "-", network],
                                    capture_output=True, text=True, timeout=60)
            return self._parse_nmap_xml(result.stdout, minimal=True)
        except Exception as e:
            logger.error(f"ICMP scan failed: {e}")
            return []

    def _port_scan(self, hosts: List[Dict]) -> Dict[str, Dict]:
        if not hosts:
            return {}
        host_ips = " ".join(h["ip"] for h in hosts[:50])
        try:
            cmd = [
                "nmap", "-sV", "-sS", "--version-intensity", "5",
                "-O", "--osscan-guess",
                "-p", "T:20-23,25,53,80,110,143,443,445,554,631,993,995,1883,3306,3389,"
                      "5353,5432,5683,5900,6379,7000,7100,8009,8080,8443,8554,8883,8888,"
                      "9100,27017,49152,49153,62078",
                "--host-timeout", "30s",
                "--script", "banner,http-title,ssl-cert",
                "-oX", "-"
            ] + host_ips.split()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            devices = self._parse_nmap_xml(result.stdout, minimal=False)
            return {d["ip"]: d for d in devices}
        except Exception as e:
            logger.warning(f"Port scan error: {e}")
            return {}

    def _full_nmap_scan(self, network: str) -> List[Dict]:
        try:
            cmd = ["nmap", "-sV", "-O", "--osscan-guess",
                   "-p", "21-23,80,443,1883,3389,5900,6379,8080",
                   "--host-timeout", "20s", "-oX", "-", network]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout, minimal=False)
        except Exception as e:
            logger.error(f"Full scan failed: {e}")
            return []

    def _parse_nmap_xml(self, xml_output: str, minimal: bool = False) -> List[Dict]:
        devices = []
        if not xml_output.strip():
            return devices
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.warning(f"XML parse error: {e}")
            return devices

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            device = {
                "ip": "", "mac": "", "hostname": "", "vendor": "Unknown",
                "open_ports": [], "services": {}, "os_guess": "",
                "device_type": "unknown", "last_seen": time.time(),
                "discovery_method": "nmap"
            }

            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    device["ip"] = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    device["mac"] = addr.get("addr", "").upper()
                    vendor = addr.get("vendor", "")
                    if vendor:
                        device["vendor"] = vendor

            if not device["ip"]:
                continue

            if device["mac"] and device["vendor"] == "Unknown":
                oui = device["mac"][:8].lower()
                device["vendor"] = OUI_VENDOR_MAP.get(oui, "Unknown")

            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hn in hostnames.findall("hostname"):
                    name = hn.get("name", "")
                    if name and not name.endswith(".arpa"):
                        device["hostname"] = name
                        break

            if minimal:
                devices.append(device)
                continue

            os_elem = host.find("os")
            if os_elem is not None:
                matches = os_elem.findall("osmatch")
                if matches:
                    best = max(matches, key=lambda x: int(x.get("accuracy", "0")))
                    device["os_guess"] = best.get("name", "")
                    device["os_accuracy"] = int(best.get("accuracy", "0"))

            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    portnum = int(port.get("portid", 0))
                    device["open_ports"].append(portnum)
                    service = port.find("service")
                    svc_info = {}
                    if service is not None:
                        svc_info = {
                            "name": service.get("name", ""),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", "")
                        }
                    device["services"][portnum] = svc_info
                    for script in port.findall("script"):
                        sid = script.get("id", "")
                        if sid == "banner":
                            svc_info["banner"] = script.get("output", "")[:200]
                        elif sid == "http-title":
                            svc_info["http_title"] = script.get("output", "")

            device["device_type"] = self._guess_device_type(device)
            devices.append(device)

        return devices

    def _merge_results(self, arp_hosts: List[Dict], port_results: Dict[str, Dict]) -> List[Dict]:
        merged = []
        for host in arp_hosts:
            ip = host["ip"]
            if ip in port_results:
                detail = port_results[ip]
                if not detail.get("mac") and host.get("mac"):
                    detail["mac"] = host["mac"]
                if not detail.get("vendor") or detail["vendor"] == "Unknown":
                    detail["vendor"] = host.get("vendor", "Unknown")
                merged.append(detail)
            else:
                merged.append(host)
        return merged

    def _guess_device_type(self, device: Dict) -> str:
        """Classify device type using vendor, OS, hostname, and config-driven port hints."""
        ports = set(device.get("open_ports", []))
        vendor = device.get("vendor", "").lower()
        os_guess = device.get("os_guess", "").lower()
        hostname = device.get("hostname", "").lower()
        services = device.get("services", {})

        http_titles = " ".join(
            str(v.get("http_title", "")) for v in services.values()
        ).lower()

        # Vendor-based
        for kw, dtype in VENDOR_DEVICE_TYPE.items():
            if kw in vendor:
                return dtype

        # OS-based
        for kw, dtype in OS_DEVICE_TYPE.items():
            if kw in os_guess:
                if kw == "linux" and any(k in hostname for k in ("cam", "camera", "ipcam")):
                    return "ip_camera"
                return dtype

        # Port-based hints from config
        port_hints = get_all_port_device_hints()
        port_type_votes: Dict[str, int] = {}
        for port in ports:
            hint = port_hints.get(port)
            if hint:
                port_type_votes[hint] = port_type_votes.get(hint, 0) + 1

        if port_type_votes:
            best_type = max(port_type_votes, key=lambda k: port_type_votes[k])
            if best_type:
                return best_type

        # HTTP title hints
        title_hints = [
            ("router", "router"), ("gateway", "router"), ("modem", "router"),
            ("camera", "ip_camera"), ("dvr", "ip_camera"), ("nvr", "ip_camera"),
            ("printer", "printer"), ("print", "printer"),
            ("tv", "smart_tv"), ("television", "smart_tv"),
        ]
        for keyword, dtype in title_hints:
            if keyword in http_titles:
                return dtype

        # Hostname hints
        hostname_hints = [
            ("cam", "ip_camera"), ("camera", "ip_camera"),
            ("router", "router"), ("gateway", "router"),
            ("printer", "printer"), ("print", "printer"),
            ("tv", "smart_tv"), ("nas", "nas"), ("storage", "nas"),
        ]
        for keyword, dtype in hostname_hints:
            if keyword in hostname:
                return dtype

        if ports:
            return "networked_device"
        return "unknown"
