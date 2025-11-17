"""
light_arp_detector.py
User-friendly, non-admin network sanity checks:
 - polls ARP cache via `arp -a`
 - checks public IP via ipify
 - checks DNS servers via `ipconfig /all` (Windows)
 - optional TLS fingerprint check for a known HTTPS host

Works on Windows without admin privileges. On other OSes, arp parsing may differ slightly.
"""

import subprocess
import time
import threading
import re
import requests
import ssl
import socket
import hashlib

# ======= Config =======
POLL_INTERVAL = 10            # seconds between checks
GATEWAY_IP_HINT = None        # if you know your gateway IP set it here (e.g., "192.168.1.1"), else autodetect
MONITOR_HOST_FOR_TLS = "www.google.com"
TLS_PORT = 443
ENABLE_TLS_CHECK = False     # set True to enable cert fingerprint check (may slow things a bit)
# ======================

def run_cmd(cmd):
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=8)
        return cp.stdout + cp.stderr
    except Exception as e:
        return ""

def parse_arp_output(arp_text):
    """
    Parse arp -a output into dict {ip: mac}
    Works for typical Windows format; for other OSes the regex still often works.
    """
    table = {}
    # match lines like:  192.168.1.1           00-11-22-33-44-55     dynamic
    for line in arp_text.splitlines():
        # find ip
        m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        m_mac = re.search(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
        if m_ip and m_mac:
            ip = m_ip.group(1)
            mac = m_mac.group(1).replace("-", ":").lower()
            table[ip] = mac
    return table

def get_default_gateway_ip():
    """
    Try to detect gateway IP from ipconfig output (Windows) or by checking common local addresses.
    Returns an IP string or None.
    """
    out = run_cmd(["ipconfig", "/all"])
    # Search for "Default Gateway . . . . . . . . . : 192.168.1.1"
    m = re.search(r"Default Gateway[^\r\n:]*:\s*([\d\.]+)", out)
    if m:
        return m.group(1)
    # fallback: try to infer by looking at arp table first IPs (not ideal)
    return None

def get_dns_servers():
    out = run_cmd(["ipconfig", "/all"])
    # collect DNS Servers lines (can be multiple)
    dns = re.findall(r"DNS Servers[^\r\n:]*:\s*([\d\.]+)", out)
    return dns

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=6).text.strip()
    except Exception:
        return None

def get_tls_fingerprint(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(der).hexdigest()
                return fp
    except Exception:
        return None

class LightDetector:
    def __init__(self):
        self.baseline_arp = {}
        self.baseline_dns = []
        self.baseline_public_ip = None
        self.baseline_tls_fp = None
        self.gateway_ip = GATEWAY_IP_HINT or get_default_gateway_ip()

        # initialize baseline
        self._take_baseline()

    def _take_baseline(self):
        arp = parse_arp_output(run_cmd(["arp", "-a"]))
        self.baseline_arp = arp
        self.baseline_dns = get_dns_servers() or []
        self.baseline_public_ip = get_public_ip()
        if ENABLE_TLS_CHECK:
            self.baseline_tls_fp = get_tls_fingerprint(MONITOR_HOST_FOR_TLS, TLS_PORT)

    def _check_arp_changes(self, current_arp):
        alerts = []
        # focus on gateway and any previously seen entries
        keys_to_check = set(self.baseline_arp.keys()) | ({self.gateway_ip} if self.gateway_ip else set())
        for ip in keys_to_check:
            if not ip:
                continue
            base = self.baseline_arp.get(ip)
            cur = current_arp.get(ip)
            if base and cur and base != cur:
                alerts.append(f"MAC changed for {ip}: was {base}, now {cur}")
            # new entry where none before (informational)
            if not base and cur:
                alerts.append(f"New ARP entry seen: {ip} -> {cur}")
        return alerts

    def _check_dns_changes(self, current_dns):
        if current_dns != self.baseline_dns:
            return f"DNS servers changed: was {self.baseline_dns}, now {current_dns}"
        return None

    def _check_public_ip_change(self, current_ip):
        if current_ip and self.baseline_public_ip and current_ip != self.baseline_public_ip:
            return f"Public IP changed: was {self.baseline_public_ip}, now {current_ip}"
        return None

    def _check_tls(self):
        if not ENABLE_TLS_CHECK:
            return None
        cur_fp = get_tls_fingerprint(MONITOR_HOST_FOR_TLS, TLS_PORT)
        if self.baseline_tls_fp and cur_fp and cur_fp != self.baseline_tls_fp:
            return f"TLS certificate fingerprint changed for {MONITOR_HOST_FOR_TLS}"
        return None

    def poll_once(self):
        out = run_cmd(["arp", "-a"])
        curr_arp = parse_arp_output(out)
        alerts = []
        alerts += self._check_arp_changes(curr_arp)
        curr_dns = get_dns_servers()
        dns_alert = self._check_dns_changes(curr_dns)
        if dns_alert:
            alerts.append(dns_alert)
        curr_ip = get_public_ip()
        ip_alert = self._check_public_ip_change(curr_ip)
        if ip_alert:
            alerts.append(ip_alert)
        tls_alert = self._check_tls()
        if tls_alert:
            alerts.append(tls_alert)

        # print heartbeat or alerts
        if alerts:
            print("\n⚠️  Network Alert:")
            for a in alerts:
                print("  -", a)
            print("Take action: verify your router, reconnect to trusted network, or disconnect.")
            # Optionally refresh baseline after user confirms; we just keep baseline (safer)
        else:
            print("[✔] Network looks normal.")

    def run_loop(self, interval=POLL_INTERVAL):
        print("Light detector starting. No admin needed. Baseline captured.")
        print("Baseline gateway:", self.gateway_ip)
        while True:
            try:
                self.poll_once()
                time.sleep(interval)
            except KeyboardInterrupt:
                print("Stopping.")
                break
            except Exception as e:
                print("Detector error:", e)
                time.sleep(interval)

if __name__ == "__main__":
    det = LightDetector()
    det.run_loop()
