import subprocess
import time
import threading
import requests

VPN_NAME = "VPNGateJapan"   # name you set in Windows VPN settings
USERNAME = "vpn"
PASSWORD = "vpn"
IP_CHECK = "https://api.ipify.org"


def get_ip():
    try:
        return requests.get(IP_CHECK, timeout=5).text.strip()
    except:
        return "ERROR"


def connect_vpn(wait_for_change=True, timeout=30):
    print("[VPN] Connecting...")
    result = subprocess.run(["rasdial", VPN_NAME, USERNAME, PASSWORD],
                            capture_output=True, text=True)

    if result.returncode != 0:
        return False, f"rasdial error: {result.stderr or result.stdout}"

    if not wait_for_change:
        return True, "Connected (not verified)"

    orig_ip = get_ip()
    start = time.time()

    while time.time() - start < timeout:
        time.sleep(1.5)
        new_ip = get_ip()
        if new_ip != orig_ip and not new_ip.startswith("ERROR"):
            return True, f"New IP detected → {new_ip}"

    return False, "Connected, but IP did not change."


def disconnect_vpn():
    print("[VPN] Disconnecting...")
    result = subprocess.run(["rasdial", VPN_NAME, "/disconnect"],
                            capture_output=True, text=True)

    if result.returncode == 0:
        return True, "Disconnected."
    else:
        return False, result.stderr or result.stdout


def start_privacy_mode(duration=10):
    def worker():
        old_ip = get_ip()
        print("[Privacy Mode] Original IP:", old_ip)

        ok, msg = connect_vpn()
        if not ok:
            print("[Privacy Mode] ❌ Connect error:", msg)
            return

        print("[Privacy Mode] ✅", msg)
        print(f"[Privacy Mode] Active for {duration} minutes...")

        time.sleep(duration * 60)

        ok, msg = disconnect_vpn()
        print("[Privacy Mode] 🔓", msg)

    threading.Thread(target=worker, daemon=False).start()
