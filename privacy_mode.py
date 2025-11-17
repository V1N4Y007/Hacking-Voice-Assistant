import subprocess
import time
import threading
import requests

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        return response.text
    except:
        return "Unable to retrieve IP"

def connect_vpn():
    try:
        subprocess.call("windscribe connect", shell=True)
        time.sleep(3)
        print("[Privacy Mode] ✅ VPN connected.")
    except Exception as e:
        print(f"[Privacy Mode] ❌ VPN connection failed: {e}")

def disconnect_vpn():
    try:
        subprocess.call("windscribe disconnect", shell=True)
        print("[Privacy Mode] 🔓 VPN disconnected.")
    except Exception as e:
        print(f"[Privacy Mode] ❌ VPN disconnection failed: {e}")

def start_privacy_mode(duration=10):
    def vpn_loop():
        print("[Privacy Mode] 🌐 Original IP:", get_public_ip())
        connect_vpn()
        print("[Privacy Mode] 🧭 New IP:", get_public_ip())
        print(f"[Privacy Mode] 🔐 Active for {duration} minutes.")
        time.sleep(duration * 60)
        disconnect_vpn()
        print("[Privacy Mode] ⛔ Privacy mode ended.")

    threading.Thread(target=vpn_loop, daemon=True).start()
