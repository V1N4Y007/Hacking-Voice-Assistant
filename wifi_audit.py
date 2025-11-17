import subprocess

def scan_wifi_networks():
    try:
        output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], shell=True)
        return output.decode('utf-8')
    except Exception as e:
        return f"Error: {e}"