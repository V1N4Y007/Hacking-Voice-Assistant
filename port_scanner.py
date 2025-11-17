import subprocess

def run_nmap_scan(ip):
    try:
        nmap_path = r"C:/Program Files (x86)/Nmap/nmap.exe"  # Full path to nmap
        result = subprocess.check_output([nmap_path, "-sV", ip])
        output = result.decode()
        ports_services = {}
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = int(parts[0].split("/")[0])
                service = parts[2] if len(parts) >= 3 else "unknown"
                ports_services[port] = service
        return ports_services
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        return {}