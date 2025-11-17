from voice import speak, takeCommand, wishMe
from phishing_detector import check_url_phishing
from wifi_audit import scan_wifi_networks
from port_scanner import run_nmap_scan
from privacy_mode import start_privacy_mode
from gemini_ai import ask_ai
from arp_spoof_detector import start_arp_spoof_detector
from metadata_cleaner import remove_metadata

if __name__ == "__main__":
    wishMe()
    while True:
        query = takeCommand().lower().replace("-", "").strip()

        if 'fishing link' in query or 'check url' in query:
            speak("Please type or paste the URL.")
            url = input("Enter URL: ")
            result = check_url_phishing(url)
            print(result)
            speak(result)

        elif 'scan wifi' in query or 'wifi audit' in query:
            speak("Scanning nearby Wi-Fi networks...")
            wifi_info = scan_wifi_networks()
            print(wifi_info)
            speak("Scan complete. Check terminal for network details.")

        elif 'scan for exploits' in query or 'port scan' in query:
            speak("Please enter the IP address to scan.")
            ip = input("Target IP: ")
            speak("Scanning open ports with Nmap...")
            ports_services = run_nmap_scan(ip)

            if not ports_services:
                speak("No open ports found or scan failed.")
                continue

            speak(f"Found {len(ports_services)} open ports.")
            for port, service in ports_services.items():
                speak(f"Port {port} is open and running {service}.")
                print(f"Port {port} is open and running {service}.")


        elif 'privacy mode' in query:
            speak("Activating privacy mode for 10 minutes.")
            start_privacy_mode()

        elif 'exit' in query or 'stop' in query:
            speak("Goodbye! Have a nice day.")
            break
        
        elif 'arp detect' in query:
            speak("Starting ARP spoof detection. Press Ctrl+C to stop.")
            start_arp_spoof_detector()

        elif 'clean metadata' in query:
            speak("Please enter the image file path to clean.")
            path = input("Image file path: ")
            remove_metadata(path)
        
        else:
            speak("Hello! How can I assist you today?")
            user_query = takeCommand().lower()
            response = ask_ai(user_query)
            speak(response)
