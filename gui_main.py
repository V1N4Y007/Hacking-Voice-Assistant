import threading
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
import sys
import os
from datetime import datetime
import subprocess
import time
import queue
import re


class HackSpeakGUI:
    def __init__(self):
        # Initialize ALL attributes FIRST before doing anything else
        self.modules = {}  # CRITICAL: Initialize this first!
        self.is_listening = False
        self.current_thread = None
        self.engine = None  # Initialize TTS engine attribute
        self.recognizer = None  # Initialize speech recognition attribute
        
        # Detector attributes (non-admin mode)
        self.detector_thread = None
        self.detector_stop_event = threading.Event()
        self.detector_running = False
        self.detector_baseline = {}
        self.detector_baseline_dns = []
        self.detector_baseline_ip = None
        self.detector_gateway = None
        self.detector_poll_interval = 10  # seconds
        
        # Initialize tkinter
        self.root = tk.Tk()
        self.setup_window()
        
        # Thread-safe queue for GUI updates
        self.gui_queue = queue.Queue()
        
        # Initialize GUI elements
        self.create_widgets()
        
        # Start GUI update checker
        self.check_queue()
        
        # Try to import modules with fallbacks - AFTER GUI is ready
        self.load_modules()
        
    def check_queue(self):
        """Check queue for GUI updates from other threads - THREAD SAFE"""
        try:
            while True:
                # Non-blocking queue check
                message_type, message_data = self.gui_queue.get_nowait()
                
                if message_type == "output":
                    text, msg_type = message_data
                    self._append_output_safe(text, msg_type)
                elif message_type == "status":
                    status = message_data
                    self._update_status_safe(status)
                elif message_type == "speak":
                    text = message_data
                    self._speak_safe(text)
                elif message_type == "button_state":
                    button, state, text, color = message_data
                    button.config(text=text, bg=color)
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.check_queue)
    
    def thread_safe_output(self, text, msg_type="normal"):
        """Thread-safe method to add output"""
        self.gui_queue.put(("output", (text, msg_type)))
    
    def thread_safe_status(self, status):
        """Thread-safe method to update status"""
        self.gui_queue.put(("status", status))
    
    def thread_safe_speak(self, text):
        """Thread-safe method for TTS"""
        self.gui_queue.put(("speak", text))
        
    def thread_safe_button_update(self, button, state, text, color):
        """Thread-safe method to update button"""
        self.gui_queue.put(("button_state", (button, state, text, color)))
        
    def load_modules(self):
        """Load modules with error handling"""
        # Voice module
        try:
            import pyttsx3
            import speech_recognition as sr
            self.modules['voice'] = True
            self.init_voice()
        except ImportError:
            self.modules['voice'] = False
            self.thread_safe_output("Voice modules not available (pyttsx3, speech_recognition)", "warning")
        
        # Other modules
        module_list = [
            ('phishing_detector', 'phishing_detector'),
            ('wifi_audit', 'wifi_audit'), 
            ('port_scanner', 'port_scanner'),
            ('privacy_mode', 'privacy_mode'),
            ('gemini_ai', 'gemini_ai'),
            ('arp_spoof_detector', 'arp_spoof_detector'),
            ('metadata_cleaner', 'metadata_cleaner')
        ]
        
        for module_name, file_name in module_list:
            try:
                self.modules[module_name] = __import__(file_name)
                self.thread_safe_output(f"Loaded {module_name}", "success")
            except ImportError as e:
                self.modules[module_name] = None
                self.thread_safe_output(f"Failed to load {module_name}: {str(e)}", "warning")
    
    def init_voice(self):
        """Initialize voice components"""
        try:
            import pyttsx3
            self.engine = pyttsx3.init('sapi5')
            voices = self.engine.getProperty('voices')
            if voices and len(voices) > 1:
                self.engine.setProperty('voice', voices[1].id)
            self.engine.setProperty('rate', 190)
            
            import speech_recognition as sr
            self.recognizer = sr.Recognizer()
            self.recognizer.energy_threshold = 300
            self.recognizer.pause_threshold = 1.0
            
        except Exception as e:
            self.modules['voice'] = False
            self.thread_safe_output(f"Voice initialization failed: {str(e)}", "error")
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("HackSpeak - Cybersecurity Assistant")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1a1a1a")
        self.root.resizable(True, True)
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1200 // 2)
        y = (self.root.winfo_screenheight() // 2) - (800 // 2)
        self.root.geometry(f"1200x800+{x}+{y}")
        
    def create_widgets(self):
        """Create and arrange all GUI widgets"""
        
        # Header
        header = tk.Frame(self.root, bg="#1a1a1a", height=60)
        header.pack(fill="x", padx=20, pady=20)
        header.pack_propagate(False)
        
        tk.Label(header, text="HackSpeak Assistant", 
                font=("Arial", 28, "bold"), fg="#00ff41", bg="#1a1a1a").pack(side="left")
        
        self.status_label = tk.Label(header, text="Ready", 
                                   font=("Arial", 12), fg="#00ff41", bg="#1a1a1a")
        self.status_label.pack(side="right")
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=20)
        
        # Left panel - Controls
        control_panel = tk.Frame(main_frame, bg="#2d2d2d", width=300)
        control_panel.pack(side="left", fill="y", padx=(0, 10))
        control_panel.pack_propagate(False)
        
        # Voice controls
        voice_frame = tk.LabelFrame(control_panel, text="Voice Control", 
                                   bg="#2d2d2d", fg="white", font=("Arial", 12, "bold"))
        voice_frame.pack(fill="x", padx=10, pady=10)
        
        self.voice_btn = tk.Button(voice_frame, text="Start Listening", 
                                  bg="#4CAF50", fg="white", font=("Arial", 14, "bold"),
                                  command=self.toggle_voice, pady=10)
        self.voice_btn.pack(fill="x", padx=10, pady=10)
        
        # Feature buttons
        features_frame = tk.LabelFrame(control_panel, text="Security Tools", 
                                     bg="#2d2d2d", fg="white", font=("Arial", 12, "bold"))
        features_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        buttons = [
            ("Check URL", self.check_url, "#FF5722"),
            ("WiFi Scan", self.wifi_scan, "#2196F3"), 
            ("Port Scan", self.port_scan, "#FF9800"),
            ("Clean Metadata", self.clean_metadata, "#9C27B0"),
            ("Privacy Mode", self.privacy_mode, "#795548"),
            ("ARP Detection", self.arp_detection, "#F44336"),
            ("Ask AI", self.ask_ai, "#4CAF50")
        ]
        
        for text, command, color in buttons:
            btn = tk.Button(features_frame, text=text, bg=color, fg="white",
                           font=("Arial", 11, "bold"), command=command, pady=5)
            btn.pack(fill="x", padx=5, pady=3)
        
        # Right panel - Output
        output_panel = tk.Frame(main_frame, bg="#2d2d2d")
        output_panel.pack(side="right", fill="both", expand=True)
        
        # Output area
        output_frame = tk.LabelFrame(output_panel, text="Output", 
                                   bg="#2d2d2d", fg="white", font=("Arial", 12, "bold"))
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, bg="#1a1a1a", fg="#00ff41",
                                                    font=("Consolas", 10), wrap=tk.WORD, 
                                                    state="disabled")
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Input area
        input_frame = tk.Frame(output_panel, bg="#2d2d2d")
        input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.input_entry = tk.Entry(input_frame, bg="#1a1a1a", fg="white", 
                                   font=("Arial", 11), insertbackground="white")
        self.input_entry.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=5)
        self.input_entry.bind("<Return>", self.handle_text_input)
        
        tk.Button(input_frame, text="Send", bg="#4CAF50", fg="white",
                 command=self.handle_text_input, font=("Arial", 10, "bold")).pack(side="right")
        
        # Welcome message - DELAY this until after modules are loaded
        self.root.after(500, self.show_welcome_message)
    
    def show_welcome_message(self):
        """Show welcome messages after GUI is fully initialized"""
        self.thread_safe_output("HackSpeak Assistant Ready!", "system")
        self.thread_safe_output("Use voice commands or click buttons above", "info")
        
        # Auto greet
        self.auto_greet()
    
    def _append_output_safe(self, text, msg_type="normal"):
        """Internal method - only call from main thread"""
        try:
            self.output_text.config(state="normal")
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            colors = {
                "normal": "#00ff41",
                "system": "#00bfff", 
                "success": "#32cd32",
                "error": "#ff4500",
                "warning": "#ffa500",
                "info": "#87ceeb"
            }
            
            formatted_text = f"[{timestamp}] {text}\n"
            
            # Insert and color the text
            start_pos = self.output_text.index(tk.END)
            self.output_text.insert(tk.END, formatted_text)
            end_pos = self.output_text.index(tk.END)
            
            tag_name = f"{msg_type}_{timestamp.replace(':', '_')}"
            self.output_text.tag_add(tag_name, start_pos, end_pos)
            self.output_text.tag_config(tag_name, foreground=colors.get(msg_type, "#00ff41"))
            
            self.output_text.config(state="disabled")
            self.output_text.see(tk.END)
            
            # Force update
            self.root.update_idletasks()
        except Exception as e:
            print(f"Error in _append_output_safe: {e}")
    
    def _update_status_safe(self, status):
        """Internal method - only call from main thread"""
        try:
            self.status_label.config(text=status)
            self.root.update_idletasks()
        except Exception as e:
            print(f"Error in _update_status_safe: {e}")
    
    def _speak_safe(self, text):
        """Internal method - only call from main thread"""
        if self.modules.get('voice') and self.engine:
            try:
                # Run TTS in separate thread to avoid blocking
                def speak_worker():
                    self.engine.say(text)
                    self.engine.runAndWait()
                
                threading.Thread(target=speak_worker, daemon=True).start()
            except Exception as e:
                print(f"TTS Error: {e}")
    
    # Legacy methods for backward compatibility - now thread-safe
    def append_output(self, text, msg_type="normal"):
        """Thread-safe wrapper for output"""
        self.thread_safe_output(text, msg_type)
    
    def update_status(self, status):
        """Thread-safe wrapper for status"""
        self.thread_safe_status(status)
    
    def speak(self, text):
        """Thread-safe wrapper for TTS"""
        self.thread_safe_speak(text)
    
    def auto_greet(self):
        """Initial greeting"""
        def greet():
            try:
                hour = datetime.now().hour
                if 0 <= hour < 12:
                    greeting = "Good Morning!"
                elif 12 <= hour < 18:
                    greeting = "Good Afternoon!" 
                else:
                    greeting = "Good Evening!"
                
                full_greeting = f"{greeting} I am HackSpeak, your cybersecurity assistant."
                self.thread_safe_output(full_greeting, "system")
                self.thread_safe_speak(full_greeting)
            except Exception as e:
                print(f"Auto greet error: {e}")
        
        threading.Thread(target=greet, daemon=True).start()
    
    def toggle_voice(self):
        """Toggle voice listening"""
        if not self.modules.get('voice'):
            self.thread_safe_output("Voice recognition not available", "error")
            return
            
        if not self.is_listening:
            self.start_listening()
        else:
            self.stop_listening()
    
    def start_listening(self):
        """Start voice listening"""
        if not self.recognizer:
            self.thread_safe_output("Voice recognizer not initialized", "error")
            return
            
        self.is_listening = True
        self.thread_safe_button_update(self.voice_btn, None, "Stop Listening", "#f44336")
        self.thread_safe_status("Listening...")
        self.thread_safe_output("Voice listening started", "success")
        
        def listen_loop():
            try:
                import speech_recognition as sr
                with sr.Microphone() as source:
                    self.recognizer.adjust_for_ambient_noise(source, duration=1)
                    
                while self.is_listening:
                    try:
                        with sr.Microphone() as source:
                            self.thread_safe_output("Listening for command...", "info")
                            audio = self.recognizer.listen(source, timeout=3, phrase_time_limit=8)
                        
                        query = self.recognizer.recognize_google(audio, language='en-in')
                        self.thread_safe_output(f"You said: {query}", "normal")
                        # Handle command in separate thread
                        threading.Thread(target=self.handle_command, args=(query,), daemon=True).start()
                        
                    except sr.WaitTimeoutError:
                        if self.is_listening:
                            self.thread_safe_output("Timeout - no speech detected", "warning")
                    except sr.UnknownValueError:
                        if self.is_listening:
                            self.thread_safe_output("Could not understand audio", "warning")
                    except Exception as e:
                        if self.is_listening:
                            self.thread_safe_output(f"Voice error: {str(e)}", "error")
                            break
            except Exception as e:
                self.thread_safe_output(f"Listen loop error: {str(e)}", "error")
        
        threading.Thread(target=listen_loop, daemon=True).start()
    
    def stop_listening(self):
        """Stop voice listening"""
        self.is_listening = False
        self.thread_safe_button_update(self.voice_btn, None, "Start Listening", "#4CAF50")
        self.thread_safe_status("Ready")
        self.thread_safe_output("Voice listening stopped", "info")
    
    def handle_text_input(self, event=None):
        """Handle text input"""
        query = self.input_entry.get().strip()
        if query:
            self.input_entry.delete(0, tk.END)
            self.thread_safe_output(f"Text input: {query}", "normal")
            threading.Thread(target=self.handle_command, args=(query,), daemon=True).start()
    
    def handle_command(self, query):
        """Process commands"""
        q = query.lower().strip()
        
        try:
            if any(word in q for word in ['url', 'phishing', 'check']):
                self.check_url()
            elif any(word in q for word in ['wifi', 'scan wifi', 'network']):
                self.wifi_scan()
            elif any(word in q for word in ['port', 'scan port', 'nmap']):
                self.port_scan()
            elif any(word in q for word in ['metadata', 'clean']):
                self.clean_metadata()
            elif any(word in q for word in ['privacy', 'vpn']):
                self.privacy_mode()
            elif any(word in q for word in ['arp', 'spoofing']):
                self.arp_detection()
            elif any(word in q for word in ['ai', 'ask', 'question']):
                self.ask_ai()
            elif any(word in q for word in ['exit', 'quit', 'stop']):
                self.exit_app()
            else:
                # Try AI response
                if self.modules.get('gemini_ai'):
                    try:
                        response = self.modules['gemini_ai'].ask_ai(q)
                        self.thread_safe_output(f"AI: {response}", "success")
                        self.thread_safe_speak(response)
                    except Exception as e:
                        self.thread_safe_output(f"AI service error: {str(e)}", "error")
                else:
                    self.thread_safe_output("Command not recognized. Try using the buttons.", "warning")
                    
        except Exception as e:
            self.thread_safe_output(f"Command error: {str(e)}", "error")
    
    def check_url(self):
        """Check URL for phishing"""
        def worker():
            try:
                # Use root.after to safely show dialog from thread
                self.root.after(0, lambda: self._check_url_dialog())
            except Exception as e:
                self.thread_safe_output(f"URL check initialization error: {str(e)}", "error")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _check_url_dialog(self):
        """Show URL dialog - must run in main thread"""
        url = simpledialog.askstring("URL Check", "Enter URL to check:")
        if not url:
            return
            
        def url_check_worker():
            self.thread_safe_output(f"Checking URL: {url}", "info")
            self.thread_safe_status("Checking URL...")
            
            if self.modules.get('phishing_detector'):
                try:
                    result = self.modules['phishing_detector'].check_url_phishing(url)
                    self.thread_safe_output(result, "success")
                    self.thread_safe_speak(result)
                except Exception as e:
                    self.thread_safe_output(f"URL check failed: {str(e)}", "error")
            else:
                # Fallback basic check
                if any(word in url.lower() for word in ['bit.ly', 'tinyurl', 'suspicious']):
                    result = "Warning: This URL might be suspicious (basic check)"
                    self.thread_safe_output(result, "warning")
                else:
                    result = "URL appears normal (basic check - install full module for detailed scan)"
                    self.thread_safe_output(result, "info")
                    
            self.thread_safe_status("Ready")
        
        threading.Thread(target=url_check_worker, daemon=True).start()
    
    def wifi_scan(self):
        """Scan WiFi networks"""
        def worker():
            self.thread_safe_output("Scanning WiFi networks...", "info")
            self.thread_safe_status("Scanning WiFi...")
            self.thread_safe_speak("Scanning WiFi networks")
            
            if self.modules.get('wifi_audit'):
                try:
                    result = self.modules['wifi_audit'].scan_wifi_networks()
                    if result:
                        self.thread_safe_output("WiFi Networks Found:", "success")
                        self.thread_safe_output(result, "normal")
                        self.thread_safe_speak("WiFi scan completed")
                    else:
                        self.thread_safe_output("No networks found", "warning")
                except Exception as e:
                    self.thread_safe_output(f"WiFi scan error: {str(e)}", "error")
            else:
                # Fallback using subprocess
                try:
                    result = subprocess.check_output(['netsh', 'wlan', 'show', 'networks'], 
                                                   shell=True, text=True, timeout=10)
                    self.thread_safe_output("WiFi Networks (fallback method):", "success")
                    self.thread_safe_output(result, "normal")
                    self.thread_safe_speak("WiFi scan completed")
                except Exception as e:
                    self.thread_safe_output(f"WiFi scan failed: {str(e)}", "error")
                    
            self.thread_safe_status("Ready")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def port_scan(self):
        """Port scanning"""
        def worker():
            try:
                self.root.after(0, lambda: self._port_scan_dialog())
            except Exception as e:
                self.thread_safe_output(f"Port scan initialization error: {str(e)}", "error")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _port_scan_dialog(self):
        """Show port scan dialog - must run in main thread"""
        ip = simpledialog.askstring("Port Scan", "Enter IP address:")
        if not ip:
            return
            
        def port_scan_worker():
            self.thread_safe_output(f"Scanning ports on {ip}...", "info")
            self.thread_safe_status("Port scanning...")
            self.thread_safe_speak("Starting port scan")
            
            if self.modules.get('port_scanner'):
                try:
                    result = self.modules['port_scanner'].run_nmap_scan(ip)
                    if result:
                        self.thread_safe_output(f"Open ports found on {ip}:", "success")
                        for port, service in result.items():
                            self.thread_safe_output(f"Port {port}: {service}", "normal")
                        self.thread_safe_speak(f"Found {len(result)} open ports")
                    else:
                        self.thread_safe_output("No open ports found", "warning")
                except Exception as e:
                    self.thread_safe_output(f"Port scan error: {str(e)}", "error")
            else:
                # Basic ping test as fallback
                try:
                    result = subprocess.run(['ping', '-n', '1', ip], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.thread_safe_output(f"Host {ip} is reachable (basic check)", "success")
                    else:
                        self.thread_safe_output(f"Host {ip} is not reachable", "warning")
                except:
                    self.thread_safe_output("Network test failed", "error")
                    
            self.thread_safe_status("Ready")
        
        threading.Thread(target=port_scan_worker, daemon=True).start()
    
    def clean_metadata(self):
        """Clean image metadata"""
        def worker():
            try:
                self.root.after(0, lambda: self._clean_metadata_dialog())
            except Exception as e:
                self.thread_safe_output(f"Metadata cleaning initialization error: {str(e)}", "error")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _clean_metadata_dialog(self):
        """Show file dialog - must run in main thread"""
        file_path = filedialog.askopenfilename(
            title="Select image to clean",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.tiff"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        def clean_worker():
            self.thread_safe_output(f"Cleaning metadata from: {os.path.basename(file_path)}", "info")
            self.thread_safe_status("Cleaning metadata...")
            
            if self.modules.get('metadata_cleaner'):
                try:
                    self.modules['metadata_cleaner'].remove_metadata(file_path)
                    self.thread_safe_output("Metadata cleaned successfully!", "success")
                    self.thread_safe_speak("Metadata cleaned successfully")
                except Exception as e:
                    self.thread_safe_output(f"Metadata cleaning failed: {str(e)}", "error")
            else:
                # Fallback using PIL
                try:
                    from PIL import Image
                    img = Image.open(file_path)
                    data = list(img.getdata())
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)
                    
                    name, ext = os.path.splitext(file_path)
                    output_path = f"{name}_cleaned{ext}"
                    clean_img.save(output_path)
                    
                    self.thread_safe_output(f"Metadata cleaned! Saved as: {os.path.basename(output_path)}", "success")
                    self.thread_safe_speak("Metadata cleaned successfully")
                except Exception as e:
                    self.thread_safe_output(f"Fallback metadata cleaning failed: {str(e)}", "error")
                    
            self.thread_safe_status("Ready")
        
        threading.Thread(target=clean_worker, daemon=True).start()
    
    def privacy_mode(self):
        """Privacy mode"""
        def worker():
            self.thread_safe_output("Activating privacy mode...", "info")
            self.thread_safe_speak("Activating privacy mode")
            
            if self.modules.get('privacy_mode'):
                try:
                    self.modules['privacy_mode'].start_privacy_mode()
                    self.thread_safe_output("Privacy mode activated!", "success")
                except Exception as e:
                    self.thread_safe_output(f"Privacy mode error: {str(e)}", "error")
            else:
                self.thread_safe_output("Privacy mode: VPN connection simulated", "info")
                self.thread_safe_output("Note: Install privacy_mode module for full functionality", "warning")
                
        threading.Thread(target=worker, daemon=True).start()
    
    # ----------------------------
    # Integrated non-admin detector
    # ----------------------------
    def _run_cmd(self, args, timeout=6):
        try:
            completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
            return completed.stdout + completed.stderr
        except Exception:
            return ""

    def _parse_arp_output(self, arp_text):
        table = {}
        for line in arp_text.splitlines():
            m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            m_mac = re.search(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
            if m_ip and m_mac:
                ip = m_ip.group(1)
                mac = m_mac.group(1).replace("-", ":").lower()
                table[ip] = mac
        return table

    def _get_gateway_from_ipconfig(self):
        out = self._run_cmd(["ipconfig", "/all"])
        m = re.search(r"Default Gateway[^\r\n:]*:\s*([\d\.]+)", out)
        if m:
            return m.group(1)
        return None

    def _get_dns_servers(self):
        out = self._run_cmd(["ipconfig", "/all"])
        dns = re.findall(r"DNS Servers[^\r\n:]*:\s*([\d\.]+)", out)
        return dns

    def _get_public_ip(self):
        # best-effort public IP without adding requests dependency
        try:
            import urllib.request, urllib.error
            with urllib.request.urlopen("https://api.ipify.org", timeout=6) as resp:
                return resp.read().decode().strip()
        except Exception:
            return None

    def _take_detector_baseline(self):
        arp = self._parse_arp_output(self._run_cmd(["arp", "-a"]))
        self.detector_baseline = arp
        self.detector_baseline_dns = self._get_dns_servers() or []
        self.detector_baseline_ip = self._get_public_ip()
        self.detector_gateway = self.detector_gateway or self._get_gateway_from_ipconfig()

    def _detector_check_once(self):
        alerts = []
        curr_arp = self._parse_arp_output(self._run_cmd(["arp", "-a"]))
        # watch gateway and baseline keys
        keys = set(self.detector_baseline.keys()) | ({self.detector_gateway} if self.detector_gateway else set())
        for ip in keys:
            if not ip:
                continue
            base_mac = self.detector_baseline.get(ip)
            curr_mac = curr_arp.get(ip)
            if base_mac and curr_mac and base_mac != curr_mac:
                alerts.append(f"MAC changed for {ip}: was {base_mac}, now {curr_mac}")
            if not base_mac and curr_mac:
                alerts.append(f"New ARP entry: {ip} -> {curr_mac}")

        # DNS check
        curr_dns = self._get_dns_servers()
        if curr_dns != self.detector_baseline_dns:
            alerts.append(f"DNS servers changed: was {self.detector_baseline_dns}, now {curr_dns}")

        # Public IP check (best-effort)
        curr_ip = self._get_public_ip()
        if curr_ip and self.detector_baseline_ip and curr_ip != self.detector_baseline_ip:
            alerts.append(f"Public IP changed: was {self.detector_baseline_ip}, now {curr_ip}")

        return alerts

    def _detector_loop(self, poll_interval):
        """Runs in background thread until stop_event is set"""
        self.thread_safe_output("Light detector baseline capture in progress...", "info")
        try:
            self._take_detector_baseline()
            self.thread_safe_output(f"Baseline captured. Gateway: {self.detector_gateway} | Public IP: {self.detector_baseline_ip}", "success")
        except Exception as e:
            self.thread_safe_output(f"Failed to capture baseline: {e}", "warning")

        while not self.detector_stop_event.is_set():
            try:
                alerts = self._detector_check_once()
                if alerts:
                    self.thread_safe_output("⚠️ Network Alert:", "warning")
                    for a in alerts:
                        self.thread_safe_output(f" - {a}", "warning")
                    # do not auto-update baseline — keep manual control
                else:
                    self.thread_safe_output("✔ Network looks normal.", "info")
            except Exception as e:
                self.thread_safe_output(f"Detector error: {e}", "error")

            # Sleep but wake earlier if stop requested
            for _ in range(int(poll_interval)):
                if self.detector_stop_event.is_set():
                    break
                time.sleep(1)

        self.thread_safe_output("Light detector stopped.", "info")

    def arp_detection(self):
        """Toggle the integrated non-admin ARP/network detector"""
        if self.detector_running:
            # Stop it
            self.thread_safe_output("Stopping ARP detection...", "info")
            self.detector_stop_event.set()
            if self.detector_thread:
                self.detector_thread.join(timeout=3)
            self.detector_running = False
            # update button state if present
            try:
                if hasattr(self, 'arp_button') and self.arp_button:
                    self.thread_safe_button_update(self.arp_button, None, "ARP Detection", "#F44336")
            except Exception:
                pass
            self.thread_safe_status("Ready")
            return

        # Start detector
        self.detector_stop_event.clear()
        self.detector_thread = threading.Thread(target=self._detector_loop, args=(self.detector_poll_interval,), daemon=True)
        self.detector_thread.start()
        self.detector_running = True
        try:
            if hasattr(self, 'arp_button') and self.arp_button:
                self.thread_safe_button_update(self.arp_button, None, "Stop ARP", "#f44336")
        except Exception:
            pass
        self.thread_safe_output("ARP detection started (non-admin mode). Monitoring gateway, DNS, and public IP.", "success")
        self.thread_safe_status("ARP Detection Active")
    
    def ask_ai(self):
        """Ask AI"""
        def worker():
            try:
                self.root.after(0, lambda: self._ask_ai_dialog())
            except Exception as e:
                self.thread_safe_output(f"AI question initialization error: {str(e)}", "error")
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _ask_ai_dialog(self):
        """Show AI question dialog - must run in main thread"""
        question = simpledialog.askstring("Ask AI", "What's your question?")
        if not question:
            return
            
        def ai_worker():
            self.thread_safe_output(f"Question: {question}", "info")
            self.thread_safe_status("Processing with AI...")
            
            if self.modules.get('gemini_ai'):
                try:
                    response = self.modules['gemini_ai'].ask_ai(question)
                    self.thread_safe_output(f"AI Response: {response}", "success")
                    self.thread_safe_speak(response)
                except Exception as e:
                    self.thread_safe_output(f"AI error: {str(e)}", "error")
            else:
                # Simple fallback responses
                responses = {
                    'hello': 'Hello! I am HackSpeak, your cybersecurity assistant.',
                    'time': f'Current time is {datetime.now().strftime("%H:%M:%S")}',
                    'date': f'Today is {datetime.now().strftime("%Y-%m-%d")}',
                    'help': 'I can help with WiFi scanning, URL checking, port scanning, and more!',
                }
                
                response = None
                for key, value in responses.items():
                    if key in question.lower():
                        response = value
                        break
                
                if not response:
                    response = "I'm sorry, I need the AI module to answer that question properly."
                    
                self.thread_safe_output(f"Basic Response: {response}", "info")
                self.thread_safe_speak(response)
                
            self.thread_safe_status("Ready")
        
        threading.Thread(target=ai_worker, daemon=True).start()
    
    def exit_app(self):
        """Exit application"""
        self.stop_listening()
        # Stop detector if running
        try:
            if self.detector_running:
                self.detector_stop_event.set()
                if self.detector_thread:
                    self.detector_thread.join(timeout=2)
        except Exception:
            pass
        self.thread_safe_output("Shutting down HackSpeak Assistant...", "system")
        self.thread_safe_speak("Goodbye!")
        self.root.after(1000, self.root.quit)
    
    def run(self):
        """Start the GUI"""
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
            self.root.mainloop()
        except KeyboardInterrupt:
            self.exit_app()


def main():
    """Main function"""
    try:
        app = HackSpeakGUI()
        app.run()
    except Exception as e:
        print(f"Application error: {e}")
        try:
            messagebox.showerror("Error", f"Failed to start HackSpeak: {str(e)}")
        except:
            print("Failed to show error dialog")


if __name__ == "__main__":
    main()
