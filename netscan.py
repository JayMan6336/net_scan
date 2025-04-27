from flask import Flask, request, redirect, url_for, render_template
import nmap
import netifaces
import time
import json
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configuration
NETWORK_RANGE = "192.168.1.0/24"  # Adjust to your LAN subnet
KNOWN_DEVICES_FILE = "known_devices.json"
CHECK_INTERVAL = 300  # Check every 5 minutes
VULNERABLE_PORTS = [21, 23, 80, 8080, 3389]  # FTP, Telnet, HTTP, RDP, etc.
WHITELISTED_DEVICES_FILE = "whitelisted_devices.json"

# Load or initialize known devices
def load_known_devices():
    if os.path.exists(KNOWN_DEVICES_FILE):
        with open(KNOWN_DEVICES_FILE, "r") as f:
            return json.load(f)
    return {}

# Save known devices
def save_known_devices(devices):
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=4)

# Load or initialize whitelisted devices
def load_whitelisted_devices():
    if os.path.exists(WHITELISTED_DEVICES_FILE):
        with open(WHITELISTED_DEVICES_FILE, "r") as f:
            return json.load(f)
    return {}

# Save whitelisted devices
def save_whitelisted_devices(devices):
    with open(WHITELISTED_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=4)

# Scan network with Nmap
def scan_network():
    nm = nmap.PortScanner()
    threats = []
    known_devices = load_known_devices()
    whitelisted_devices = load_whitelisted_devices()
    
    try:
        nm.scan(hosts=get_network_range(), arguments="-sn")  # Ping scan for devices
        current_devices = {}
        
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                mac = nm[host]["addresses"].get("mac", "Unknown")
                hostname = nm[host].hostname() or "Unknown"
                current_devices[host] = {"mac": mac, "hostname": hostname}
                
                # Check for new devices
                if host not in known_devices:
                    threats.append({
                        "host": host,
                        "mac": mac,
                        "hostname": hostname,
                        "issue": "New device detected"
                    })
                
                # Scan for vulnerable ports
                nm.scan(hosts=host, arguments=f"-sV -O -p {','.join(map(str, VULNERABLE_PORTS))} --open")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        threats.append({
                            "host": host,
                            "mac": mac,
                            "hostname": hostname,
                            "issue": f"Open vulnerable port {port} ({nm[host][proto][port]['name']})"
                        })
        
        # Update known devices
        save_known_devices(current_devices)
        return threats
    except Exception as e:
        return [{"host": "Error", "mac": "N/A", "hostname": "N/A", "issue": f"Scan failed: {str(e)}"}]

# Send notification email
def send_notification(threat):
    msg = Message("Network Threat Detected", sender="your-email@example.com", recipients=["admin@example.com"])
    msg.body = f"Host: {threat['host']}\nMAC: {threat['mac']}\nHostname: {threat['hostname']}\nIssue: {threat['issue']}"
    mail.send(msg)

# User authentication setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = {'admin': {'password': 'admin123'}}

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard route
@app.route('/')
@login_required
def dashboard():
    threats = scan_network()
    for threat in threats:
        send_notification(threat)
    return render_template('dashboard.html', threats=threats)

# Whitelist route
@app.route('/whitelist', methods=['GET', 'POST'])
@login_required
def whitelist():
    if request.method == 'POST':
        mac = request.form['mac']
        whitelisted_devices = load_whitelisted_devices()
        whitelisted_devices[mac] = True
        save_whitelisted_devices(whitelisted_devices)
        return redirect(url_for('dashboard'))
    return render_template('whitelist.html')

if __name__ == '__main__':
    app.run(debug=True)
