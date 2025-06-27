from flask import Flask, request, redirect, url_for, render_template
import nmap
import netifaces
import time
import json
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = '64charsecretkey'
# Flask-Mail configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='youremail@gmail.com',
    MAIL_PASSWORD='apppassword',
    MAIL_DEFAULT_SENDER='youremail@gmail.com'
)

mail = Mail(app)  # Initialize the mail object
# Configuration
NETWORK_RANGE = "192.168.1.0/24"  # Adjust to your LAN subnet
KNOWN_DEVICES_FILE = "known_devices.json"
CHECK_INTERVAL = 900  # Check every 15 minutes
VULNERABLE_PORTS = [21,22,23,25,53,80,110,135,139,445,143,161,162,389,443,1433,1434,3306,3389,1521,5900,8080,27017,8443]  # FTP, Telnet, HTTP, RDP, etc.
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

def scan_network():
    nm = nmap.PortScanner()
    threats = []
    known_devices = load_known_devices()
    current_devices = {}

    try:
        # Initial scan for devices
        nm.scan(hosts="192.168.1.0/24", arguments="-sn")
        print("All hosts scanned:", nm.all_hosts())
        print("Initial scan result keys:", nm._scan_result["scan"].keys())

        for host in nm.all_hosts():
            try:
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

                    # Port scan for each host (use a new PortScanner)
                    port_scanner = nmap.PortScanner()
                    port_scanner.scan(hosts=host, arguments=f"-sV -O -p {','.join(map(str, VULNERABLE_PORTS))} --open")
                    print("Port scan result keys for", host, ":", port_scanner._scan_result["scan"].keys())
                    for proto in port_scanner[host].all_protocols():
                        ports = port_scanner[host][proto].keys()
                        for port in ports:
                            threats.append({
                                "host": host,
                                "mac": mac,
                                "hostname": hostname,
                                "issue": f"Open vulnerable port {port} ({port_scanner[host][proto][port]['name']})"
                            })
            except KeyError:
                print(f"Host {host} is in all_hosts() but not in scan results!")
                continue

    except Exception as e:
        print(f"Scan failed: {e}")
        return [{"host": "Error", "mac": "N/A", "hostname": "N/A", "issue": f"Scan failed: {e}"}]

    save_known_devices(current_devices)
    print("Current devices:", current_devices)
    print("Threats found:", threats)
    return threats

# Example usage (in your main script or route):
# threats = scan_network()

# Send notification email
def send_notification(threat):
    msg = Message("Network Threat Detected", sender="youremail@gmail.com", recipients=["recipient@email.com"])
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
