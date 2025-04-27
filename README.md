To install and run `netscan.py` on a Debian Linux system (& via SSH), follow these steps:

### Step 1: Install Required Dependencies

First, ensure you have Python and pip installed. If not, you can install them using:

```bash
sudo apt update
sudo apt install python3 python3-pip
```

### Step 2: Clone or Copy the Script

If you have the script in a repository, clone it using Git:

```bash
git clone https://github.com/JayMan6336/net_scan/netscan.git
cd netscan
```

Or if you have the script as a file, copy it to your server.

### Step 3: Install Python Packages

Use `pip` to install the necessary packages. First, generate a `requirements.txt` file with the current environment's dependencies:

```bash
pip freeze > requirements.txt
```

Then, install these dependencies:

```bash
pip install -r requirements.txt
```

### Step 4: Configure Email Notifications (Optional)

If you want email notifications, configure Flask-Mail in your script or create a configuration file.

### Step 5: Run the Script

Run the script using Python:

```bash
python3 netscan.py
```

### Step 6: Access the Web Interface

Open a web browser and navigate to `http://<your-server-ip>`. You should see the login page if user authentication is implemented.

### Additional Tips

- **Security**: Ensure your server is secured, especially if exposed to the internet.
- **Logging**: Implement logging to track script activities and detect issues.
- **Updates**: Regularly update dependencies to patch vulnerabilities.

This setup provides a basic framework for network monitoring with Flask. Enhancements can include more sophisticated scanning, better visualization, and additional security features as needed.
