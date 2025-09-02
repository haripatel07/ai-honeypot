import random
import datetime
import pandas as pd

# --- Building Blocks for Log Generation ---

HOSTNAMES = ['corp-server-01', 'web-prod-03', 'db-main-01', 'api-gateway-1']
PROCESSES = ['sshd', 'cron', 'kernel', 'systemd', 'apache2', 'mysql']
USERS = ['root', 'admin', 'ubuntu', 'guest', 'testuser']

# Templates for "normal" system messages
MESSAGE_TEMPLATES = [
    "Accepted password for {user} from 10.0.{ip_part}.{ip_part} port {port}",
    "session opened for user {user} by (uid=0)",
    "CRON[{pid}]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)",
    "kernel: a new usb device found, idVendor=1d6b, idProduct=0002",
    "systemd: Started Session {session_id} of user {user}.",
    "apache2: AH00558: apache2: Could not reliably determine the server's fully qualified domain name",
    "mysql: [Note] Server socket created on IP: '127.0.0.1'."
]

def generate_log_line():
    """Generates a single, realistic-looking syslog line."""
    
    # Generate a realistic timestamp
    now = datetime.datetime.now()
    timestamp = now.strftime('%b %d %H:%M:%S')
    
    hostname = random.choice(HOSTNAMES)
    process = random.choice(PROCESSES)
    pid = random.randint(1000, 9999)
    user = random.choice(USERS)
    
    # Populate the message template with random data
    message = random.choice(MESSAGE_TEMPLATES).format(
        user=user,
        ip_part=random.randint(1, 254),
        port=random.randint(1024, 65535),
        pid=pid,
        session_id=random.randint(1, 100)
    )
    
    return f"{timestamp} {hostname} {process}[{pid}]: {message}"

def main(num_lines=10000):
    """Main function to generate a log file."""
    
    log_file_path = 'data/normal_traffic.log'
    print(f"Generating {num_lines} log entries for the honeypot...")
    
    with open(log_file_path, 'w') as f:
        for _ in range(num_lines):
            f.write(generate_log_line() + '\n')
            
    print(f"Successfully generated log file at '{log_file_path}'")
    
if __name__ == "__main__":
    main()