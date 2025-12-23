#!/bin/bash

# Create auth log file
touch /var/log/auth.log
chmod 644 /var/log/auth.log

# Start rsyslog to capture SSH logs
echo "Starting rsyslog..."
rsyslogd

# Configure SSH to log everything
echo "Starting SSH server..."
/usr/sbin/sshd -D -e &
SSHD_PID=$!

# Wait for SSH to start
sleep 2

# Function to monitor SSH directly from its process output
monitor_ssh_logs() {
    LOG_COLLECTOR="http://soc-logs:5000/ingest"
    
    # Monitor btmp for failed logins (binary format)
    while true; do
        # Use lastb to read failed login attempts from btmp
        lastb -F -i -w | tail -n 50 | while read -r line; do
            # Skip header line
            if echo "$line" | grep -q "begins"; then
                continue
            fi
            
            # Parse lastb output: username tty source timestamp
            USER=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line" | awk '{print $3}')
            
            # Skip empty or header lines
            if [ -z "$USER" ] || [ "$USER" = "btmp" ] || [ "$USER" = "wtmp" ]; then
                continue
            fi
            
            # Send to log collector
            if [ ! -z "$IP" ] && [ "$IP" != "0.0.0.0" ]; then
                echo "[AUTH] Failed login detected: $USER from $IP"
                curl -s -X POST "$LOG_COLLECTOR" \
                  -H "Content-Type: application/json" \
                  -d "{
                    \"timestamp\": \"$(date -Iseconds)\",
                    \"source\": \"auth-server\",
                    \"event\": \"login_failed\",
                    \"user\": \"$USER\",
                    \"ip\": \"$IP\"
                  }" &
            fi
        done
        
        sleep 2
    done
}

# Start monitoring in background
monitor_ssh_logs &

echo "Auth server ready - monitoring btmp for failed logins"

# Keep container running
wait $SSHD_PID
