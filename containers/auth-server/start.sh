#!/bin/bash

# Start SSH server
service ssh start

# Wait for SSH to be ready
sleep 2

# Start log monitoring in background
/usr/local/bin/log_auth.sh &

# Keep container running
tail -f /dev/null
