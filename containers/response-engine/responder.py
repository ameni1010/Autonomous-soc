from flask import Flask, request, jsonify
import subprocess
import json
from datetime import datetime
import os

app = Flask(__name__)
ACTIONS_LOG = "/logs/actions.log"

# Blocked IPs storage
blocked_ips = set()

@app.route('/execute', methods=['POST'])
def execute_action():
    """Execute security response actions"""
    data = request.json
    action = data.get('action')
    ip = data.get('ip', 'unknown')
    
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "target_ip": ip,
        "status": "failed",
        "message": ""
    }
    
    try:
        if action == 'block_ip':
            # Simulate IP blocking (actual iptables requires proper privileges)
            blocked_ips.add(ip)
            result['status'] = 'success'
            result['message'] = f'IP {ip} blocked successfully'
            print(f"🛡️  BLOCKED IP: {ip}")
            
        elif action == 'monitor':
            result['status'] = 'success'
            result['message'] = f'IP {ip} added to monitoring watchlist'
            print(f"👁️  MONITORING: {ip}")
            
        elif action == 'escalate':
            result['status'] = 'success'
            result['message'] = 'Incident escalated to SOC manager'
            print(f"⬆️  ESCALATED: Incident involving {ip}")
            
        elif action == 'dismiss':
            result['status'] = 'success'
            result['message'] = 'Incident marked as false positive'
            print(f"✓ DISMISSED: Alert for {ip}")
            
        else:
            result['message'] = f'Unknown action: {action}'
            print(f"❌ UNKNOWN ACTION: {action}")
    
    except Exception as e:
        result['error'] = str(e)
        print(f"❌ ERROR: {e}")
    
    # Log all actions
    try:
        os.makedirs(os.path.dirname(ACTIONS_LOG), exist_ok=True)
        with open(ACTIONS_LOG, 'a') as f:
            f.write(json.dumps(result) + '\n')
    except Exception as e:
        print(f"Failed to log action: {e}")
    
    return jsonify(result), 200

@app.route('/status', methods=['GET'])
def get_status():
    """Get current response engine status"""
    return jsonify({
        "blocked_ips": list(blocked_ips),
        "blocked_count": len(blocked_ips)
    }), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "response-engine"
    }), 200

if __name__ == '__main__':
    print("🛡️  Response Engine starting on port 5003...")
    app.run(host='0.0.0.0', port=5003)
