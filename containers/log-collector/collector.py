from flask import Flask, request, jsonify
import json
import os
from datetime import datetime
import requests

app = Flask(__name__)
LOG_DIR = "/logs"
UNIFIED_LOG = f"{LOG_DIR}/unified.log"

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

@app.route('/ingest', methods=['POST'])
def ingest_log():
    """Receive and normalize logs from any source"""
    try:
        data = request.json
        
        # Normalize log format
        unified_log = {
            "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
            "source": data.get("source", "unknown"),
            "event": data.get("event", "unknown"),
            "user": data.get("user"),
            "ip": data.get("ip"),
            "details": data.get("details", {}),
            "reputation": data.get("reputation"),
            "confidence": data.get("confidence")
        }
        
        # Write to unified log file
        with open(UNIFIED_LOG, 'a') as f:
            f.write(json.dumps(unified_log) + '\n')
        
        print(f"[LOG INGESTED] {unified_log['event']} from {unified_log['source']}")
        
        # Forward to detection engine
        try:
            requests.post(
                'http://soc-detection:5001/analyze',
                json=unified_log,
                timeout=2
            )
        except Exception as e:
            print(f"Failed to forward to detection engine: {e}")
        
        return jsonify({"status": "ingested", "log_id": unified_log["timestamp"]}), 200
        
    except Exception as e:
        print(f"Error ingesting log: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "service": "log-collector"}), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    """Retrieve recent logs"""
    try:
        if not os.path.exists(UNIFIED_LOG):
            return jsonify({"logs": []}), 200
            
        with open(UNIFIED_LOG, 'r') as f:
            lines = f.readlines()
            logs = [json.loads(line) for line in lines[-100:]]  # Last 100 logs
        
        return jsonify({"logs": logs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("🔍 Log Collector starting on port 5000...")
    app.run(host='0.0.0.0', port=5000)
