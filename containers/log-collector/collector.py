from flask import Flask, request, jsonify
import json
import os
from datetime import datetime
import requests

app = Flask(__name__)
LOG_DIR = "/logs"
UNIFIED_LOG = f"{LOG_DIR}/unified.log"

os.makedirs(LOG_DIR, exist_ok=True)

@app.route('/ingest', methods=['POST'])
def ingest_log():
    try:
        data = request.json
        
        unified_log = {
            "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
            "source": data.get("source", "unknown"),
            "event": data.get("event", "unknown"),
            "user": data.get("user"),
            "ip": data.get("ip"),
            "details": data.get("details", {})
        }
        
        with open(UNIFIED_LOG, 'a') as f:
            f.write(json.dumps(unified_log) + '\n')
        
        try:
            requests.post('http://soc-detection:5001/analyze', json=unified_log, timeout=2)
        except:
            pass
        
        return jsonify({"status": "ingested"}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    print("🔍 Log Collector starting on port 5000...")
    app.run(host='0.0.0.0', port=5000)
