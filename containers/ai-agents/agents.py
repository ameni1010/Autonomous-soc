from flask import Flask, request, jsonify
import os
import json
from datetime import datetime, timezone
import random

app = Flask(__name__)

DECISIONS_LOG = "/logs/agent_decisions.log"

def log_decision(agent_name, input_data, output_data):
    """Log agent decisions for dashboard"""
    try:
        os.makedirs("/logs", exist_ok=True)
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent_name,
            "input": input_data,
            "output": output_data
        }
        
        with open(DECISIONS_LOG, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        print(f"[LOG] Decision logged for {agent_name}")
            
    except Exception as e:
        print(f"Failed to log decision: {e}")

@app.route('/triage', methods=['POST'])
def triage_agent():
    """SOC Tier 1 - Initial Alert Triage (MOCK)"""
    try:
        alert = request.json
        
        alert_type = alert.get('alert_type', '')
        confidence = alert.get('confidence', 0.5)
        
        if 'Brute' in alert_type or confidence > 0.85:
            severity = "high"
            status = "valid_alert"
            reason = "Multiple failed authentication attempts detected from single source, indicating potential brute force attack pattern."
        elif confidence > 0.7:
            severity = "medium"
            status = "valid_alert"
            reason = "Suspicious activity pattern detected that warrants further investigation."
        else:
            severity = "low"
            status = "valid_alert"
            reason = "Anomalous behavior identified, monitoring for escalation."
        
        result = {
            "status": status,
            "severity": severity,
            "reason": reason
        }
        
        print(f"[TRIAGE] {alert_type}: {status} - {severity}")
        log_decision("Triage Agent", alert, result)
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"[ERROR] Triage failed: {e}")
        return jsonify({"status": "error", "severity": "medium", "reason": "Triage error"}), 200

@app.route('/investigate', methods=['POST'])
def investigation_agent():
    """SOC Tier 2 - Deep Investigation (MOCK)"""
    try:
        data = request.json
        
        alert = data.get('alert', {})
        triage = data.get('triage', {})
        
        # Handle JSON strings from n8n
        if isinstance(alert, str):
            try:
                alert = json.loads(alert)
                print("[DEBUG] Parsed alert from JSON string")
            except:
                alert = {}
        
        if isinstance(triage, str):
            try:
                triage = json.loads(triage)
                print("[DEBUG] Parsed triage from JSON string")
            except:
                triage = {}
        
        if not alert:
            alert = {"alert_type": "Unknown", "ip": "unknown"}
        
        if not triage:
            triage = {"severity": "medium"}
        
        alert_type = alert.get('alert_type', '')
        
        if 'Brute' in alert_type:
            attack_type = "Credential Stuffing / Brute Force Attack"
            attack_chain = [
                "Initial reconnaissance and target identification",
                "Automated credential testing using common passwords",
                "Multiple failed authentication attempts",
                "Possible credential compromise on successful login"
            ]
            indicators = [
                f"Source IP: {alert.get('ip', 'unknown')}",
                f"Failed login count: {alert.get('failed_count', 'N/A')}",
                "Rapid sequential authentication attempts"
            ]
            confidence = 0.92
        elif 'Credential' in alert_type:
            attack_type = "Credential Compromise"
            attack_chain = [
                "Previous failed authentication attempts",
                "Successful login with compromised credentials",
                "Potential lateral movement preparation"
            ]
            indicators = [
                f"Compromised account: {alert.get('user', 'unknown')}",
                f"Source IP: {alert.get('ip', 'unknown')}",
                "Access pattern anomaly detected"
            ]
            confidence = 0.88
        else:
            attack_type = "Suspicious Activity"
            attack_chain = ["Anomalous behavior detected"]
            indicators = [f"Source IP: {alert.get('ip', 'unknown')}"]
            confidence = 0.75
        
        result = {
            "attack_type": attack_type,
            "confidence": confidence,
            "attack_chain": attack_chain,
            "indicators": indicators,
            "analysis": f"Analysis indicates {attack_type.lower()} with {int(confidence*100)}% confidence based on observed patterns."
        }
        
        print(f"[INVESTIGATION] Attack: {attack_type} (confidence: {confidence})")
        log_decision("Investigation Agent", data, result)
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"[ERROR] Investigation failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "attack_type": "Analysis Error",
            "confidence": 0.5,
            "attack_chain": ["Error during analysis"],
            "indicators": ["Investigation failed"],
            "analysis": "An error occurred during investigation"
        }), 200

@app.route('/threat-intel', methods=['POST'])
def threat_intel_agent():
    """Threat Intelligence Enrichment (MOCK)"""
    try:
        data = request.json
        ip = data.get('ip', 'unknown')
        
        is_malicious = ip.endswith('.8') or ip.endswith('.9') or ip.endswith('.3')
        
        threat_data = {
            "ip": ip,
            "reputation": "malicious" if is_malicious else "unknown",
            "risk_score": round(random.uniform(7.5, 9.5), 1) if is_malicious else round(random.uniform(1.0, 3.5), 1),
            "known_campaigns": ["credential_stuffing", "brute_force"] if is_malicious else [],
            "geolocation": "Multiple locations" if is_malicious else "Unknown",
            "last_seen": datetime.now().strftime("%Y-%m-%d") if is_malicious else None
        }
        
        print(f"[THREAT INTEL] IP {ip}: {threat_data['reputation']} (risk: {threat_data['risk_score']})")
        log_decision("Threat Intel Agent", data, threat_data)
        
        return jsonify(threat_data), 200
        
    except Exception as e:
        print(f"[ERROR] Threat intel failed: {e}")
        return jsonify({"ip": "unknown", "reputation": "unknown", "risk_score": 5.0}), 200

@app.route('/decide', methods=['POST'])
def decision_agent():
    """SOC Team Lead - Final Decision (MOCK)"""
    try:
        data = request.json
        
        triage = data.get('triage', {})
        investigation = data.get('investigation', {})
        threat_intel = data.get('threat_intel', {})
        
        # Handle JSON strings
        if isinstance(triage, str):
            try:
                triage = json.loads(triage)
            except:
                triage = {}
        
        if isinstance(investigation, str):
            try:
                investigation = json.loads(investigation)
            except:
                investigation = {}
        
        if isinstance(threat_intel, str):
            try:
                threat_intel = json.loads(threat_intel)
            except:
                threat_intel = {}
        
        severity = triage.get('severity', 'medium')
        confidence = investigation.get('confidence', 0.5)
        reputation = threat_intel.get('reputation', 'unknown')
        risk_score = threat_intel.get('risk_score', 0)
        
        if (severity in ['high', 'critical']) and (confidence > 0.85) and (reputation == 'malicious'):
            decision = "block_ip"
            final_severity = "critical"
            justification = "High-confidence threat detected with malicious IP reputation. Immediate blocking required to prevent further compromise."
            actions = [
                "Block source IP immediately",
                "Reset credentials for affected accounts",
                "Enable MFA for compromised users",
                "Monitor for lateral movement"
            ]
        elif (severity == 'high') or (confidence > 0.8):
            decision = "block_ip"
            final_severity = "high"
            justification = "Significant threat identified with high confidence level. Proactive blocking recommended."
            actions = [
                "Block source IP",
                "Alert security team",
                "Review authentication logs"
            ]
        elif (severity == 'medium') and (risk_score > 5.0):
            decision = "monitor"
            final_severity = "medium"
            justification = "Suspicious activity detected with moderate risk. Enhanced monitoring initiated."
            actions = [
                "Enable enhanced logging",
                "Monitor IP activity closely"
            ]
        else:
            decision = "monitor"
            final_severity = "low"
            justification = "Low-risk anomaly detected. Continuing standard monitoring."
            actions = ["Maintain standard monitoring"]
        
        result = {
            "decision": decision,
            "severity": final_severity,
            "justification": justification,
            "recommended_actions": actions
        }
        
        print(f"[DECISION] Action: {decision} - Severity: {final_severity}")
        log_decision("Decision Agent", data, result)
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"[ERROR] Decision failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "decision": "monitor",
            "severity": "medium",
            "justification": "Error during decision making",
            "recommended_actions": ["Manual review required"]
        }), 200

@app.route('/report', methods=['POST'])
def reporting_agent():
    """Generate Incident Report (MOCK)"""
    try:
        data = request.json
        
        report = f"""# Security Incident Report

## Executive Summary
A security incident was detected and analyzed by the autonomous SOC system.

## Incident Details
- **Detection Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Incident Type**: {data.get('investigation', {}).get('attack_type', 'Security Incident')}
- **Severity**: {data.get('decision', {}).get('severity', 'Unknown').upper()}
- **Confidence**: {int(data.get('investigation', {}).get('confidence', 0) * 100)}%

## Response Actions Taken
{chr(10).join(f"- {action}" for action in data.get('decision', {}).get('recommended_actions', ['Actions pending']))}

## Recommendations
- Implement multi-factor authentication
- Deploy rate limiting on authentication endpoints
- Enhance monitoring for similar attack patterns

---
*Report generated by Autonomous SOC System*
"""
        
        print("[REPORT] Incident report generated")
        log_decision("Reporting Agent", data, {"report": report})
        
        return jsonify({"report": report}), 200
        
    except Exception as e:
        print(f"[ERROR] Report failed: {e}")
        return jsonify({"report": "Error generating report"}), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "ai-agents-mock",
        "mode": "simulation"
    }), 200

if __name__ == '__main__':
    print("🤖 AI Agents (MOCK MODE) starting on port 5002...")
    print("⚠️  Using simulated AI responses - no API key required")
    app.run(host='0.0.0.0', port=5002)
