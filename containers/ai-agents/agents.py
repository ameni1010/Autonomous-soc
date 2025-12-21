from flask import Flask, request, jsonify
from anthropic import Anthropic
import os
import json

app = Flask(__name__)

# Initialize Anthropic client
api_key = os.environ.get('ANTHROPIC_API_KEY')
if not api_key:
    print("⚠️  WARNING: ANTHROPIC_API_KEY not set!")
    client = None
else:
    client = Anthropic(api_key=api_key)

MODEL = "claude-sonnet-4-20250514"

def call_claude(prompt, max_tokens=1000):
    """Helper function to call Claude API"""
    if not client:
        return {"error": "API key not configured"}
    
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        
        # Extract text and try to parse as JSON
        text = response.content[0].text
        
        # Try to extract JSON from markdown code blocks
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        
        return json.loads(text)
    except json.JSONDecodeError:
        # If not valid JSON, return as text
        return {"response": text}
    except Exception as e:
        return {"error": str(e)}

@app.route('/triage', methods=['POST'])
def triage_agent():
    """SOC Tier 1 - Initial Alert Triage"""
    alert = request.json
    
    prompt = f"""You are a SOC Tier 1 analyst performing initial triage on a security alert.

Alert Details:
{json.dumps(alert, indent=2)}

Analyze this alert and determine:
1. Is this a valid security concern or a false positive?
2. What is the severity level?
3. What is your reasoning?

Respond ONLY with valid JSON in this exact format:
{{
  "status": "valid_alert" or "false_positive",
  "severity": "low" or "medium" or "high" or "critical",
  "reason": "brief explanation in 1-2 sentences"
}}"""

    result = call_claude(prompt, max_tokens=500)
    print(f"[TRIAGE] {alert.get('alert_type')}: {result.get('status')} - {result.get('severity')}")
    
    return jsonify(result), 200

@app.route('/investigate', methods=['POST'])
def investigation_agent():
    """SOC Tier 2 - Deep Investigation"""
    data = request.json
    
    prompt = f"""You are a SOC Tier 2 analyst conducting a deep investigation.

Alert: {json.dumps(data.get('alert', {}), indent=2)}
Triage Result: {json.dumps(data.get('triage', {}), indent=2)}
Additional Context: {json.dumps(data.get('context', {}), indent=2)}

Investigate and identify:
1. The type of attack
2. The attack chain/sequence
3. Key indicators of compromise
4. Your confidence level

Respond ONLY with valid JSON in this exact format:
{{
  "attack_type": "name of the attack pattern",
  "confidence": 0.0-1.0,
  "attack_chain": ["step1", "step2", "step3"],
  "indicators": ["indicator1", "indicator2"],
  "analysis": "detailed explanation in 2-3 sentences"
}}"""

    result = call_claude(prompt, max_tokens=800)
    print(f"[INVESTIGATION] Attack: {result.get('attack_type')} (confidence: {result.get('confidence')})")
    
    return jsonify(result), 200

@app.route('/threat-intel', methods=['POST'])
def threat_intel_agent():
    """Threat Intelligence Enrichment"""
    data = request.json
    ip = data.get('ip', 'unknown')
    
    # In real-world: Query VirusTotal, AbuseIPDB, threat feeds, etc.
    # For demo: Simulate based on IP pattern
    
    is_malicious = ip.endswith('.2') or ip.endswith('.3')
    
    threat_data = {
        "ip": ip,
        "reputation": "malicious" if is_malicious else "clean",
        "risk_score": 8.5 if is_malicious else 2.0,
        "known_campaigns": ["credential_stuffing", "brute_force"] if is_malicious else [],
        "geolocation": "Unknown",
        "asn": "Unknown",
        "last_seen": "2024-12-19" if is_malicious else None
    }
    
    print(f"[THREAT INTEL] IP {ip}: {threat_data['reputation']} (risk: {threat_data['risk_score']})")
    
    return jsonify(threat_data), 200

@app.route('/decide', methods=['POST'])
def decision_agent():
    """SOC Team Lead - Final Decision"""
    data = request.json
    
    prompt = f"""You are a SOC Team Lead making the final decision on an incident response.

Triage Analysis: {json.dumps(data.get('triage', {}), indent=2)}
Investigation: {json.dumps(data.get('investigation', {}), indent=2)}
Threat Intelligence: {json.dumps(data.get('threat_intel', {}), indent=2)}

Based on all the evidence, decide:
1. What action should be taken? (block_ip, monitor, escalate, or dismiss)
2. Final severity assessment
3. Detailed justification
4. Recommended follow-up actions

Respond ONLY with valid JSON in this exact format:
{{
  "decision": "block_ip" or "monitor" or "escalate" or "dismiss",
  "severity": "low" or "medium" or "high" or "critical",
  "justification": "detailed reasoning in 2-3 sentences",
  "recommended_actions": ["action1", "action2", "action3"]
}}"""

    result = call_claude(prompt, max_tokens=800)
    print(f"[DECISION] Action: {result.get('decision')} - Severity: {result.get('severity')}")
    
    return jsonify(result), 200

@app.route('/report', methods=['POST'])
def reporting_agent():
    """Generate Comprehensive Incident Report"""
    data = request.json
    
    prompt = f"""You are generating a professional SOC incident report.

Complete Incident Data:
{json.dumps(data, indent=2)}

Generate a clear, executive-friendly incident report with:
- Executive Summary (2-3 sentences)
- Attack Timeline
- Technical Analysis
- Actions Taken
- Recommendations

Format as markdown."""

    result = call_claude(prompt, max_tokens=1500)
    print("[REPORT] Incident report generated")
    
    return jsonify({"report": result.get("response", "Report generation failed")}), 200

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "ai-agents",
        "api_key_configured": client is not None
    }), 200

if __name__ == '__main__':
    if not client:
        print("⚠️  WARNING: Starting without API key - agents will not function properly!")
    print("🤖 AI Agents starting on port 5002...")
    app.run(host='0.0.0.0', port=5002)
