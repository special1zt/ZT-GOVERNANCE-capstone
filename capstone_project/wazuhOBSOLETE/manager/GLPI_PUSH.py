
import sys
import json
import os
import urllib.request
import urllib.parse

def main():
    # 1. Wazuh passes the path to the alert JSON file as the first argument
    alert_file = sys.argv[1]
    with open(alert_file, 'r') as f:
        alert = json.load(f)

    # 2. Pull Secrets & Setup Routing
    # Uses the internal Docker network name for your GLPI container
    glpi_url = "http://capstone_glpi:80/apirest.php"
    app_token = os.environ.get('GLPI_APP_TOKEN')
    user_token = os.environ.get('GLPI_USER_TOKEN')

    if not app_token or not user_token:
        print("Error: GLPI Tokens missing from environment.")
        sys.exit(1)

    headers = {
        'Content-Type': 'application/json',
        'App-Token': app_token,
        'Authorization': f'user_token {user_token}'
    }

    # 3. Extract dynamic data from the Wazuh alert
    rule_desc = alert.get('rule', {}).get('description', 'Unauthorized Access Attempt')
    rule_level = alert.get('rule', {}).get('level', 0)
    
    # Safely extract custom JSON fields parsed by your decoder
    event_data = alert.get('data', {})
    agent_id = event_data.get('agent_id', 'UNKNOWN_IDENTITY')
    target_route = event_data.get('route', 'UNKNOWN_ROUTE')
    auth_decision = event_data.get('decision', 'DENY')
    posture_status = event_data.get('posture', 'UNKNOWN_POSTURE')
    
    # 4. Format a professional, enterprise-grade ticket body
    ticket_title = f"[SOC ALERT] Priority {rule_level} - Detected Lateral Movement Attempt: {rule_desc}"
    
    ticket_content = (
        "AUTOMATED SECURITY INCIDENT REPORT\n"
        "==================================\n\n"
        "Immediate analyst review is required to determine if this is a misconfigured internal asset or an active lateral movement attempt.\n\n"
        "INCIDENT METADATA:\n"
        "------------------\n"
        f"- Target Endpoint: {target_route}\n"
        f"- Configuration Item (CI): {agent_id}\n"
        f"- Device Posture Check: {posture_status.upper()}\n"
        f"- Enforcement Action: {auth_decision.upper()}\n\n"
        "RAW TELEMETRY / SIEM PAYLOAD:\n"
        "-----------------------------\n"
        f"{json.dumps(alert, indent=2)}\n"
    )

    try:
        # --- API STEP 1: INIT SESSION ---
        req_init = urllib.request.Request(f"{glpi_url}/initSession", headers=headers)
        with urllib.request.urlopen(req_init) as response:
            session_data = json.loads(response.read().decode())
            session_token = session_data['session_token']
        
        headers['Session-Token'] = session_token

        # --- API STEP 2: PUSH TICKET ---
        ticket_payload = {
            "input": {
                "name": ticket_title,
                "content": ticket_content,
                "status": 1, # GLPI Status ID 1: 'New'
                "urgency": 5 # GLPI Urgency ID 5: 'Very High'
            }
        }
        
        req_ticket = urllib.request.Request(
            f"{glpi_url}/Ticket", 
            data=json.dumps(ticket_payload).encode('utf-8'), 
            headers=headers, 
            method='POST'
        )
        urllib.request.urlopen(req_ticket)

        # --- API STEP 3: KILL SESSION ---
        req_kill = urllib.request.Request(f"{glpi_url}/killSession", headers=headers)
        urllib.request.urlopen(req_kill)
        
        print("Successfully pushed Incident Ticket to GLPI.")

    except Exception as e:
        print(f"Failed to integrate with GLPI ITSM: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()