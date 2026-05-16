import os
from typing import Any

import requests
from flask import Flask, jsonify, request


app = Flask(__name__)

GLPI_URL = os.getenv("GLPI_URL", "http://glpi").rstrip("/")
APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
USER_TOKEN = os.getenv("GLPI_USER_TOKEN")
GLPI_API_URL = f"{GLPI_URL}/apirest.php"
TIMEOUT = 5


def first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def auth_headers() -> dict[str, str]:
    return {
        "App-Token": APP_TOKEN or "",
        "Authorization": f"user_token {USER_TOKEN or ''}",
    }


def session_headers(session_token: str) -> dict[str, str]:
    return {
        "App-Token": APP_TOKEN or "",
        "Session-Token": session_token,
        "Content-Type": "application/json",
    }


def start_glpi_session() -> str:
    response = requests.get(f"{GLPI_API_URL}/initSession", headers=auth_headers(), timeout=TIMEOUT)
    response.raise_for_status()

    session_token = response.json().get("session_token")
    if not session_token:
        raise RuntimeError("GLPI did not return a session token")
    return session_token


def stop_glpi_session(headers: dict[str, str]) -> None:
    try:
        requests.get(f"{GLPI_API_URL}/killSession", headers=headers, timeout=TIMEOUT)
    except Exception as exc:
        print(f"[!] GLPI session cleanup failed: {exc}")


def find_computer_id(headers: dict[str, str], device_id: str) -> int | None:
    if not device_id or device_id == "unknown":
        return None

    response = requests.get(
        f"{GLPI_API_URL}/Computer/",
        headers=headers,
        params={"searchText[name]": device_id},
        timeout=TIMEOUT,
    )
    response.raise_for_status()

    for computer in response.json():
        if computer.get("name") == device_id:
            return computer.get("id")
    return None


def link_ticket_to_computer(headers: dict[str, str], ticket_id: int, computer_id: int) -> bool:
    response = requests.post(
        f"{GLPI_API_URL}/Item_Ticket",
        headers=headers,
        json={
            "input": {
                "tickets_id": ticket_id,
                "itemtype": "Computer",
                "items_id": computer_id,
            }
        },
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    return True


def alert_fields(data: dict[str, Any]) -> dict[str, str]:
    result = data.get("result") or {}
    agent_id = first(result.get("agent_id")) or "unknown"
    device_id = first(result.get("device_id")) or "unknown"

    return {
        "search_name": data.get("search_name", "Zero Trust Alert"),
        "agent_id": agent_id,
        "device_id": device_id,
        "actor_label": f"unauthenticated actor on {device_id}" if agent_id == "unknown" and device_id != "unknown" else agent_id,
        "route": first(result.get("route")) or first(result.get("endpoint")) or "/unknown",
        "resource": first(result.get("resource")) or "unknown",
        "request_id": first(result.get("request_id")) or "unknown",
        "decision": first(result.get("decision")) or "unknown",
        "reason": first(result.get("reason")) or "unknown",
    }


def ticket_payload(fields: dict[str, str], link_status: str) -> dict[str, dict[str, Any]]:
    return {
        "input": {
            "name": f"CRITICAL: Zero Trust Violation - {fields['search_name']}",
            "content": (
                "Automated SOC Alert:\n\n"
                f"Actor: {fields['actor_label']}\n"
                f"Agent identity: {fields['agent_id']}\n"
                f"Device / Computer CI: {fields['device_id']}\n"
                f"Resource: {fields['resource']}\n"
                f"Route: {fields['route']}\n"
                f"Decision: {fields['decision']}\n"
                f"Reason: {fields['reason']}\n"
                f"Request ID: {fields['request_id']}\n\n"
                f"CI correlation: {link_status}\n\n"
                "Recommended response: investigate the mapped Computer CI, review the Splunk event, "
                "and revoke or rotate credentials if the activity is confirmed malicious."
            ),
            "urgency": 5,
            "type": 2,
        }
    }


@app.route("/splunk-alert", methods=["POST"])
def handle_alert():
    data = request.get_json(silent=True) or {}
    fields = alert_fields(data)
    print(f"[*] Splunk webhook: {fields}")

    try:
        session_token = start_glpi_session()
    except Exception as exc:
        print(f"[!] GLPI connection failed: {exc}")
        return jsonify({"error": "GLPI Auth Failed"}), 500

    headers = session_headers(session_token)
    computer_id = None
    linked = False

    try:
        try:
            computer_id = find_computer_id(headers, fields["device_id"])
            link_status = (
                f"Linked to GLPI Computer ID {computer_id} ({fields['device_id']})."
                if computer_id
                else "No matching GLPI Computer CI found."
            )
        except Exception as exc:
            link_status = f"Computer CI lookup failed: {exc}"

        ticket_response = requests.post(
            f"{GLPI_API_URL}/Ticket",
            headers=headers,
            json=ticket_payload(fields, link_status),
            timeout=TIMEOUT,
        )
        ticket_response.raise_for_status()
        ticket_id = ticket_response.json().get("id")

        if computer_id and ticket_id:
            try:
                linked = link_ticket_to_computer(headers, ticket_id, computer_id)
                print(f"[+] Linked ticket {ticket_id} to Computer {computer_id} ({fields['device_id']})")
            except Exception as exc:
                print(f"[!] Ticket created but CI link failed: {exc}")

        print(f"[+] Ticket generated: {ticket_id}")
        return jsonify({
            "status": "Ticket Created",
            "ticket_id": ticket_id,
            "computer_id": computer_id,
            "linked": linked,
        }), 201
    finally:
        stop_glpi_session(headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
