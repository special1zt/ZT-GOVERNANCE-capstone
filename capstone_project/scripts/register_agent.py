import json
import os
from pathlib import Path

from dotenv import load_dotenv

from glpi_client import GLPIClient

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


AGENTS = [
    {
        "agent_id": "agent1",
        "display_name": "LLama Maverick",
        "owner_person": "Autonomous Agent Lab",
        "purpose": "Representative chat & task LLM agent.",
        "roles": ["agent_basic", "agent_internal"],
        "device": {
            "device_id": "agent-dev-01",
            "posture_status": "healthy",
            "risk_score": 10,
            "decoy_hit": False,
            "denied_burst_count": 0,
        },
    },
    {
        "agent_id": "agent2",
        "display_name": "Pi Qwen",
        "owner_person": "Autonomous Agent Lab",
        "purpose": "Representative code assistant agent.",
        "roles": ["agent_internal", "agent_sensitive"],
        "device": {
            "device_id": "agent-dev-02",
            "posture_status": "healthy",
            "risk_score": 65,
            "decoy_hit": False,
            "denied_burst_count": 0,
        },
    },
]

RESOURCES = [
    {
        "resource_id": "public-status",
        "name": "Gateway Status",
        "sensitivity_tier": "public",
        "route_prefix": "/public",
        "owner_team": "platform-operations",
    },
    {
        "resource_id": "internal-assets",
        "name": "Internal Asset Inventory",
        "sensitivity_tier": "internal",
        "route_prefix": "/internal/assets",
        "owner_team": "security-engineering",
    },
    {
        "resource_id": "sensitive-admin",
        "name": "Privileged Response Actions",
        "sensitivity_tier": "sensitive",
        "route_prefix": "/sensitive/admin",
        "owner_team": "security-engineering",
    },
]

POLICIES = [
    {
        "policy_id": "policy-public",
        "sensitivity_tier": "public",
        "required_roles": [],
        "required_posture": "healthy",
        "requires_change_approval": False,
    },
    {
        "policy_id": "policy-internal",
        "sensitivity_tier": "internal",
        "required_roles": ["agent_internal"],
        "required_posture": "healthy",
        "requires_change_approval": False,
    },
    {
        "policy_id": "policy-sensitive",
        "sensitivity_tier": "sensitive",
        "required_roles": ["agent_sensitive"],
        "required_posture": "healthy",
        "requires_change_approval": True,
    },
]


def bool_int(value: bool) -> int:
    return 1 if value else 0


def glpi_computer_payload(agent: dict) -> dict:
    device = agent["device"]
    description = (
        f"Agent ID: {agent['agent_id']}\n"
        f"Owner: {agent['owner_person']}\n"
        f"Purpose: {agent['purpose']}\n"
        f"Roles: {', '.join(agent['roles'])}\n"
        f"Posture: {device['posture_status']}\n"
        f"Risk score: {device['risk_score']}\n"
        "Managed by capstone Zero Trust registration automation."
    )
    return {
        "name": device["device_id"],
        "contact": agent["owner_person"],
        "otherserial": device["device_id"],
        "states_id": 1,
        "comment": description,
    }


def register_glpi_computers() -> dict[str, int]:
    ci_ids = {}
    client = GLPIClient()
    client.connect()

    try:
        print("\n--- Registering GLPI Computer CIs ---")
        for agent in AGENTS:
            device_id = agent["device"]["device_id"]
            existing = client.get_computer_by_name(device_id)
            if existing and existing.get("id"):
                computer_id = int(existing["id"])
                ci_ids[device_id] = computer_id
                client.update_computer(computer_id, glpi_computer_payload(agent))
                print(f"[=] {device_id} updated as GLPI Computer ID {computer_id}")
                continue

            print(f"[*] Creating CI for {device_id}...")
            response = client.create_computer(glpi_computer_payload(agent))
            if "id" not in response:
                raise RuntimeError(f"GLPI did not return an id for {device_id}: {response}")

            ci_ids[device_id] = int(response["id"])
            print(f"[+] {device_id} created as GLPI Computer ID {response['id']}")
    finally:
        client.kill_session()

    return ci_ids


def seed_security_db(ci_ids: dict[str, int]) -> bool:
    try:
        import pymysql
    except ImportError:
        print("[!] pymysql is not installed locally; skipped local DB seeding.")
        return False

    host = os.getenv("SECURITY_DB_HOST", "127.0.0.1")
    port = int(os.getenv("SECURITY_DB_PORT", "3306"))
    user = os.getenv("SECURITY_DB_USER")
    password = os.getenv("SECURITY_DB_PASS")

    if not user or not password:
        print("[!] SECURITY_DB_USER and SECURITY_DB_PASS are missing; skipped local DB seeding.")
        return False

    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database="posture_db",
            autocommit=True,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
        )
    except Exception as exc:
        print(f"[!] Could not reach posture_db at {host}:{port}; skipped local DB seeding: {exc}")
        return False

    with conn:
        with conn.cursor() as cur:
            print("\n--- Seeding Local Governance Tables ---")
            for agent in AGENTS:
                cur.execute(
                    """
                    INSERT INTO agent_identity
                        (agent_id, display_name, owner_person, purpose, roles)
                    VALUES
                        (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        display_name = VALUES(display_name),
                        owner_person = VALUES(owner_person),
                        purpose = VALUES(purpose),
                        roles = VALUES(roles)
                    """,
                    (
                        agent["agent_id"],
                        agent["display_name"],
                        agent["owner_person"],
                        agent["purpose"],
                        json.dumps(agent["roles"]),
                    ),
                )

                device = agent["device"]
                cur.execute(
                    """
                    INSERT INTO device_ci
                        (device_id, agent_id, itsm_ci_id, posture_status, last_checkin,
                         risk_score, decoy_hit, denied_burst_count)
                    VALUES
                        (%s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        agent_id = VALUES(agent_id),
                        itsm_ci_id = VALUES(itsm_ci_id),
                        last_checkin = VALUES(last_checkin),
                        risk_score = VALUES(risk_score)
                    """,
                    (
                        device["device_id"],
                        agent["agent_id"],
                        ci_ids.get(device["device_id"]),
                        device["posture_status"],
                        device["risk_score"],
                        bool_int(device["decoy_hit"]),
                        device["denied_burst_count"],
                    ),
                )
                cur.execute(
                    """
                    INSERT INTO device_health (device_id, status)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE device_id = device_id
                    """,
                    (device["device_id"], device["posture_status"]),
                )
                print(f"[+] Seeded {agent['agent_id']} / {device['device_id']}")

            for resource in RESOURCES:
                cur.execute(
                    """
                    INSERT INTO resource
                        (resource_id, name, sensitivity_tier, route_prefix, owner_team)
                    VALUES
                        (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        name = VALUES(name),
                        sensitivity_tier = VALUES(sensitivity_tier),
                        route_prefix = VALUES(route_prefix),
                        owner_team = VALUES(owner_team)
                    """,
                    (
                        resource["resource_id"],
                        resource["name"],
                        resource["sensitivity_tier"],
                        resource["route_prefix"],
                        resource["owner_team"],
                    ),
                )

            for policy in POLICIES:
                cur.execute(
                    """
                    INSERT INTO access_policy
                        (policy_id, sensitivity_tier, required_roles, required_posture,
                         requires_change_approval)
                    VALUES
                        (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        sensitivity_tier = VALUES(sensitivity_tier),
                        required_roles = VALUES(required_roles),
                        required_posture = VALUES(required_posture),
                        requires_change_approval = VALUES(requires_change_approval)
                    """,
                    (
                        policy["policy_id"],
                        policy["sensitivity_tier"],
                        json.dumps(policy["required_roles"]),
                        policy["required_posture"],
                        bool_int(policy["requires_change_approval"]),
                    ),
                )

            print("[+] Resource and AccessPolicy seed data is current.")
    return True


def main() -> None:
    ci_ids = register_glpi_computers()
    db_seeded = seed_security_db(ci_ids)

    print("\n--- Registration Summary ---")
    for device_id, ci_id in ci_ids.items():
        print(f"{device_id}: GLPI Computer ID {ci_id}")
    print(f"Local DB seeded: {'yes' if db_seeded else 'no'}")
    print("----------------------------\n")


if __name__ == "__main__":
    main()
