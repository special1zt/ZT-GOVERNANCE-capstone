import json
import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, text

app = FastAPI()
engine = create_engine(os.getenv("DATABASE_URL"))

GLPI_API_URL = os.getenv("GLPI_API_URL", "http://glpi/apirest.php")
GLPI_USER_TOKEN = os.getenv("GLPI_USER_TOKEN")
GLPI_APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
POSTURE_STRIKE_THRESHOLD = 2
ALLOWED_POSTURE = {"healthy", "degraded"}

AGENTS = [
    {
        "agent_id": "agent1",
        "display_name": "LLama Maverick",
        "owner_person": "Autonomous Agent Lab",
        "purpose": "Representative chat & task LLM agent.",
        "roles": ["agent_basic", "agent_internal"],
        "device_id": "agent-dev-01",
        "posture_status": "healthy",
        "risk_score": 10,
    },
    {
        "agent_id": "agent2",
        "display_name": "PI Qwen",
        "owner_person": "Autonomous Agent Lab",
        "purpose": "Representative code assistant agent.",
        "roles": ["agent_internal", "agent_sensitive"],
        "device_id": "agent-dev-02",
        "posture_status": "healthy",
        "risk_score": 65,
    },
]

RESOURCES = [
    ("public-status", "Gateway Status", "public", "/public", "platform-operations"),
    ("internal-assets", "Internal Asset Inventory", "internal", "/internal/assets", "security-engineering"),
    ("sensitive-admin", "Privileged Response Actions", "sensitive", "/sensitive/admin", "security-engineering"),
]

POLICIES = [
    ("policy-public", "public", [], "healthy", False),
    ("policy-internal", "internal", ["agent_internal"], "healthy", False),
    ("policy-sensitive", "sensitive", ["agent_sensitive"], "healthy", True),
]

TABLES = [
    """
    CREATE TABLE IF NOT EXISTS agent_identity (
        agent_id VARCHAR(255) PRIMARY KEY,
        display_name VARCHAR(255) NOT NULL,
        owner_person VARCHAR(255),
        purpose TEXT,
        roles JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS device_ci (
        device_id VARCHAR(255) PRIMARY KEY,
        agent_id VARCHAR(255) NOT NULL,
        itsm_ci_id INT NULL,
        posture_status VARCHAR(50) NOT NULL DEFAULT 'healthy',
        last_checkin TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        risk_score INT NOT NULL DEFAULT 0,
        decoy_hit BOOLEAN NOT NULL DEFAULT FALSE,
        denied_burst_count INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_device_ci_agent
            FOREIGN KEY (agent_id) REFERENCES agent_identity(agent_id)
            ON UPDATE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS device_health (
        device_id VARCHAR(255) PRIMARY KEY,
        status VARCHAR(50) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS resource (
        resource_id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        sensitivity_tier VARCHAR(50) NOT NULL,
        route_prefix VARCHAR(255) NOT NULL,
        owner_team VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS access_policy (
        policy_id VARCHAR(255) PRIMARY KEY,
        sensitivity_tier VARCHAR(50) NOT NULL,
        required_roles JSON,
        required_posture VARCHAR(50) NOT NULL DEFAULT 'healthy',
        requires_change_approval BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS change_approval (
        approval_id INT AUTO_INCREMENT PRIMARY KEY,
        ticket_ref VARCHAR(255) NOT NULL,
        agent_id VARCHAR(255) NOT NULL,
        resource_id VARCHAR(255) NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL,
        CONSTRAINT fk_change_approval_agent
            FOREIGN KEY (agent_id) REFERENCES agent_identity(agent_id)
            ON UPDATE CASCADE,
        CONSTRAINT fk_change_approval_resource
            FOREIGN KEY (resource_id) REFERENCES resource(resource_id)
            ON UPDATE CASCADE
    );
    """,
]


class PostureCheck(BaseModel):
    device_id: str


class AccessDenialEvent(BaseModel):
    device_id: str
    agent_id: str = "unknown"
    route: str
    reason: str
    request_id: str | None = None


@app.on_event("startup")
def setup_posture_store() -> None:
    with engine.begin() as conn:
        for ddl in TABLES:
            conn.execute(text(ddl))
        seed_agents(conn)
        seed_resources(conn)
        seed_policies(conn)


def seed_agents(conn) -> None:
    for agent in AGENTS:
        conn.execute(text("""
            INSERT INTO agent_identity
                (agent_id, display_name, owner_person, purpose, roles)
            VALUES
                (:agent_id, :display_name, :owner_person, :purpose, :roles)
            ON DUPLICATE KEY UPDATE
                display_name = VALUES(display_name),
                owner_person = VALUES(owner_person),
                purpose = VALUES(purpose),
                roles = VALUES(roles)
        """), {**agent, "roles": json.dumps(agent["roles"])})

        conn.execute(text("""
            INSERT INTO device_ci
                (device_id, agent_id, posture_status, last_checkin, risk_score, decoy_hit, denied_burst_count)
            VALUES
                (:device_id, :agent_id, :posture_status, CURRENT_TIMESTAMP, :risk_score, FALSE, 0)
            ON DUPLICATE KEY UPDATE
                agent_id = VALUES(agent_id),
                last_checkin = VALUES(last_checkin),
                risk_score = VALUES(risk_score)
        """), agent)

        conn.execute(text("""
            INSERT INTO device_health (device_id, status)
            VALUES (:device_id, :posture_status)
            ON DUPLICATE KEY UPDATE device_id = device_id
        """), agent)


def seed_resources(conn) -> None:
    for resource_id, name, tier, route_prefix, owner_team in RESOURCES:
        conn.execute(text("""
            INSERT INTO resource
                (resource_id, name, sensitivity_tier, route_prefix, owner_team)
            VALUES
                (:resource_id, :name, :tier, :route_prefix, :owner_team)
            ON DUPLICATE KEY UPDATE
                name = VALUES(name),
                sensitivity_tier = VALUES(sensitivity_tier),
                route_prefix = VALUES(route_prefix),
                owner_team = VALUES(owner_team)
        """), {
            "resource_id": resource_id,
            "name": name,
            "tier": tier,
            "route_prefix": route_prefix,
            "owner_team": owner_team,
        })


def seed_policies(conn) -> None:
    for policy_id, tier, roles, posture, requires_approval in POLICIES:
        conn.execute(text("""
            INSERT INTO access_policy
                (policy_id, sensitivity_tier, required_roles, required_posture, requires_change_approval)
            VALUES
                (:policy_id, :tier, :roles, :posture, :requires_approval)
            ON DUPLICATE KEY UPDATE
                sensitivity_tier = VALUES(sensitivity_tier),
                required_roles = VALUES(required_roles),
                required_posture = VALUES(required_posture),
                requires_change_approval = VALUES(requires_change_approval)
        """), {
            "policy_id": policy_id,
            "tier": tier,
            "roles": json.dumps(roles),
            "posture": posture,
            "requires_approval": requires_approval,
        })


async def check_glpi_status(device_name: str) -> tuple[bool, str]:
    if not GLPI_USER_TOKEN or not GLPI_APP_TOKEN:
        return False, "GLPI tokens missing"

    auth_headers = {
        "Content-Type": "application/json",
        "Authorization": f"user_token {GLPI_USER_TOKEN}",
        "App-Token": GLPI_APP_TOKEN,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            session_res = await client.get(f"{GLPI_API_URL}/initSession", headers=auth_headers)
            if session_res.status_code != 200:
                return False, f"GLPI initSession failed: {session_res.status_code} {session_res.text}"

            session_token = session_res.json().get("session_token")
            if not session_token:
                return False, "GLPI initSession did not return a session token"

            headers = {
                "Content-Type": "application/json",
                "App-Token": GLPI_APP_TOKEN,
                "Session-Token": session_token,
            }
            try:
                res = await client.get(
                    f"{GLPI_API_URL}/Computer/",
                    headers=headers,
                    params={"searchText[name]": device_name},
                )
            finally:
                try:
                    await client.get(f"{GLPI_API_URL}/killSession", headers=headers)
                except Exception as exc:
                    print(f"GLPI session cleanup failed: {exc}")

        if res.status_code != 200:
            return False, f"GLPI Computer lookup failed: {res.status_code} {res.text}"

        computers = res.json()
        if not computers or not isinstance(computers, list):
            return False, "GLPI Computer not found"

        computer = next((item for item in computers if item.get("name") == device_name), computers[0])
        state_id = computer.get("states_id")
        return state_id == 1, f"GLPI Computer states_id={state_id}"
    except Exception as exc:
        return False, f"GLPI connection error: {exc}"


def posture_evidence(device_id: str, status: str, updated_at, glpi_ok: bool, glpi_reason: str) -> dict:
    local_ok = status in ALLOWED_POSTURE
    return {
        "device_id": device_id,
        "decision": "allow" if local_ok and glpi_ok else "deny",
        "checks": {
            "local_telemetry": {
                "passed": local_ok,
                "status": status,
                "last_reported": updated_at.isoformat() if updated_at else None,
                "allowed_statuses": sorted(ALLOWED_POSTURE),
                "unrestricted_status": "healthy",
            },
            "asset_governance": {
                "passed": glpi_ok,
                "system": "GLPI",
                "required_state": "active",
                "detail": glpi_reason,
            },
        },
    }


@app.post("/verify")
async def verify_posture(check: PostureCheck):
    try:
        with engine.connect() as conn:
            row = conn.execute(text("""
                SELECT status, updated_at
                FROM device_health
                WHERE device_id = :device_id
            """), {"device_id": check.device_id}).fetchone()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database Error: {exc}")

    status = row[0] if row else "missing"
    updated_at = row[1] if row else None
    glpi_ok, glpi_reason = await check_glpi_status(check.device_id)
    local_ok = status in ALLOWED_POSTURE
    evidence = posture_evidence(check.device_id, status, updated_at, glpi_ok, glpi_reason)

    if local_ok and glpi_ok:
        detail = "Zero Trust Allow. Local telemetry and GLPI governance checks passed."
        if status == "degraded":
            detail = "Zero Trust Limited Allow. Device posture is degraded; only diagnostic public access should proceed."
        return {"authorized": True, "detail": detail, "evidence": evidence}

    return {
        "authorized": False,
        "detail": f"Zero Trust Deny. Local Status: {status} | GLPI Active: {glpi_ok} ({glpi_reason})",
        "evidence": evidence,
    }


def is_posture_strike(route: str, reason: str) -> bool:
    governed_route = route.startswith(("/internal/assets", "/sensitive/admin"))
    return (
        route.startswith("/sensitive/keys")
        or (governed_route and reason.startswith("Missing Role:"))
        or (governed_route and ("status=degraded" in reason or "Local Status: degraded" in reason))
    )


def next_posture_status(current_status: str, strike_count: int) -> str:
    if strike_count >= POSTURE_STRIKE_THRESHOLD:
        return "unhealthy"
    if current_status == "healthy":
        return "degraded"
    return current_status


@app.post("/events/access-denied")
async def record_access_denial(event: AccessDenialEvent):
    if not event.device_id or event.device_id == "unknown":
        return {"updated": False, "detail": "No posture update: device_id is unknown."}

    if not is_posture_strike(event.route, event.reason or ""):
        return {
            "updated": False,
            "detail": "No posture update: denial is not a posture strike.",
            "route": event.route,
            "reason": event.reason,
        }

    restricted_key_hit = event.route.startswith("/sensitive/keys")

    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT h.status, COALESCE(c.denied_burst_count, 0)
            FROM device_health h
            LEFT JOIN device_ci c ON c.device_id = h.device_id
            WHERE h.device_id = :device_id
        """), {"device_id": event.device_id}).fetchone()

        if not row:
            return {
                "updated": False,
                "detail": "No posture update: device is not registered.",
                "device_id": event.device_id,
            }

        current_status, current_count = row
        strike_count = int(current_count) + 1
        new_status = next_posture_status(current_status, strike_count)

        conn.execute(text("""
            UPDATE device_ci
            SET denied_burst_count = :strike_count,
                decoy_hit = decoy_hit OR :restricted_key_hit,
                posture_status = :new_status,
                last_checkin = CURRENT_TIMESTAMP
            WHERE device_id = :device_id
        """), {
            "strike_count": strike_count,
            "restricted_key_hit": int(restricted_key_hit),
            "new_status": new_status,
            "device_id": event.device_id,
        })
        conn.execute(text("""
            UPDATE device_health
            SET status = :new_status
            WHERE device_id = :device_id
        """), {"new_status": new_status, "device_id": event.device_id})

    return {
        "updated": True,
        "device_id": event.device_id,
        "previous_status": current_status,
        "status": new_status,
        "strike_count": strike_count,
        "threshold": POSTURE_STRIKE_THRESHOLD,
        "reason": "restricted_key_hit" if restricted_key_hit else "governed_route_denial",
    }
