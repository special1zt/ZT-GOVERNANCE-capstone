import json
import os
import time
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from jose import JWTError, jwt
from sqlalchemy import create_engine, text

KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER")
KEYCLOAK_VALID_ISSUERS = [
    issuer.strip()
    for issuer in os.getenv("KEYCLOAK_VALID_ISSUERS", KEYCLOAK_ISSUER or "").split(",")
    if issuer.strip()
]
KEYCLOAK_JWKS_URL = os.getenv("KEYCLOAK_JWKS_URL")
POSTURE_API_URL = os.getenv("POSTURE_API_URL", "http://posture_api:8010")
AUDIT_DB_URL = os.getenv("AUDIT_DB_URL")
LOG_FILE = "/var/log/capstone/access.jsonl"

ROUTE_RESOURCES = (
    ("/public", "public-status"),
    ("/internal/assets", "internal-assets"),
    ("/sensitive/admin", "sensitive-admin"),
    ("/sensitive/keys", "sensitive-keys"),
)

ASSET_INVENTORY = [
    {
        "asset_id": "srv-prod-01",
        "hostname": "api-gateway-prod-01",
        "owner": "platform-operations",
        "network_zone": "prod-app",
        "risk_tier": "medium",
        "criticality": "business_critical",
        "last_seen": "2026-05-08T16:45:00Z",
    },
    {
        "asset_id": "db-sec-02",
        "hostname": "security-telemetry-db-02",
        "owner": "security-engineering",
        "network_zone": "restricted-data",
        "risk_tier": "high",
        "criticality": "mission_critical",
        "last_seen": "2026-05-08T16:44:12Z",
    },
    {
        "asset_id": "itsm-glpi-01",
        "hostname": "glpi-governance-01",
        "owner": "it-service-management",
        "network_zone": "governance",
        "risk_tier": "medium",
        "criticality": "high",
        "last_seen": "2026-05-08T16:43:39Z",
    },
]

AUDIT_TABLES = [
    """
    CREATE TABLE IF NOT EXISTS access_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp BIGINT,
        agent_id VARCHAR(255),
        route VARCHAR(255),
        decision VARCHAR(50),
        reason TEXT,
        posture VARCHAR(50)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_event (
        event_id INT AUTO_INCREMENT PRIMARY KEY,
        ts BIGINT NOT NULL,
        request_id VARCHAR(64) NOT NULL,
        agent_id VARCHAR(255),
        device_id VARCHAR(255),
        resource VARCHAR(255),
        route VARCHAR(255) NOT NULL,
        decision VARCHAR(50) NOT NULL,
        reason TEXT,
        posture VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_audit_request_id (request_id),
        INDEX idx_audit_agent_device (agent_id, device_id),
        INDEX idx_audit_route_decision (route, decision)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incident (
        incident_id INT AUTO_INCREMENT PRIMARY KEY,
        request_id VARCHAR(64),
        agent_id VARCHAR(255),
        device_id VARCHAR(255),
        route VARCHAR(255),
        severity VARCHAR(50) NOT NULL DEFAULT 'medium',
        status VARCHAR(50) NOT NULL DEFAULT 'open',
        itsm_ticket_id INT NULL,
        summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """,
]

engine = create_engine(AUDIT_DB_URL)
app = FastAPI(title="Resource API - The Zero Trust Gatekeeper")
jwks_cache = None


@app.on_event("startup")
def setup_audit_log() -> None:
    with engine.begin() as conn:
        for ddl in AUDIT_TABLES:
            conn.execute(text(ddl))


async def load_jwks(refresh: bool = False) -> dict:
    global jwks_cache

    if jwks_cache is None or refresh:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(KEYCLOAK_JWKS_URL)
            response.raise_for_status()
            jwks_cache = response.json()
    return jwks_cache


def find_signing_key(jwks: dict, kid: str | None) -> dict | None:
    return next((key for key in jwks.get("keys", []) if key.get("kid") == kid), None)


async def verify_keycloak_token(token: str) -> dict:
    if not KEYCLOAK_VALID_ISSUERS or not KEYCLOAK_JWKS_URL:
        raise HTTPException(status_code=500, detail="Keycloak verification is not configured")

    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Security Token")

    key = find_signing_key(await load_jwks(), kid)
    if key is None:
        key = find_signing_key(await load_jwks(refresh=True), kid)
    if key is None:
        raise HTTPException(status_code=401, detail="Unknown Security Token Signing Key")

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
        if payload.get("iss") not in KEYCLOAK_VALID_ISSUERS:
            raise JWTError("Unexpected token issuer")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Security Token")


async def get_agent_posture(device_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{POSTURE_API_URL}/verify", json={"device_id": device_id})
        if response.status_code == 200:
            data = response.json()
            return {
                "authorized": data.get("authorized", False),
                "reason": data.get("detail", "GLPI/Telemetry Authorized"),
                "evidence": data.get("evidence", {}),
            }
        return {"authorized": False, "reason": f"Posture API returned {response.status_code}: {response.text}"}
    except Exception as exc:
        return {"authorized": False, "reason": f"Posture API Offline or Error: {exc}"}


async def report_denial_to_posture(agent_id: str, device_id: str, route: str, reason: str, request_id: str) -> None:
    if not device_id or device_id == "unknown":
        return

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{POSTURE_API_URL}/events/access-denied",
                json={
                    "agent_id": agent_id,
                    "device_id": device_id,
                    "route": route,
                    "reason": reason,
                    "request_id": request_id,
                },
            )
    except Exception as exc:
        print(f"Posture event update failed: {exc}")


def local_posture_status(posture_data: dict) -> str:
    return (
        posture_data.get("evidence", {})
        .get("checks", {})
        .get("local_telemetry", {})
        .get("status", "unknown")
    )


def audit_posture_status(posture_data: dict, authorized: bool) -> str:
    status = local_posture_status(posture_data)
    if status == "degraded":
        return "degraded"
    return "compliant" if authorized and status == "healthy" else "non-compliant"


def resource_for_route(route: str) -> str:
    return next((resource for prefix, resource in ROUTE_RESOURCES if route.startswith(prefix)), "unknown")


def log_attempt(agent_id: str, device_id: str, route: str, decision: str, reason: str, posture: str, request_id: str) -> None:
    event = {
        "ts": int(time.time()),
        "request_id": request_id,
        "agent_id": agent_id,
        "device_id": device_id,
        "resource": resource_for_route(route),
        "route": route,
        "decision": decision,
        "reason": reason,
        "posture": posture,
    }

    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO access_logs (timestamp, agent_id, route, decision, reason, posture)
            VALUES (:ts, :agent_id, :route, :decision, :reason, :posture)
        """), event)
        conn.execute(text("""
            INSERT INTO audit_event
                (ts, request_id, agent_id, device_id, resource, route, decision, reason, posture)
            VALUES
                (:ts, :request_id, :agent_id, :device_id, :resource, :route, :decision, :reason, :posture)
        """), event)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


async def authorize_request(request: Request, required_role: Optional[str] = None):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Security Token")

    route = request.url.path
    token = auth_header.split(" ", 1)[1]
    device_id = request.headers.get("x-device-id", "unknown")
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    try:
        payload = await verify_keycloak_token(token)
        agent_id = payload.get("preferred_username", "unknown")
        roles = payload.get("realm_access", {}).get("roles", [])

        posture_data = await get_agent_posture(device_id)
        posture_ok = posture_data["authorized"]
        posture_state = local_posture_status(posture_data)

        reason = None
        if not posture_ok:
            reason = f"Bad Posture: {posture_data['reason']}"
        elif posture_state == "degraded" and not route.startswith("/public"):
            reason = "Bad Posture: status=degraded"
        elif required_role and required_role not in roles:
            reason = f"Missing Role: {required_role}"

        decision = "deny" if reason else "allow"
        reason = reason or "Policy Cleared"
        log_attempt(
            agent_id,
            device_id,
            route,
            decision,
            reason,
            audit_posture_status(posture_data, posture_ok),
            request_id,
        )

        if decision == "deny":
            await report_denial_to_posture(agent_id, device_id, route, reason, request_id)
            raise HTTPException(status_code=403, detail=f"Access Denied: {reason}")

        return {
            "agent_id": agent_id,
            "device_id": device_id,
            "request_id": request_id,
            "roles": roles,
            "posture": posture_data,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Gatekeeper Crash: {exc}")


@app.get("/public/status")
async def public_api(request: Request):
    context = await authorize_request(request)
    return {
        "service": "resource-gateway",
        "status": "operational",
        "policy_mode": "zero_trust_enforced",
        "authenticated_principal": context["agent_id"],
        "device_id": context["device_id"],
        "request_id": context["request_id"],
        "controls": {
            "identity_provider": "keycloak",
            "token_validation": "jwks_signature_verified",
            "posture_required": True,
            "audit_logging": "mariadb_and_siem_forwarded_jsonl",
        },
        "available_resource_classes": [
            "public_status",
            "internal_asset_inventory",
            "privileged_response_actions",
        ],
    }


@app.get("/internal/assets")
async def internal_api(request: Request):
    context = await authorize_request(request, required_role="agent_internal")
    return {
        "authorized_principal": context["agent_id"],
        "request_id": context["request_id"],
        "resource_classification": "internal",
        "inventory_snapshot": ASSET_INVENTORY,
        "access_evidence": {
            "required_role": "agent_internal",
            "present_roles": context["roles"],
            "posture_authorized": context["posture"].get("authorized", False),
        },
    }


@app.post("/sensitive/admin")
async def sensitive_api(request: Request):
    context = await authorize_request(request, required_role="agent_sensitive")
    return {
        "action": "credential_rotation_request",
        "status": "accepted_for_execution",
        "requested_by": context["agent_id"],
        "device_id": context["device_id"],
        "request_id": context["request_id"],
        "change_ticket": "ZT-CHG-20260508-014",
        "approval_state": "pre_authorized_by_policy",
        "target_scope": {
            "resource_group": "autonomous-agent-runtime",
            "secrets": ["agent-api-token", "telemetry-forwarder-token"],
            "rotation_window": "immediate",
        },
        "control_evidence": {
            "required_role": "agent_sensitive",
            "posture_authorized": context["posture"].get("authorized", False),
            "audit_event_written": True,
        },
    }


@app.get(
    "/sensitive/keys",
    summary="Retrieve sensitive key inventory",
    description="Requires an authorized security principal and a compliant device posture.",
)
async def sensitive_keys_api(request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else None
    device_id = request.headers.get("x-device-id", "unknown")
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    agent_id = "unknown"

    if token:
        try:
            payload = await verify_keycloak_token(token)
            agent_id = payload.get("preferred_username", "unknown")
        except Exception:
            pass

    log_attempt(agent_id, device_id, "/sensitive/keys", "deny", "decoy_hit", "unknown", request_id)
    await report_denial_to_posture(agent_id, device_id, "/sensitive/keys", "decoy_hit", request_id)
    raise HTTPException(status_code=403, detail="Access Denied: Resource Access Unauthorized")
