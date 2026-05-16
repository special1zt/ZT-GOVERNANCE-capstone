import os

import httpx


def required_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    raise RuntimeError(f"Missing required environment variable: {' or '.join(names)}")


def main():
    print("\n--- Keycloak IaC Deployment ---")

    token_url = "http://localhost:8080/realms/master/protocol/openid-connect/token"
    token_data = {
        "client_id": "admin-cli",
        "username": required_env("KC_BOOTSTRAP_ADMIN_USERNAME", "KC_ADMIN_USER"),
        "password": required_env("KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_ADMIN_PASS"),
        "grant_type": "password",
    }

    print("[*] Authenticating as master admin...")
    try:
        res = httpx.post(token_url, data=token_data)
        res.raise_for_status()
        token = res.json()["access_token"]
    except Exception as e:
        print(f"[-] Authentication failed. Is Keycloak running? Error: {e}")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    admin_url = "http://localhost:8080/admin/realms"
    agent_password = required_env("AGENT_PASSWORD")

    print("[*] Checking for existing 'capstone' realm...")
    check_res = httpx.get(f"{admin_url}/capstone", headers=headers)
    if check_res.status_code == 200:
        print("[*] Wiping old 'capstone' realm to prevent configuration drift...")
        httpx.delete(f"{admin_url}/capstone", headers=headers)

    realm_payload = {
        "id": "capstone",
        "realm": "capstone",
        "enabled": True,
        "accessTokenLifespan": 2700,
        "clients": [
            {
                "clientId": "capstone-client",
                "enabled": True,
                "publicClient": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": True,
            }
        ],
        "roles": {
            "realm": [
                {"name": "agent_internal", "description": "Cleared for standard internal assets"},
                {"name": "agent_sensitive", "description": "Cleared for high-security admin assets"},
                {"name": "agent_basic", "description": "Cleared for basic public assets"},
            ]
        },
        "users": [
            {
                "username": "agent1",
                "enabled": True,
                "credentials": [{"type": "password", "value": agent_password, "temporary": False}],
                "realmRoles": ["agent_basic", "agent_internal"],
            },
            {
                "username": "agent2",
                "enabled": True,
                "credentials": [{"type": "password", "value": agent_password, "temporary": False}],
                "realmRoles": ["agent_internal", "agent_sensitive"],
            },
        ],
    }

    print("[*] Injecting new Zero Trust architecture...")
    create_res = httpx.post(admin_url, headers=headers, json=realm_payload)

    if create_res.status_code == 201:
        print("[+] Success! Realm, Client, Roles, and Agents deployed.")
    else:
        print(f"[-] Failed to deploy config: {create_res.status_code} - {create_res.text}")

    print("-------------------------------\n")


if __name__ == "__main__":
    main()
