# Zero Trust for AI Agents

This project is a Zero Trust lab for AI agents. The idea is that an AI agent should not just get dropped into an environment with access to APIs, tools, and internal resources without any real oversight.

If an agent can request data, interact with systems, or make decisions, then it needs to be managed like something that can affect the environment. That means it should have an identity, a role, a posture state, logs, and a record that can tie its behavior back to an asset or incident.

This lab treats the AI agent as a managed configuration item instead of just another script. The agent does not get trusted just because it has a token. Its access depends on identity, role, posture, and whether it is recognized as an active asset in GLPI.

The goal is not to build a perfect enterprise product. The goal is to show a working model for how AI agents could be governed with Zero Trust ideas.

## What This Project Does

This project connects a few pieces that are usually handled separately:

- agent identity
- posture checks
- API access control
- asset tracking
- logging
- SIEM detection
- incident response

The main flow looks like this:

```text
AI Agent â Identity Check â Posture Check â Access Decision â Logs â SIEM Alert â GLPI Ticket
```

The point is simple: authentication is not enough. The agent can prove who it is and still be denied if its posture or asset status does not check out.

## Main Components

| Component | Role |
|---|---|
| Keycloak | Handles identity and role-based access for the agent |
| FastAPI services | Provide protected resources and posture checks |
| GLPI | Tracks the AI agent as a configuration item and stores incident tickets |
| Splunk | Monitors logs and detects suspicious behavior |
| alert_fwd | Acts as the Micro-SOC bridge between Splunk alerts and GLPI tickets |
| Qwen / Ollama | Used as the test agent to interact with the environment |

## Why I Built This

AI agents are starting to act less like simple chatbots and more like automated workers. They can call APIs, inspect data, use tools, and make decisions across systems.

That creates a security problem. If an AI agent has access but no clear identity, no asset record, no posture checks, and no incident trail, then it becomes another unmanaged thing security teams have to chase later.

This project is my way of modeling a better approach:

> Treat AI agents like enterprise assets, check their identity and posture, monitor what they do, and create incident records when their behavior crosses a line.

That is the core of the project.

## Research Question

How can a Zero Trust security model be used to govern AI agents by combining identity, posture validation, asset management, API access control, SIEM detection, and automated incident response?

## Architecture Overview

The lab uses a basic Zero Trust flow:

1. The agent authenticates through Keycloak.
2. The agent requests a protected API resource.
3. The Resource API checks the token and role.
4. The Resource API checks the agent posture.
5. The posture check confirms whether the agent is healthy and active in GLPI.
6. The request is allowed or denied.
7. The decision is logged.
8. Splunk can detect suspicious activity.
9. `alert_fwd` receives the alert and creates a GLPI ticket.

```text
Keycloak
   â
Resource API / Posture API
   â
GLPI / CMDB
   â
Logs
   â
Splunk
   â
alert_fwd
   â
GLPI Incident Ticket
```

## Resource Access Model

The API resources are separated by sensitivity.

| Resource Type | Purpose |
|---|---|
| Public | Low-risk endpoint used for basic testing |
| Internal | Requires a valid identity and good posture |
| Sensitive | Higher-risk endpoint used to test stricter access control |
| Honeypot / Decoy | Used to prove detection and response when touched |

The honeypot endpoint is not there because the project needs fake secrets. It is there to show that suspicious agent behavior can be detected, logged, and turned into an incident.

## Qwen / Ollama Testing

Qwen is used as the test AI agent. It is given an identity and a task, then used to see how the system responds when the agent tries to access protected resources.

The testing focuses on three basic situations:

### Allowed Access

The agent accesses a resource it should be allowed to use.

Expected result:

```text
Authenticated â Posture Validated â Access Allowed
```

### Denied Access

The agent authenticates, but the system denies the request because posture or authorization fails.

Expected result:

```text
Authenticated â Posture Failed â Access Denied â Event Logged
```

### Decoy Access

The agent touches a honeypot or sensitive endpoint.

Expected result:

```text
Decoy Access â Splunk Alert â alert_fwd â GLPI Ticket
```

## What Counts as a Successful Demo

A working demo should show the full chain:

1. The agent has an identity in Keycloak.
2. The agent exists as a managed asset in GLPI.
3. The agent requests a protected resource.
4. The API checks token, role, and posture.
5. A valid request is allowed.
6. A denied or suspicious request is logged.
7. Splunk detects the event.
8. `alert_fwd` receives the alert.
9. GLPI gets an incident ticket tied back to the agent.

If that works, the project works.

## Example Scenario

An agent named `agent-dev-02` tries to access an internal resource.

The system checks:

- Is the token valid?
- Does the agent have the right role?
- Is the device posture healthy?
- Is the agent active in GLPI?
- Is this resource allowed for that agent?

If the agent fails posture, the request is denied even if authentication worked.

That is intentional. Identity alone is not trust.

## Repository Layout

```text
.
âââ agent OBSOLETE/       # Older agent work kept for reference
âââ alert_fwd/            # Micro-SOC alert forwarder for Splunk-to-GLPI tickets
âââ extras/               # Screenshots and prompts used during testing
âââ keycloak/             # Keycloak realm, identity, or setup files
âââ logs/                 # API and test logs
âââ scripts/              # Setup, test, and helper scripts
âââ services/             # Main API services for resource access and posture checks
âââ splunk/               # Splunk configuration, searches, or detection notes
âââ wazuhOBSOLETE/        # Older Wazuh work kept for reference
âââ .env                  # Local environment variables, not for public commits
âââ docker-compose.yml    # Local lab setup
âââ init-db.sql           # Database initialization script
```

Some folders are marked obsolete because they were part of earlier versions of the project. They are kept for reference, but the current build is centered around Keycloak, the API services, GLPI, Splunk, and `alert_fwd`.

## Setup Notes

This project is built as a local lab. The exact values depend on the local environment, but the main services are controlled through Docker and environment variables.

Typical local services include:

```text
Keycloak
GLPI
Database services
Resource / posture APIs
Splunk
alert_fwd
```

The `.env` file stores local values such as service URLs, tokens, and database settings. Real secrets should not be committed to the public repo.

## Current Focus

The current focus is making the full security loop stable:

```text
Agent Request â Access Decision â Log Event â Splunk Alert â alert_fwd â GLPI Ticket
```

Current work includes:

- validating posture checks for `agent-dev-02`
- confirming that allowed access works when posture is healthy
- confirming that denied access is logged correctly
- testing the honeypot endpoint
- checking that Splunk sees the right events
- checking that `alert_fwd` creates the correct GLPI ticket
- keeping Qwen prompts consistent enough for repeatable testing

## Known Limitations

This is still a prototype lab, not a production system.

Some limitations:

- Some credentials are stored locally for testing.
- Workload identity is simulated instead of fully production-grade.
- Runtime isolation is limited.
- Posture logic is simplified.
- Some older project folders are still present for reference.
- Qwen/Ollama behavior can change between runs.

A stronger production version would need better secret handling, stronger runtime isolation, short-lived credentials, workload identity, and more mature SIEM/SOAR workflows.

## Final Goal

The final goal is to show that AI agents can be governed using the same security ideas already used for enterprise systems:

- identity
- posture
- asset management
- access control
- monitoring
- detection
- incident response

This project does not claim to solve every AI security problem. It shows a practical starting point for managing AI agents before they become another unmanaged system nobody wants to be responsible for.

## Author

Elton White

CIT481 Capstone Project
