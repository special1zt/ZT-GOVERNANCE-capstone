-- init-db.sql
CREATE DATABASE IF NOT EXISTS posture_db;
CREATE DATABASE IF NOT EXISTS audit_log;

GRANT ALL PRIVILEGES ON posture_db.* TO 'security_admin'@'%';
GRANT ALL PRIVILEGES ON audit_log.* TO 'security_admin'@'%';
FLUSH PRIVILEGES;

USE posture_db;

CREATE TABLE IF NOT EXISTS agent_identity (
    agent_id VARCHAR(255) PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    owner_person VARCHAR(255),
    purpose TEXT,
    roles JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_device_ci_agent
        FOREIGN KEY (agent_id) REFERENCES agent_identity(agent_id)
        ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS device_health (
    device_id VARCHAR(255) PRIMARY KEY,
    status VARCHAR(50) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS resource (
    resource_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    sensitivity_tier VARCHAR(50) NOT NULL,
    route_prefix VARCHAR(255) NOT NULL,
    owner_team VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_policy (
    policy_id VARCHAR(255) PRIMARY KEY,
    sensitivity_tier VARCHAR(50) NOT NULL,
    required_roles JSON,
    required_posture VARCHAR(50) NOT NULL DEFAULT 'healthy',
    requires_change_approval BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);

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

INSERT INTO agent_identity
    (agent_id, display_name, owner_person, purpose, roles)
VALUES
    ('agent1', 'LLama Maverick', 'Autonomous Agent Lab',
     'Representative chat & task LLM agent.',
     JSON_ARRAY('agent_basic', 'agent_internal')),
    ('agent2', 'Pi Qwen', 'Autonomous Agent Lab',
     'Representative code assistant agent',
     JSON_ARRAY('agent_internal', 'agent_sensitive'))
ON DUPLICATE KEY UPDATE
    display_name = VALUES(display_name),
    owner_person = VALUES(owner_person),
    purpose = VALUES(purpose),
    roles = VALUES(roles);

INSERT INTO device_ci
    (device_id, agent_id, posture_status, risk_score, decoy_hit, denied_burst_count)
VALUES
    ('agent-dev-01', 'agent1', 'healthy', 10, FALSE, 0),
    ('agent-dev-02', 'agent2', 'healthy', 65, FALSE, 0)
ON DUPLICATE KEY UPDATE
    agent_id = VALUES(agent_id),
    risk_score = VALUES(risk_score);

INSERT INTO device_health (device_id, status)
VALUES
    ('agent-dev-01', 'healthy'),
    ('agent-dev-02', 'healthy')
ON DUPLICATE KEY UPDATE
    device_id = device_id;

INSERT INTO resource
    (resource_id, name, sensitivity_tier, route_prefix, owner_team)
VALUES
    ('public-status', 'Gateway Status', 'public', '/public', 'platform-operations'),
    ('internal-assets', 'Internal Asset Inventory', 'internal', '/internal/assets', 'security-engineering'),
    ('sensitive-admin', 'Privileged Response Actions', 'sensitive', '/sensitive/admin', 'security-engineering')
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    sensitivity_tier = VALUES(sensitivity_tier),
    route_prefix = VALUES(route_prefix),
    owner_team = VALUES(owner_team);

INSERT INTO access_policy
    (policy_id, sensitivity_tier, required_roles, required_posture, requires_change_approval)
VALUES
    ('policy-public', 'public', JSON_ARRAY(), 'healthy', FALSE),
    ('policy-internal', 'internal', JSON_ARRAY('agent_internal'), 'healthy', FALSE),
    ('policy-sensitive', 'sensitive', JSON_ARRAY('agent_sensitive'), 'healthy', TRUE)
ON DUPLICATE KEY UPDATE
    sensitivity_tier = VALUES(sensitivity_tier),
    required_roles = VALUES(required_roles),
    required_posture = VALUES(required_posture),
    requires_change_approval = VALUES(requires_change_approval);

USE audit_log;

CREATE TABLE IF NOT EXISTS access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp BIGINT,
    agent_id VARCHAR(255),
    route VARCHAR(255),
    decision VARCHAR(50),
    reason TEXT,
    posture VARCHAR(50)
);

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);
