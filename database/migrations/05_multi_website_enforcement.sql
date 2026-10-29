-- ==============================================================================
-- SECURITY GUARD - Migration 05: Multi-Website Monitoring & Active Enforcement
-- Phase 10: Multi-Website Architecture, Policy Decision & Enforcement Auditing
-- ==============================================================================

-- 1. Extend request_logs with website attribution and enforcement fields
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'website_id'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN website_id VARCHAR(64) DEFAULT 'default_web_app';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'blocked'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN blocked BOOLEAN DEFAULT FALSE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'block_reason'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN block_reason TEXT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_request_logs_website_id ON request_logs(website_id);

-- 2. Extend security_alerts with website attribution
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'website_id'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN website_id VARCHAR(64) DEFAULT 'default_web_app';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_alerts_website_id ON security_alerts(website_id);

-- 3. Table: monitored_websites (Website Registry)
CREATE TABLE IF NOT EXISTS monitored_websites (
    id SERIAL PRIMARY KEY,
    website_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    upstream_url VARCHAR(255) NOT NULL,
    monitoring_mode VARCHAR(20) DEFAULT 'MONITOR_ONLY', -- 'MONITOR_ONLY' or 'ENFORCE'
    is_active BOOLEAN DEFAULT TRUE,
    agent_secret_hash VARCHAR(255),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_monitoring_mode CHECK (monitoring_mode IN ('MONITOR_ONLY', 'ENFORCE'))
);

CREATE INDEX IF NOT EXISTS idx_monitored_websites_website_id ON monitored_websites(website_id);
CREATE INDEX IF NOT EXISTS idx_monitored_websites_is_active ON monitored_websites(is_active);

-- Seed default demo websites if not exists
INSERT INTO monitored_websites (website_id, name, upstream_url, monitoring_mode, is_active, description)
VALUES 
    ('site_demo_node', 'Node.js Demo Shop', 'http://127.0.0.1:4001', 'MONITOR_ONLY', TRUE, 'Node.js Express E-Commerce & Blog application'),
    ('site_demo_python', 'Python Demo Portal', 'http://127.0.0.1:4002', 'MONITOR_ONLY', TRUE, 'Python FastAPI Corporate Directory & Portal service')
ON CONFLICT (website_id) DO NOTHING;

-- 4. Table: enforcement_policies (Active Security Policies)
CREATE TABLE IF NOT EXISTS enforcement_policies (
    id SERIAL PRIMARY KEY,
    website_id VARCHAR(64) REFERENCES monitored_websites(website_id) ON DELETE CASCADE,
    policy_type VARCHAR(50) NOT NULL, -- 'IP_BLOCK', 'PATH_RESTRICT', 'SEVERITY_THRESHOLD', 'DETECTOR_BLOCK'
    match_criteria JSONB NOT NULL,
    action VARCHAR(20) DEFAULT 'BLOCK', -- 'BLOCK', 'ALLOW'
    reason TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_policy_action CHECK (action IN ('BLOCK', 'ALLOW'))
);

CREATE INDEX IF NOT EXISTS idx_enforcement_policies_website_id ON enforcement_policies(website_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_policies_is_active ON enforcement_policies(is_active);

-- 5. Table: enforcement_audit_logs (Tamper-evident enforcement audit trail)
CREATE TABLE IF NOT EXISTS enforcement_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    website_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(128),
    action VARCHAR(20) NOT NULL, -- 'BLOCKED', 'ALLOWED_MONITOR', 'ALLOWED_CLEAN'
    policy_id INTEGER REFERENCES enforcement_policies(id) ON DELETE SET NULL,
    reason TEXT NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    target_path TEXT NOT NULL,
    matched_rule VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_enforcement_audit_website_id ON enforcement_audit_logs(website_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_audit_client_ip ON enforcement_audit_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_enforcement_audit_action ON enforcement_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_enforcement_audit_created_at ON enforcement_audit_logs(created_at);
