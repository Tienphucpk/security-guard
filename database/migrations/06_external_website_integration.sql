-- ==============================================================================
-- SECURITY GUARD - Migration 06: External Website Integration & Live Monitoring
-- Phase 11: Integration Methods, Health Diagnostics, SSRF & Ingestion
-- ==============================================================================

DO $$
BEGIN
    -- 1. Allow upstream_url to be optional (for APPLICATION_AGENT / LOG_INGESTION)
    ALTER TABLE monitored_websites ALTER COLUMN upstream_url DROP NOT NULL;

    -- 2. Domain / Hostname
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'domain'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN domain VARCHAR(255);
    END IF;

    -- 3. Integration Method: REVERSE_PROXY, APPLICATION_AGENT, LOG_INGESTION
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'integration_method'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN integration_method VARCHAR(30) DEFAULT 'REVERSE_PROXY';
    END IF;

    -- 4. Health Status & Diagnostics
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'health_status'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN health_status VARCHAR(20) DEFAULT 'UNKNOWN';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'last_health_check'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN last_health_check TIMESTAMP WITH TIME ZONE;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'health_diagnostic'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN health_diagnostic TEXT;
    END IF;

    -- 5. Last Event Telemetry Timestamp
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'last_event_at'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN last_event_at TIMESTAMP WITH TIME ZONE;
    END IF;

    -- 6. External flag (true for user-registered external sites, false for internal demo sites)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'is_external'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN is_external BOOLEAN DEFAULT FALSE;
    END IF;

    -- 7. Encrypted Agent Secret (AES-256-GCM envelope for HMAC verification; never plaintext)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'monitored_websites' AND column_name = 'encrypted_agent_secret'
    ) THEN
        ALTER TABLE monitored_websites ADD COLUMN encrypted_agent_secret TEXT;
    END IF;
END $$;

-- Add check constraint for integration_method if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_integration_method'
    ) THEN
        ALTER TABLE monitored_websites 
        ADD CONSTRAINT chk_integration_method 
        CHECK (integration_method IN ('REVERSE_PROXY', 'APPLICATION_AGENT', 'LOG_INGESTION'));
    END IF;
END $$;

-- Populate domain for existing default demo sites if null
UPDATE monitored_websites 
SET domain = 'localhost:4001', integration_method = 'REVERSE_PROXY', health_status = 'HEALTHY', is_external = FALSE
WHERE website_id = 'site_demo_node' AND (domain IS NULL OR domain = '');

UPDATE monitored_websites 
SET domain = 'localhost:4002', integration_method = 'REVERSE_PROXY', health_status = 'HEALTHY', is_external = FALSE
WHERE website_id = 'site_demo_python' AND (domain IS NULL OR domain = '');

CREATE INDEX IF NOT EXISTS idx_monitored_websites_domain ON monitored_websites(domain);
CREATE INDEX IF NOT EXISTS idx_monitored_websites_method ON monitored_websites(integration_method);
