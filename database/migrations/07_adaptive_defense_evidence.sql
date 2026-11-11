-- ==============================================================================
-- SECURITY GUARD - Migration 07: Adaptive Defense Evidence & Risk Scoring
-- Advanced Defense: Hybrid Detection Evidence, Adaptive Risk & Multi-Decision Audit
-- ==============================================================================

DO $$
BEGIN
    -- 1. Extend request_logs with adaptive defense columns
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'request_id'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN request_id VARCHAR(128);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'risk_score'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN risk_score DOUBLE PRECISION DEFAULT 0;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'decision'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN decision VARCHAR(20) DEFAULT 'ALLOW';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'decision_reason'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN decision_reason TEXT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'rule_matches'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN rule_matches JSONB DEFAULT '[]'::jsonb;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'ml_anomaly_score'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN ml_anomaly_score DOUBLE PRECISION;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'request_logs' AND column_name = 'evidence'
    ) THEN
        ALTER TABLE request_logs ADD COLUMN evidence JSONB DEFAULT '{}'::jsonb;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_request_logs_request_id ON request_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_request_logs_decision ON request_logs(decision);

-- 2. Dedicated Table: detection_evidence (Clean, high-fidelity audit trail)
CREATE TABLE IF NOT EXISTS detection_evidence (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(128) NOT NULL,
    website_id VARCHAR(64) NOT NULL DEFAULT 'default_web_app',
    request_log_id INTEGER REFERENCES request_logs(id) ON DELETE SET NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    rule_matches JSONB DEFAULT '[]'::jsonb,
    rule_severity VARCHAR(20) DEFAULT 'NONE',
    ml_anomaly_score DOUBLE PRECISION,
    ml_threshold DOUBLE PRECISION,
    ml_mode VARCHAR(20) DEFAULT 'shadow',
    matched_features JSONB DEFAULT '[]'::jsonb,
    evidence JSONB DEFAULT '{}'::jsonb,
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    decision VARCHAR(20) NOT NULL DEFAULT 'ALLOW',
    decision_reason TEXT,
    processing_time_ms DOUBLE PRECISION DEFAULT 0.0,
    CONSTRAINT chk_decision CHECK (decision IN ('ALLOW', 'MONITOR', 'BLOCK'))
);

CREATE INDEX IF NOT EXISTS idx_detection_evidence_req_id ON detection_evidence(request_id);
CREATE INDEX IF NOT EXISTS idx_detection_evidence_website ON detection_evidence(website_id);
CREATE INDEX IF NOT EXISTS idx_detection_evidence_decision ON detection_evidence(decision);
CREATE INDEX IF NOT EXISTS idx_detection_evidence_time ON detection_evidence(timestamp DESC);

-- 3. Extend security_alerts with evidence link and adaptive risk fields
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'request_id'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN request_id VARCHAR(128);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'decision'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN decision VARCHAR(20) DEFAULT 'MONITOR';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'evidence'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN evidence JSONB DEFAULT '{}'::jsonb;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_alerts_request_id ON security_alerts(request_id);
