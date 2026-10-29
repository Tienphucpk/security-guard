-- ==============================================================================
-- SECURITY GUARD - Migration 02: Add Alert Fields
-- Bổ sung các trường severity, method, request_log_id cho bảng security_alerts
-- ==============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'severity'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN severity VARCHAR(20) DEFAULT 'medium';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'method'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN method VARCHAR(10) DEFAULT 'GET';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'request_log_id'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN request_log_id BIGINT REFERENCES request_logs(id) ON DELETE SET NULL;
    END IF;
END $$;
