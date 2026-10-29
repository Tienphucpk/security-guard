-- ==============================================================================
-- SECURITY GUARD - Migration 03: Add updated_at and indexes to security_alerts
-- Phase 4: Alert Management & Real-time Monitoring
-- ==============================================================================

DO $$
BEGIN
    -- 1. Add updated_at column to security_alerts if not exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'security_alerts' AND column_name = 'updated_at'
    ) THEN
        ALTER TABLE security_alerts ADD COLUMN updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
    END IF;
END $$;

-- 2. Create optimized indexes for Alert Management queries
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_updated_at ON security_alerts(updated_at);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON security_alerts(alert_type);
