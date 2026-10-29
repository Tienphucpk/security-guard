-- ==============================================================================
-- SECURITY GUARD - Database Initialization Schema (PostgreSQL)
-- Đồ án: Bảo mật và An toàn thông tin
-- ==============================================================================

-- 1. Table: users (Tài khoản người dùng trong hệ thống thử nghiệm)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Table: request_logs (Ghi nhận metadata mọi HTTP request phục vụ phát hiện bất thường)
CREATE TABLE IF NOT EXISTS request_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ip VARCHAR(45) NOT NULL,
    method VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    user_agent TEXT,
    response_time_ms NUMERIC(10, 2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for request_logs query optimization
CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip);
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_status_code ON request_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_request_logs_method ON request_logs(method);
CREATE INDEX IF NOT EXISTS idx_request_logs_url ON request_logs(url);

-- 3. Table: detection_rules (Định nghĩa các luật phát hiện an ninh cơ bản)
CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    rule_code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- brute_force, sqli, xss, scanner, anomaly
    severity VARCHAR(20) DEFAULT 'medium', -- low, medium, high, critical
    is_active BOOLEAN DEFAULT TRUE,
    description TEXT,
    rule_config JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Table: security_alerts (Lưu trữ các cảnh báo bảo mật khi phát hiện hành vi khả nghi)
CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGSERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES detection_rules(id) ON DELETE SET NULL,
    request_log_id BIGINT REFERENCES request_logs(id) ON DELETE SET NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium',
    risk_score NUMERIC(5, 2) DEFAULT 0.00,
    source_ip VARCHAR(45) NOT NULL,
    method VARCHAR(10) DEFAULT 'GET',
    target_url TEXT,
    description TEXT NOT NULL,
    details JSONB,
    status VARCHAR(50) DEFAULT 'new', -- new, acknowledged, resolved, false_positive
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for security_alerts
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_updated_at ON security_alerts(updated_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON security_alerts(alert_type);
