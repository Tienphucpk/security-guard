-- ==============================================================================
-- SECURITY GUARD - Initial Seed Data
-- ==============================================================================

-- Seed initial detection rules templates
INSERT INTO detection_rules (rule_code, name, category, severity, is_active, description, rule_config)
VALUES
    ('RULE-BF-001', 'High Frequency Failed Logins (Brute Force)', 'brute_force', 'high', TRUE, 'Phát hiện nhiều lần đăng nhập thất bại từ cùng một địa chỉ IP trong khoảng thời gian ngắn.', '{"threshold_failures": 5, "window_seconds": 60}'),
    ('RULE-SQLI-001', 'Basic SQL Injection Pattern in URL/Query', 'sqli', 'critical', TRUE, 'Phát hiện các từ khóa/ký tự SQL đặc thù như union, select, 1=1, or, -- trong query params.', '{"patterns": ["union select", "1=1", "'' or ''"] }'),
    ('RULE-XSS-001', 'Basic Cross-Site Scripting Pattern', 'xss', 'high', TRUE, 'Phát hiện thẻ <script> hoặc các handler onmouseover/onerror trong tham số request.', '{"patterns": ["<script>", "javascript:", "onerror="] }'),
    ('RULE-SCAN-001', 'Vulnerability Scanner User-Agent Detection', 'scanner', 'medium', TRUE, 'Phát hiện User-Agent đặc thù của các công cụ scan như sqlmap, nikto, dirbuster, nmap.', '{"signatures": ["sqlmap", "nikto", "dirbuster", "nmap"] }')
ON CONFLICT (rule_code) DO NOTHING;

-- Seed dummy test users (mật khẩu minh họa không dùng trong môi trường thật)
INSERT INTO users (username, email, password_hash, role)
VALUES
    ('admin', 'admin@securityguard.local', '$2b$12$placeholder_hash_for_testing_purposes', 'admin'),
    ('alice', 'alice@securityguard.local', '$2b$12$placeholder_hash_for_testing_purposes', 'user'),
    ('bob', 'bob@securityguard.local', '$2b$12$placeholder_hash_for_testing_purposes', 'user')
ON CONFLICT (username) DO NOTHING;
