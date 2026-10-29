-- ==============================================================================
-- SECURITY GUARD - Detection Rules Seed (Phase 3)
-- Seed standard rules: BRUTE_FORCE, SCANNER, TRAFFIC, URL, SQLI, XSS
-- ==============================================================================

INSERT INTO detection_rules (rule_code, name, category, severity, is_active, description, rule_config)
VALUES
    (
        'RULE-BF-001',
        'Brute Force Login Detection',
        'brute_force',
        'high',
        TRUE,
        'Phát hiện >= 5 lần đăng nhập thất bại từ cùng một địa chỉ IP trong 5 phút.',
        '{"threshold": 5, "window_seconds": 300, "score": 70}'
    ),
    (
        'RULE-SCAN-001',
        'Security Scanner Detection',
        'scanner',
        'high',
        TRUE,
        'Phát hiện User-Agent hoặc dấu hiệu công cụ quét bảo mật tự động (sqlmap, nikto, nmap, dirbuster, gobuster, wpscan, masscan).',
        '{"signatures": ["sqlmap", "nikto", "nmap", "dirbuster", "gobuster", "wpscan", "masscan"], "score": 60}'
    ),
    (
        'RULE-TRAFFIC-001',
        'Abnormal Traffic Rate Detection',
        'abnormal_traffic',
        'medium',
        TRUE,
        'Phát hiện lưu lượng request bất thường vượt quá 100 requests / 60 giây từ một IP.',
        '{"threshold": 100, "window_seconds": 60, "score": 40}'
    ),
    (
        'RULE-URL-001',
        'Suspicious URL and Sensitive Probe Detection',
        'suspicious_url',
        'medium',
        TRUE,
        'Phát hiện truy vấn đến các file cấu hình nhạy cảm và endpoint quản trị (.env, .git, config.php, wp-login).',
        '{"patterns": ["/.env", "/.git/head", "/.git/config", "/wp-login.php", "/web.config", "/config.php", "/phpinfo.php", "/.ds_store", "/server-status"], "score": 35}'
    ),
    (
        'RULE-SQLI-001',
        'SQL Injection Pattern Detection',
        'sql_injection',
        'high',
        TRUE,
        'Phát hiện các mẫu SQL Injection (UNION SELECT, '' OR 1=1, INFORMATION_SCHEMA, SLEEP).',
        '{"patterns": ["union select", "union all select", "'' or ''1''=''1", "'' or 1=1", "information_schema.", "sleep(", "benchmark(", "waitfor delay"], "score": 80}'
    ),
    (
        'RULE-XSS-001',
        'Cross-Site Scripting (XSS) Detection',
        'xss',
        'high',
        TRUE,
        'Phát hiện mã kịch bản XSS độc hại (<script>, onerror=, javascript:, <iframe>, <svg>, document.cookie).',
        '{"patterns": ["<script>", "</script>", "onload=", "onerror=", "javascript:", "<iframe", "<svg", "document.cookie"], "score": 75}'
    )
ON CONFLICT (rule_code) DO NOTHING;
