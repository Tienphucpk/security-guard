-- ==============================================================================
-- SECURITY GUARD - Migration 08: Real Docker Security Labs Registration
-- Integration of OWASP Juice Shop, DVWA, OWASP WebGoat, and OWASP WebWolf
-- ==============================================================================

DO $$
BEGIN
    -- 1. Insert or update the 4 primary Docker web security lab targets
    INSERT INTO monitored_websites (
        website_id,
        name,
        upstream_url,
        domain,
        integration_method,
        monitoring_mode,
        is_active,
        is_external,
        health_status,
        health_diagnostic,
        description
    ) VALUES 
        (
            'owasp_juice_shop',
            'OWASP Juice Shop',
            'http://127.0.0.1:4101',
            'localhost:4101',
            'REVERSE_PROXY',
            'MONITOR_ONLY',
            TRUE,
            FALSE,
            'HEALTHY',
            'Connected to local Docker container on port 4101',
            'Modern vulnerable web application (Node.js/Angular/SQLite) for testing OWASP Top 10 vulnerabilities'
        ),
        (
            'dvwa',
            'Damn Vulnerable Web Application (DVWA)',
            'http://127.0.0.1:4102',
            'localhost:4102',
            'REVERSE_PROXY',
            'MONITOR_ONLY',
            TRUE,
            FALSE,
            'HEALTHY',
            'Connected to local Docker container on port 4102',
            'Classic PHP/MySQL security testing target for SQLi, XSS, Brute Force, and Command Injection'
        ),
        (
            'owasp_webgoat',
            'OWASP WebGoat',
            'http://127.0.0.1:4103/WebGoat',
            'localhost:4103',
            'REVERSE_PROXY',
            'MONITOR_ONLY',
            TRUE,
            FALSE,
            'HEALTHY',
            'Connected to local Docker container on port 4103 at subpath /WebGoat',
            'Deliberately insecure Java/Spring web application for security lessons and training'
        ),
        (
            'owasp_webwolf',
            'OWASP WebWolf',
            'http://127.0.0.1:9091/WebWolf',
            'localhost:9091',
            'REVERSE_PROXY',
            'MONITOR_ONLY',
            TRUE,
            FALSE,
            'HEALTHY',
            'Connected to local Docker container on port 9091 at subpath /WebWolf',
            'Companion tool for OWASP WebGoat testing callbacks, tokens, and out-of-band SSRF attacks'
        )
    ON CONFLICT (website_id) DO UPDATE SET
        name = EXCLUDED.name,
        upstream_url = EXCLUDED.upstream_url,
        domain = EXCLUDED.domain,
        integration_method = EXCLUDED.integration_method,
        description = EXCLUDED.description,
        is_active = TRUE,
        updated_at = CURRENT_TIMESTAMP;

    -- 2. Mark legacy demo sites clearly in descriptions
    UPDATE monitored_websites 
    SET description = 'Legacy Demo - Node.js Express E-Commerce & Blog application'
    WHERE website_id = 'site_demo_node';

    UPDATE monitored_websites 
    SET description = 'Legacy Demo - Python FastAPI Corporate Directory & Portal service'
    WHERE website_id = 'site_demo_python';

END $$;
