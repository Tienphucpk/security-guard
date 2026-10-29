-- ==============================================================================
-- SECURITY GUARD - Request Logs Seed Data (Phase 2 Testing)
-- Provides baseline traffic data (normal requests, 404, 400, 500)
-- ==============================================================================

INSERT INTO request_logs (timestamp, ip, method, url, status_code, user_agent, response_time_ms)
VALUES
    -- Normal browsing traffic
    (NOW() - INTERVAL '15 minutes', '192.168.1.100', 'GET', '/', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 15.20),
    (NOW() - INTERVAL '14 minutes', '192.168.1.100', 'GET', '/login', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 8.50),
    (NOW() - INTERVAL '13 minutes', '192.168.1.100', 'POST', '/login', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 32.10),
    (NOW() - INTERVAL '12 minutes', '192.168.1.100', 'GET', '/dashboard', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 12.40),
    (NOW() - INTERVAL '11 minutes', '192.168.1.100', 'GET', '/search?q=security', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 18.90),

    -- Another user traffic
    (NOW() - INTERVAL '10 minutes', '192.168.1.105', 'GET', '/', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 14.10),
    (NOW() - INTERVAL '9 minutes', '192.168.1.105', 'GET', '/profile', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 10.80),

    -- Client errors (404 Not Found)
    (NOW() - INTERVAL '8 minutes', '10.0.0.15', 'GET', '/unknown-endpoint', 404, 'Mozilla/5.0 (X11; Linux x86_64)', 4.20),
    (NOW() - INTERVAL '7 minutes', '10.0.0.15', 'GET', '/favicon.ico', 404, 'Mozilla/5.0 (X11; Linux x86_64)', 2.10),

    -- Client error (400 Bad Request)
    (NOW() - INTERVAL '6 minutes', '10.0.0.22', 'POST', '/login', 400, 'python-requests/2.31.0', 6.40),

    -- Server error simulation (500 Internal Server Error)
    (NOW() - INTERVAL '5 minutes', '127.0.0.1', 'GET', '/api/test-error', 500, 'curl/8.4.0', 45.00)
ON CONFLICT DO NOTHING;
