-- ==============================================================================
-- SECURITY GUARD - Migration 09: Clean Up Demo Websites & Test Artifacts
-- Removes legacy simulated demo sites, debug sites, and automated test data.
-- Retains exclusively the genuine Docker Web Security Labs:
-- 1. OWASP Juice Shop (owasp_juice_shop)
-- 2. DVWA (dvwa)
-- 3. OWASP WebGoat (owasp_webgoat)
-- 4. OWASP WebWolf (owasp_webwolf)
-- ==============================================================================

DO $$
BEGIN
    -- 1. Remove security alerts associated with legacy demos or test runs
    DELETE FROM security_alerts
    WHERE website_id IN ('site_demo_node', 'site_demo_python', 'site_debug_test')
       OR website_id LIKE 'site_lab_%'
       OR website_id LIKE 'site_ext_%'
       OR website_id LIKE 'site_test_%'
       OR target_url LIKE '%phase5_marker%'
       OR target_url LIKE '%unit_test%'
       OR target_url LIKE '%resilience%'
       OR target_url LIKE '%demo_phase%';

    -- 2. Remove request logs associated with legacy demos or test runs
    DELETE FROM request_logs
    WHERE website_id IN ('site_demo_node', 'site_demo_python', 'site_debug_test')
       OR website_id LIKE 'site_lab_%'
       OR website_id LIKE 'site_ext_%'
       OR website_id LIKE 'site_test_%'
       OR url LIKE '%phase5_marker%'
       OR url LIKE '%unit_test%'
       OR url LIKE '%resilience%'
       OR url LIKE '%demo_phase%';

    -- 3. Remove audits and detection evidence for legacy demos or test runs
    DELETE FROM enforcement_audit_logs
    WHERE website_id IN ('site_demo_node', 'site_demo_python', 'site_debug_test')
       OR website_id LIKE 'site_lab_%'
       OR website_id LIKE 'site_ext_%'
       OR website_id LIKE 'site_test_%';

    DELETE FROM detection_evidence
    WHERE website_id IN ('site_demo_node', 'site_demo_python', 'site_debug_test')
       OR website_id LIKE 'site_lab_%'
       OR website_id LIKE 'site_ext_%'
       OR website_id LIKE 'site_test_%';

    -- 4. Remove policies for legacy demos
    DELETE FROM enforcement_policies
    WHERE website_id IN ('site_demo_node', 'site_demo_python', 'site_debug_test')
       OR website_id LIKE 'site_lab_%'
       OR website_id LIKE 'site_ext_%'
       OR website_id LIKE 'site_test_%';

    -- 5. Remove legacy demo sites and auto-generated lab entries from monitored_websites
    DELETE FROM monitored_websites
    WHERE website_id IN ('site_demo_node', 'site_demo_python', 'site_debug_test')
       OR website_id LIKE 'site_lab_%'
       OR website_id LIKE 'site_ext_%'
       OR website_id LIKE 'site_test_%';

    -- 6. Ensure default monitoring mode for DVWA is MONITOR_ONLY for a fresh start
    UPDATE monitored_websites
    SET monitoring_mode = 'MONITOR_ONLY'
    WHERE website_id IN ('owasp_juice_shop', 'dvwa', 'owasp_webgoat', 'owasp_webwolf');

END $$;
