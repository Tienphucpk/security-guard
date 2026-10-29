-- ==============================================================================
-- SECURITY GUARD - Migration 04: User Sessions & RBAC Roles Standardization
-- Phase 9: Authentication, Authorization & User Management
-- ==============================================================================

-- 1. Ensure role check constraint on users table
DO $$
BEGIN
    -- Update existing roles to uppercase standard
    UPDATE users SET role = 'ADMIN' WHERE role ILIKE 'admin';
    UPDATE users SET role = 'ANALYST' WHERE role ILIKE 'user' OR role ILIKE 'analyst';
END $$;

-- 2. Create user_sessions table for server-side PostgreSQL session store
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGSERIAL PRIMARY KEY,
    session_id VARCHAR(128) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip VARCHAR(45),
    user_agent TEXT
);

-- 3. Indexes for rapid session validation and cleanup
CREATE INDEX IF NOT EXISTS idx_user_sessions_session_id ON user_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
