-- Firebase Authentication Sync Schema
-- This schema syncs Firebase users with your PostgreSQL database
-- Compatible with Supabase, PostgreSQL, and other Postgres-based systems

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- USERS TABLE
-- Stores Firebase user data synced to PostgreSQL
-- =============================================================================

CREATE TABLE users (
  -- Primary key (your internal user ID)
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

  -- Firebase UID (unique identifier from Firebase Auth)
  firebase_uid TEXT UNIQUE NOT NULL,

  -- User profile information
  email TEXT UNIQUE,
  email_verified BOOLEAN DEFAULT FALSE,
  phone_number TEXT,
  phone_verified BOOLEAN DEFAULT FALSE,
  display_name TEXT,
  photo_url TEXT,

  -- Authentication metadata
  provider_id TEXT, -- 'password', 'google.com', 'apple.com', 'facebook.com', etc.
  last_sign_in_at TIMESTAMPTZ,

  -- Custom claims (stored as JSONB for flexibility)
  custom_claims JSONB DEFAULT '{}'::JSONB,

  -- Application-specific fields
  role TEXT DEFAULT 'user', -- 'user', 'admin', 'moderator', etc.
  status TEXT DEFAULT 'active', -- 'active', 'suspended', 'deleted'
  subscription_tier TEXT DEFAULT 'free', -- 'free', 'pro', 'premium'
  subscription_status TEXT, -- 'active', 'past_due', 'canceled', 'trialing'
  subscription_current_period_end TIMESTAMPTZ,

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);

-- Indexes for performance
CREATE INDEX idx_users_firebase_uid ON users(firebase_uid);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone_number ON users(phone_number);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_subscription_tier ON users(subscription_tier);
CREATE INDEX idx_users_created_at ON users(created_at DESC);

-- =============================================================================
-- USER PROFILES TABLE (OPTIONAL)
-- Extended user profile information separate from auth data
-- =============================================================================

CREATE TABLE user_profiles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Profile details
  first_name TEXT,
  last_name TEXT,
  bio TEXT,
  avatar_url TEXT,
  cover_photo_url TEXT,

  -- Contact information
  website TEXT,
  location TEXT,
  timezone TEXT,

  -- Preferences (stored as JSONB)
  preferences JSONB DEFAULT '{
    "notifications": {
      "email": true,
      "push": true,
      "sms": false
    },
    "theme": "light",
    "language": "en"
  }'::JSONB,

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(user_id)
);

CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);

-- =============================================================================
-- FIREBASE AUTH PROVIDERS TABLE
-- Tracks all auth providers linked to a user (email, Google, Apple, etc.)
-- =============================================================================

CREATE TABLE user_auth_providers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Provider information
  provider_id TEXT NOT NULL, -- 'password', 'google.com', 'apple.com', etc.
  provider_uid TEXT NOT NULL, -- UID from the provider

  -- Provider-specific data
  provider_data JSONB DEFAULT '{}'::JSONB, -- Store provider-specific info

  -- Timestamps
  linked_at TIMESTAMPTZ DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,

  UNIQUE(user_id, provider_id),
  UNIQUE(provider_id, provider_uid)
);

CREATE INDEX idx_user_auth_providers_user_id ON user_auth_providers(user_id);
CREATE INDEX idx_user_auth_providers_provider ON user_auth_providers(provider_id);

-- =============================================================================
-- USER SESSIONS TABLE
-- Track active Firebase sessions for security and analytics
-- =============================================================================

CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Session information
  firebase_session_id TEXT,
  device_id TEXT,
  device_name TEXT,
  device_type TEXT, -- 'web', 'ios', 'android'
  browser TEXT,
  os TEXT,
  ip_address INET,
  user_agent TEXT,

  -- Location data (optional)
  country TEXT,
  city TEXT,
  latitude DECIMAL(10, 8),
  longitude DECIMAL(11, 8),

  -- Session lifecycle
  last_active_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_last_active ON user_sessions(last_active_at DESC);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

-- =============================================================================
-- AUDIT LOG TABLE
-- Track all authentication events for security and compliance
-- =============================================================================

CREATE TABLE auth_audit_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  firebase_uid TEXT,

  -- Event information
  event_type TEXT NOT NULL, -- 'login', 'logout', 'signup', 'password_reset', 'email_verify', 'mfa_enable', etc.
  event_status TEXT NOT NULL, -- 'success', 'failure', 'attempted'
  provider_id TEXT, -- Which provider was used

  -- Request metadata
  ip_address INET,
  user_agent TEXT,
  device_type TEXT,
  location TEXT,

  -- Additional context
  metadata JSONB DEFAULT '{}'::JSONB,
  error_message TEXT,

  -- Timestamp
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_log_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_auth_audit_log_firebase_uid ON auth_audit_log(firebase_uid);
CREATE INDEX idx_auth_audit_log_event_type ON auth_audit_log(event_type);
CREATE INDEX idx_auth_audit_log_created_at ON auth_audit_log(created_at DESC);

-- =============================================================================
-- TRIGGERS
-- Auto-update timestamps
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER user_profiles_updated_at
  BEFORE UPDATE ON user_profiles
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create or update user from Firebase token
CREATE OR REPLACE FUNCTION upsert_firebase_user(
  p_firebase_uid TEXT,
  p_email TEXT,
  p_email_verified BOOLEAN,
  p_phone_number TEXT,
  p_display_name TEXT,
  p_photo_url TEXT,
  p_provider_id TEXT
)
RETURNS UUID AS $$
DECLARE
  v_user_id UUID;
BEGIN
  -- Insert or update user
  INSERT INTO users (
    firebase_uid,
    email,
    email_verified,
    phone_number,
    display_name,
    photo_url,
    provider_id,
    last_sign_in_at
  )
  VALUES (
    p_firebase_uid,
    p_email,
    p_email_verified,
    p_phone_number,
    p_display_name,
    p_photo_url,
    p_provider_id,
    NOW()
  )
  ON CONFLICT (firebase_uid)
  DO UPDATE SET
    email = COALESCE(EXCLUDED.email, users.email),
    email_verified = EXCLUDED.email_verified,
    phone_number = COALESCE(EXCLUDED.phone_number, users.phone_number),
    display_name = COALESCE(EXCLUDED.display_name, users.display_name),
    photo_url = COALESCE(EXCLUDED.photo_url, users.photo_url),
    provider_id = EXCLUDED.provider_id,
    last_sign_in_at = NOW(),
    updated_at = NOW()
  RETURNING id INTO v_user_id;

  -- Create user profile if it doesn't exist
  INSERT INTO user_profiles (user_id)
  VALUES (v_user_id)
  ON CONFLICT (user_id) DO NOTHING;

  RETURN v_user_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get user by Firebase UID
CREATE OR REPLACE FUNCTION get_user_by_firebase_uid(p_firebase_uid TEXT)
RETURNS TABLE (
  id UUID,
  firebase_uid TEXT,
  email TEXT,
  email_verified BOOLEAN,
  phone_number TEXT,
  display_name TEXT,
  photo_url TEXT,
  role TEXT,
  status TEXT,
  subscription_tier TEXT,
  custom_claims JSONB
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    u.id,
    u.firebase_uid,
    u.email,
    u.email_verified,
    u.phone_number,
    u.display_name,
    u.photo_url,
    u.role,
    u.status,
    u.subscription_tier,
    u.custom_claims
  FROM users u
  WHERE u.firebase_uid = p_firebase_uid
    AND u.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- Function to update user custom claims (roles, permissions)
CREATE OR REPLACE FUNCTION update_user_custom_claims(
  p_user_id UUID,
  p_claims JSONB
)
RETURNS BOOLEAN AS $$
BEGIN
  UPDATE users
  SET
    custom_claims = p_claims,
    updated_at = NOW()
  WHERE id = p_user_id;

  RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Function to revoke all user sessions
CREATE OR REPLACE FUNCTION revoke_user_sessions(p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE user_sessions
  SET revoked_at = NOW()
  WHERE user_id = p_user_id
    AND revoked_at IS NULL
    AND (expires_at IS NULL OR expires_at > NOW());

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
  v_count INTEGER;
BEGIN
  DELETE FROM user_sessions
  WHERE expires_at < NOW() - INTERVAL '30 days';

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) - For Supabase
-- Enable if using Supabase or need RLS
-- =============================================================================

-- Uncomment below if using Supabase:

-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE user_auth_providers ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;

-- Users can read their own data
-- CREATE POLICY "Users can view own data"
--   ON users FOR SELECT
--   TO authenticated
--   USING (firebase_uid = auth.uid());

-- Users can update their own profile
-- CREATE POLICY "Users can update own profile"
--   ON users FOR UPDATE
--   TO authenticated
--   USING (firebase_uid = auth.uid());

-- Users can view their own profile
-- CREATE POLICY "Users can view own profile"
--   ON user_profiles FOR SELECT
--   TO authenticated
--   USING (user_id IN (SELECT id FROM users WHERE firebase_uid = auth.uid()));

-- Users can update their own profile
-- CREATE POLICY "Users can update own profile"
--   ON user_profiles FOR UPDATE
--   TO authenticated
--   USING (user_id IN (SELECT id FROM users WHERE firebase_uid = auth.uid()));

-- =============================================================================
-- SAMPLE DATA (OPTIONAL - Remove in production)
-- =============================================================================

-- Example: Insert a test user
-- INSERT INTO users (firebase_uid, email, email_verified, display_name, role)
-- VALUES (
--   'test-firebase-uid-123',
--   'test@example.com',
--   true,
--   'Test User',
--   'user'
-- );

-- =============================================================================
-- MAINTENANCE TASKS
-- =============================================================================

-- Run periodically to clean up old sessions (e.g., via cron job)
-- SELECT cleanup_expired_sessions();

-- Example: Create a pg_cron job (if pg_cron extension is available)
-- SELECT cron.schedule(
--   'cleanup-expired-sessions',
--   '0 2 * * *', -- Run at 2 AM daily
--   'SELECT cleanup_expired_sessions();'
-- );
