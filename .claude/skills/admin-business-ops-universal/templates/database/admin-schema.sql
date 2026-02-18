/**
 * Admin & Business Operations - Database Schema
 * Complete schema for admin dashboard, analytics, affiliates, and promo codes
 */

-- Enable UUID extension (if not already enabled)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================
-- ANALYTICS EVENTS TABLE
-- Tracks all user actions for admin analytics
-- =============================================

CREATE TABLE IF NOT EXISTS analytics_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  event_data JSONB DEFAULT '{}'::jsonb,
  session_id TEXT,
  user_agent TEXT,
  ip_address INET,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_analytics_events_user ON analytics_events(user_id, created_at DESC);
CREATE INDEX idx_analytics_events_type ON analytics_events(event_type, created_at DESC);
CREATE INDEX idx_analytics_events_session ON analytics_events(session_id);

COMMENT ON TABLE analytics_events IS 'Tracks all user actions for admin analytics';

-- =============================================
-- API USAGE TRACKING
-- Tracks API calls for cost monitoring
-- =============================================

CREATE TABLE IF NOT EXISTS api_usage (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  response_time_ms INTEGER,
  tokens_used INTEGER DEFAULT 0,
  cost_cents INTEGER DEFAULT 0,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_api_usage_user ON api_usage(user_id, created_at DESC);
CREATE INDEX idx_api_usage_endpoint ON api_usage(endpoint, created_at DESC);
CREATE INDEX idx_api_usage_date ON api_usage(created_at DESC);

COMMENT ON TABLE api_usage IS 'Tracks API calls for cost monitoring';

-- =============================================
-- DAILY METRICS AGGREGATION
-- Aggregated daily statistics for fast queries
-- =============================================

CREATE TABLE IF NOT EXISTS daily_metrics (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  metric_date DATE NOT NULL UNIQUE,

  -- User metrics
  total_users INTEGER DEFAULT 0,
  new_users INTEGER DEFAULT 0,
  active_users INTEGER DEFAULT 0,

  -- Subscription metrics (customize tier names as needed)
  free_users INTEGER DEFAULT 0,
  pro_users INTEGER DEFAULT 0,
  premium_users INTEGER DEFAULT 0,

  -- Revenue metrics (in cents)
  revenue_cents INTEGER DEFAULT 0,
  mrr_cents INTEGER DEFAULT 0,

  -- Usage metrics (customize based on your app)
  total_actions INTEGER DEFAULT 0,
  total_ai_calls INTEGER DEFAULT 0,
  total_tokens_used BIGINT DEFAULT 0,

  -- Cost metrics (in cents)
  ai_cost_cents INTEGER DEFAULT 0,
  infrastructure_cost_cents INTEGER DEFAULT 0,

  -- Engagement metrics
  avg_session_duration_seconds INTEGER DEFAULT 0,

  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_daily_metrics_date ON daily_metrics(metric_date DESC);

COMMENT ON TABLE daily_metrics IS 'Aggregated daily statistics for fast queries';

-- =============================================
-- PROMO CODES TABLE
-- Tracks discount codes and special offers
-- =============================================

CREATE TABLE IF NOT EXISTS promo_codes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  code TEXT NOT NULL UNIQUE,
  description TEXT,
  discount_type TEXT CHECK (discount_type IN ('percentage', 'fixed_amount', 'trial_extension')),
  discount_value INTEGER NOT NULL, -- percentage (0-100) or cents
  applies_to TEXT[] DEFAULT ARRAY[]::TEXT[], -- which subscription tiers
  max_uses INTEGER,
  current_uses INTEGER DEFAULT 0,
  valid_from TIMESTAMPTZ DEFAULT NOW(),
  valid_until TIMESTAMPTZ,
  stripe_coupon_id TEXT,
  created_by UUID REFERENCES auth.users(id),
  metadata JSONB DEFAULT '{}'::jsonb,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_promo_codes_code ON promo_codes(code) WHERE is_active = TRUE;
CREATE INDEX idx_promo_codes_active ON promo_codes(is_active, valid_until);

COMMENT ON TABLE promo_codes IS 'Discount codes and special offers';

-- =============================================
-- PROMO CODE REDEMPTIONS
-- Tracks who used which promo codes
-- =============================================

CREATE TABLE IF NOT EXISTS promo_code_redemptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  promo_code_id UUID REFERENCES promo_codes(id) ON DELETE CASCADE,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  subscription_id TEXT, -- External subscription ID (e.g., Stripe)
  discount_amount_cents INTEGER,
  redeemed_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(promo_code_id, user_id)
);

CREATE INDEX idx_promo_redemptions_code ON promo_code_redemptions(promo_code_id);
CREATE INDEX idx_promo_redemptions_user ON promo_code_redemptions(user_id);

COMMENT ON TABLE promo_code_redemptions IS 'Tracks who used which promo codes';

-- =============================================
-- AFFILIATES TABLE
-- Tracks affiliate partners and their performance
-- =============================================

CREATE TABLE IF NOT EXISTS affiliates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  affiliate_code TEXT NOT NULL UNIQUE,
  commission_tier INTEGER DEFAULT 1 CHECK (commission_tier IN (1, 2, 3)),
  commission_rate INTEGER DEFAULT 30, -- percentage
  total_referrals INTEGER DEFAULT 0,
  total_revenue_cents INTEGER DEFAULT 0,
  total_commission_cents INTEGER DEFAULT 0,
  payout_method TEXT,
  payout_details JSONB DEFAULT '{}'::jsonb,
  metadata JSONB DEFAULT '{}'::jsonb,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_affiliates_code ON affiliates(affiliate_code) WHERE is_active = TRUE;
CREATE INDEX idx_affiliates_user ON affiliates(user_id);
CREATE INDEX idx_affiliates_revenue ON affiliates(total_revenue_cents DESC);

COMMENT ON TABLE affiliates IS 'Affiliate program participants and their performance';

-- =============================================
-- AFFILIATE REFERRALS
-- Tracks individual affiliate-driven signups
-- =============================================

CREATE TABLE IF NOT EXISTS affiliate_referrals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  affiliate_id UUID REFERENCES affiliates(id) ON DELETE CASCADE,
  referred_user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  subscription_id TEXT, -- External subscription ID
  revenue_cents INTEGER DEFAULT 0,
  commission_cents INTEGER DEFAULT 0,
  commission_paid BOOLEAN DEFAULT FALSE,
  referred_at TIMESTAMPTZ DEFAULT NOW(),
  converted_at TIMESTAMPTZ,
  UNIQUE(affiliate_id, referred_user_id)
);

CREATE INDEX idx_affiliate_referrals_affiliate ON affiliate_referrals(affiliate_id, referred_at DESC);
CREATE INDEX idx_affiliate_referrals_user ON affiliate_referrals(referred_user_id);
CREATE INDEX idx_affiliate_referrals_unpaid ON affiliate_referrals(commission_paid) WHERE commission_paid = FALSE;

COMMENT ON TABLE affiliate_referrals IS 'Individual affiliate-driven signups and conversions';

-- =============================================
-- ADMIN USERS TABLE
-- Tracks admin permissions and roles
-- =============================================

CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
  role TEXT CHECK (role IN ('super_admin', 'admin', 'analyst')) DEFAULT 'analyst',
  permissions JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_admin_users_user ON admin_users(user_id);

COMMENT ON TABLE admin_users IS 'Admin permissions and roles';

-- =============================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Only admins can access analytics data
-- =============================================

ALTER TABLE analytics_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE daily_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE promo_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE promo_code_redemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE affiliates ENABLE ROW LEVEL SECURITY;
ALTER TABLE affiliate_referrals ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

-- Admin-only read access for analytics
CREATE POLICY "Admins can view analytics events"
  ON analytics_events FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE admin_users.user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can view API usage"
  ON api_usage FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE admin_users.user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can view daily metrics"
  ON daily_metrics FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE admin_users.user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage promo codes"
  ON promo_codes FOR ALL
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE admin_users.user_id = auth.uid()
    )
  );

-- Users can view their own affiliate data, admins can view all
CREATE POLICY "Users can view own affiliate data"
  ON affiliates FOR SELECT
  TO authenticated
  USING (
    user_id = auth.uid() OR
    EXISTS (
      SELECT 1 FROM admin_users WHERE admin_users.user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage affiliates"
  ON affiliates FOR ALL
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE admin_users.user_id = auth.uid()
    )
  );

-- =============================================
-- HELPER FUNCTIONS
-- =============================================

-- Function to check if user is admin
CREATE OR REPLACE FUNCTION is_admin(check_user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM admin_users
    WHERE user_id = check_user_id
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to log analytics event
CREATE OR REPLACE FUNCTION log_analytics_event(
  p_user_id UUID,
  p_event_type TEXT,
  p_event_data JSONB DEFAULT '{}'::jsonb,
  p_session_id TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_event_id UUID;
BEGIN
  INSERT INTO analytics_events (user_id, event_type, event_data, session_id)
  VALUES (p_user_id, p_event_type, p_event_data, p_session_id)
  RETURNING id INTO v_event_id;

  RETURN v_event_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to update daily metrics (run this via cron job or daily)
CREATE OR REPLACE FUNCTION update_daily_metrics()
RETURNS VOID AS $$
DECLARE
  v_today DATE := CURRENT_DATE;
BEGIN
  -- Customize this based on your app's tables and metrics
  INSERT INTO daily_metrics (
    metric_date,
    total_users,
    new_users,
    active_users,
    total_actions
  )
  SELECT
    v_today,
    (SELECT COUNT(*) FROM auth.users),
    (SELECT COUNT(*) FROM auth.users WHERE DATE(created_at) = v_today),
    (SELECT COUNT(DISTINCT user_id) FROM analytics_events WHERE DATE(created_at) = v_today),
    (SELECT COUNT(*) FROM analytics_events WHERE DATE(created_at) = v_today)
  ON CONFLICT (metric_date)
  DO UPDATE SET
    total_users = EXCLUDED.total_users,
    new_users = EXCLUDED.new_users,
    active_users = EXCLUDED.active_users,
    total_actions = EXCLUDED.total_actions,
    updated_at = NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to update affiliate totals after referral
CREATE OR REPLACE FUNCTION update_affiliate_totals()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE affiliates
  SET
    total_referrals = (SELECT COUNT(*) FROM affiliate_referrals WHERE affiliate_id = NEW.affiliate_id),
    total_revenue_cents = (SELECT COALESCE(SUM(revenue_cents), 0) FROM affiliate_referrals WHERE affiliate_id = NEW.affiliate_id),
    total_commission_cents = (SELECT COALESCE(SUM(commission_cents), 0) FROM affiliate_referrals WHERE affiliate_id = NEW.affiliate_id),
    updated_at = NOW()
  WHERE id = NEW.affiliate_id;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_affiliate_totals
  AFTER INSERT OR UPDATE ON affiliate_referrals
  FOR EACH ROW
  EXECUTE FUNCTION update_affiliate_totals();

-- Function to increment promo code usage
CREATE OR REPLACE FUNCTION increment_promo_usage()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE promo_codes
  SET current_uses = current_uses + 1,
      updated_at = NOW()
  WHERE id = NEW.promo_code_id;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_increment_promo_usage
  AFTER INSERT ON promo_code_redemptions
  FOR EACH ROW
  EXECUTE FUNCTION increment_promo_usage();

-- =============================================
-- INITIAL DATA
-- =============================================

-- Create first admin user (replace with your user ID)
-- INSERT INTO admin_users (user_id, role, permissions)
-- VALUES (
--   'YOUR_USER_ID_HERE',
--   'super_admin',
--   '{"manage_users": true, "manage_affiliates": true, "manage_promo_codes": true}'::jsonb
-- );
