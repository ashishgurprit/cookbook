-- ============================================================================
-- CBT Mood Tracking Database Schema
-- ============================================================================
-- Purpose: Daily mood logging, activity monitoring, behavioral activation
-- Framework: PostgreSQL / Supabase compatible
-- Privacy: HIPAA-compliant design
-- Version: 1.0
-- ============================================================================

-- ============================================================================
-- Table: mood_entries
-- Description: Daily mood check-ins with multiple emotion tracking
-- ============================================================================
CREATE TABLE mood_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  entry_date DATE NOT NULL,
  entry_time TIME,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Primary emotions with intensities
  emotions JSONB NOT NULL DEFAULT '[]'::jsonb,
  -- Format: [{"emotion": "happiness", "intensity": 65}, {"emotion": "anxiety", "intensity": 30}]

  -- Overall mood (simplified 1-10 scale)
  overall_mood INTEGER CHECK (overall_mood >= 1 AND overall_mood <= 10),

  -- Physical sensations
  physical_sensations TEXT[],
  energy_level INTEGER CHECK (energy_level >= 1 AND energy_level <= 10),
  sleep_quality INTEGER CHECK (sleep_quality >= 1 AND sleep_quality <= 10),
  sleep_hours NUMERIC(3, 1), -- e.g., 7.5 hours

  -- Context
  notes TEXT, -- Free-text reflection
  triggers TEXT, -- What influenced mood today
  coping_used TEXT[], -- Coping strategies used

  -- Flags
  crisis_level BOOLEAN DEFAULT false, -- Flag for therapist attention
  medication_taken BOOLEAN,

  -- Metadata
  is_archived BOOLEAN DEFAULT false,

  UNIQUE(user_id, entry_date, entry_time), -- One entry per user per datetime
  CONSTRAINT valid_emotions CHECK (
    jsonb_typeof(emotions) = 'array'
  )
);

-- ============================================================================
-- Table: activity_log
-- Description: Behavioral activation activity tracking
-- ============================================================================
CREATE TABLE activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  activity_date DATE NOT NULL,
  activity_time TIME,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Activity details
  activity_name VARCHAR(200) NOT NULL,
  activity_type VARCHAR(50), -- "pleasure", "mastery", "social", "physical", "values"
  duration_minutes INTEGER, -- How long was the activity

  -- Mood impact
  mood_before INTEGER CHECK (mood_before >= 1 AND mood_before <= 10),
  mood_after INTEGER CHECK (mood_after >= 1 AND mood_after <= 10),

  -- Specific emotions before/after (optional detailed tracking)
  emotions_before JSONB DEFAULT '[]'::jsonb,
  emotions_after JSONB DEFAULT '[]'::jsonb,

  -- Planning vs completion
  was_planned BOOLEAN DEFAULT false,
  completed BOOLEAN DEFAULT true,
  difficulty_rating INTEGER CHECK (difficulty_rating >= 1 AND difficulty_rating <= 10),

  -- Notes
  notes TEXT,
  obstacles TEXT, -- What made it hard to do
  accomplishment_notes TEXT, -- What did you achieve

  -- Linking
  mood_entry_id UUID REFERENCES mood_entries(id) ON DELETE SET NULL,

  INDEX idx_activity_log_user (user_id),
  INDEX idx_activity_log_date (activity_date),
  INDEX idx_activity_log_type (activity_type)
);

-- ============================================================================
-- Table: activity_schedule
-- Description: Planned activities for behavioral activation
-- ============================================================================
CREATE TABLE activity_schedule (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  therapist_id UUID REFERENCES therapists(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Schedule details
  planned_date DATE NOT NULL,
  planned_time TIME,
  activity_name VARCHAR(200) NOT NULL,
  activity_type VARCHAR(50),

  -- Motivation
  why_important TEXT, -- Connection to values
  expected_difficulty INTEGER CHECK (expected_difficulty >= 1 AND expected_difficulty <= 10),

  -- Obstacles and solutions
  potential_obstacles TEXT,
  solutions TEXT, -- How to overcome obstacles

  -- Completion tracking
  completed BOOLEAN DEFAULT false,
  completed_at TIMESTAMPTZ,
  actual_difficulty INTEGER CHECK (actual_difficulty >= 1 AND actual_difficulty <= 10),

  -- Link to actual activity
  activity_log_id UUID REFERENCES activity_log(id) ON DELETE SET NULL,

  -- Metadata
  is_homework BOOLEAN DEFAULT false, -- Therapist-assigned
  is_archived BOOLEAN DEFAULT false,

  INDEX idx_activity_schedule_user (user_id),
  INDEX idx_activity_schedule_date (planned_date),
  INDEX idx_activity_schedule_completed (completed)
);

-- ============================================================================
-- Table: emotion_definitions
-- Description: Master list of emotions for consistent tracking
-- ============================================================================
CREATE TABLE emotion_definitions (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) NOT NULL UNIQUE,
  slug VARCHAR(50) NOT NULL UNIQUE,
  category VARCHAR(50), -- "primary", "secondary"
  emoji VARCHAR(10),
  description TEXT,
  opposite_emotion_id INTEGER REFERENCES emotion_definitions(id),
  display_order INTEGER DEFAULT 0,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed data for common emotions
INSERT INTO emotion_definitions (name, slug, category, emoji, description, display_order) VALUES
-- Primary emotions
('Happiness', 'happiness', 'primary', '😊', 'Feeling joyful, content, or pleased', 1),
('Sadness', 'sadness', 'primary', '😢', 'Feeling down, low, or grief', 2),
('Anxiety', 'anxiety', 'primary', '😰', 'Feeling worried, nervous, or fearful', 3),
('Anger', 'anger', 'primary', '😠', 'Feeling frustrated, irritated, or enraged', 4),
('Shame', 'shame', 'primary', '😔', 'Feeling embarrassed, guilty, or inadequate', 5),
('Disgust', 'disgust', 'primary', '🤢', 'Feeling revolted or repelled', 6),

-- Secondary emotions
('Loneliness', 'loneliness', 'secondary', '😞', 'Feeling isolated or disconnected', 10),
('Hopelessness', 'hopelessness', 'secondary', '😔', 'Feeling without hope or optimism', 11),
('Excitement', 'excitement', 'secondary', '🤩', 'Feeling energized and enthusiastic', 12),
('Contentment', 'contentment', 'secondary', '😌', 'Feeling peaceful and satisfied', 13),
('Overwhelm', 'overwhelm', 'secondary', '😵', 'Feeling unable to cope with demands', 14),
('Pride', 'pride', 'secondary', '😊', 'Feeling accomplished or satisfied with oneself', 15),
('Fear', 'fear', 'secondary', '😨', 'Feeling threatened or in danger', 16),
('Jealousy', 'jealousy', 'secondary', '😒', 'Feeling envious of others', 17),
('Gratitude', 'gratitude', 'secondary', '🙏', 'Feeling thankful and appreciative', 18),
('Confusion', 'confusion', 'secondary', '😕', 'Feeling uncertain or unclear', 19);

-- ============================================================================
-- Table: physical_sensation_definitions
-- Description: Common physical sensations associated with emotions
-- ============================================================================
CREATE TABLE physical_sensation_definitions (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  slug VARCHAR(100) NOT NULL UNIQUE,
  category VARCHAR(50), -- "cardiovascular", "muscular", "respiratory", "gastrointestinal", "other"
  commonly_associated_with TEXT[], -- Common emotions, e.g., ["anxiety", "panic"]

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed data
INSERT INTO physical_sensation_definitions (name, slug, category, commonly_associated_with) VALUES
('Heart racing', 'heart_racing', 'cardiovascular', ARRAY['anxiety', 'panic', 'excitement']),
('Tightness in chest', 'chest_tightness', 'cardiovascular', ARRAY['anxiety', 'panic', 'sadness']),
('Stomach discomfort', 'stomach_discomfort', 'gastrointestinal', ARRAY['anxiety', 'disgust']),
('Nausea', 'nausea', 'gastrointestinal', ARRAY['anxiety', 'disgust', 'fear']),
('Muscle tension', 'muscle_tension', 'muscular', ARRAY['anxiety', 'anger', 'stress']),
('Headache', 'headache', 'other', ARRAY['stress', 'overwhelm', 'anger']),
('Fatigue', 'fatigue', 'other', ARRAY['sadness', 'depression', 'overwhelm']),
('Restlessness', 'restlessness', 'other', ARRAY['anxiety', 'anger']),
('Difficulty breathing', 'difficulty_breathing', 'respiratory', ARRAY['anxiety', 'panic']),
('Shallow breathing', 'shallow_breathing', 'respiratory', ARRAY['anxiety', 'stress']),
('Sweating', 'sweating', 'other', ARRAY['anxiety', 'fear', 'panic']),
('Trembling', 'trembling', 'muscular', ARRAY['anxiety', 'fear']),
('Warmth/flushing', 'warmth', 'cardiovascular', ARRAY['shame', 'anger', 'embarrassment']),
('Cold hands/feet', 'cold_extremities', 'cardiovascular', ARRAY['anxiety', 'fear']);

-- ============================================================================
-- Table: coping_strategies
-- Description: User's personalized coping strategy inventory
-- ============================================================================
CREATE TABLE coping_strategies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  strategy_name VARCHAR(200) NOT NULL,
  category VARCHAR(50), -- "distraction", "self_soothing", "social", "physical", "cognitive"
  description TEXT,

  -- Effectiveness tracking
  times_used INTEGER DEFAULT 0,
  avg_effectiveness NUMERIC(3, 2), -- 0.00 to 10.00

  -- Situations where helpful
  helpful_for TEXT[], -- e.g., ["anxiety", "overwhelm"]

  is_archived BOOLEAN DEFAULT false,

  UNIQUE(user_id, strategy_name)
);

-- ============================================================================
-- Indexes for Performance
-- ============================================================================
CREATE INDEX idx_mood_entries_user ON mood_entries(user_id);
CREATE INDEX idx_mood_entries_date ON mood_entries(entry_date);
CREATE INDEX idx_mood_entries_emotions ON mood_entries USING GIN (emotions);

CREATE INDEX idx_activity_log_user_date ON activity_log(user_id, activity_date);
CREATE INDEX idx_activity_schedule_user_date ON activity_schedule(user_id, planned_date);

-- ============================================================================
-- Row Level Security (RLS)
-- ============================================================================
ALTER TABLE mood_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_schedule ENABLE ROW LEVEL SECURITY;
ALTER TABLE coping_strategies ENABLE ROW LEVEL SECURITY;

-- Users can only access their own data
CREATE POLICY mood_entries_user_policy ON mood_entries
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY activity_log_user_policy ON activity_log
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY activity_schedule_user_policy ON activity_schedule
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY coping_strategies_user_policy ON coping_strategies
  FOR ALL
  USING (auth.uid() = user_id);

-- ============================================================================
-- Triggers
-- ============================================================================
CREATE TRIGGER mood_entries_updated_at
  BEFORE UPDATE ON mood_entries
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Views
-- ============================================================================

-- View: Weekly mood summary
CREATE VIEW weekly_mood_summary AS
SELECT
  user_id,
  DATE_TRUNC('week', entry_date) AS week_start,
  COUNT(*) AS entries_count,
  AVG(overall_mood) AS avg_mood,
  AVG(energy_level) AS avg_energy,
  AVG(sleep_quality) AS avg_sleep_quality,
  AVG(sleep_hours) AS avg_sleep_hours,
  SUM(CASE WHEN crisis_level THEN 1 ELSE 0 END) AS crisis_count
FROM mood_entries
WHERE is_archived = false
GROUP BY user_id, DATE_TRUNC('week', entry_date);

-- View: Activity effectiveness
CREATE VIEW activity_effectiveness AS
SELECT
  user_id,
  activity_type,
  COUNT(*) AS times_performed,
  AVG(mood_after - mood_before) AS avg_mood_improvement,
  AVG(difficulty_rating) AS avg_difficulty
FROM activity_log
WHERE completed = true AND mood_before IS NOT NULL AND mood_after IS NOT NULL
GROUP BY user_id, activity_type;

-- ============================================================================
-- Analytics Functions
-- ============================================================================

-- Function: Get mood trend for specific emotion
CREATE OR REPLACE FUNCTION get_emotion_trend(
  p_user_id UUID,
  p_emotion VARCHAR(50),
  p_days INTEGER DEFAULT 30
)
RETURNS TABLE (
  date DATE,
  avg_intensity NUMERIC,
  count INTEGER
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    me.entry_date AS date,
    AVG((e->>'intensity')::int)::NUMERIC AS avg_intensity,
    COUNT(*)::INTEGER AS count
  FROM mood_entries me,
    jsonb_array_elements(me.emotions) AS e
  WHERE me.user_id = p_user_id
    AND me.entry_date >= CURRENT_DATE - p_days
    AND (e->>'emotion')::text = p_emotion
  GROUP BY me.entry_date
  ORDER BY date;
END;
$$ LANGUAGE plpgsql;

-- Function: Calculate behavioral activation adherence
CREATE OR REPLACE FUNCTION get_ba_adherence(
  p_user_id UUID,
  p_weeks INTEGER DEFAULT 4
)
RETURNS TABLE (
  week_start DATE,
  planned_activities INTEGER,
  completed_activities INTEGER,
  adherence_rate NUMERIC
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    DATE_TRUNC('week', planned_date)::DATE AS week_start,
    COUNT(*)::INTEGER AS planned_activities,
    SUM(CASE WHEN completed THEN 1 ELSE 0 END)::INTEGER AS completed_activities,
    ROUND(
      (SUM(CASE WHEN completed THEN 1 ELSE 0 END)::NUMERIC / COUNT(*)) * 100,
      2
    ) AS adherence_rate
  FROM activity_schedule
  WHERE user_id = p_user_id
    AND planned_date >= CURRENT_DATE - (p_weeks * 7)
  GROUP BY DATE_TRUNC('week', planned_date)
  ORDER BY week_start;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Stored Procedure: Record mood entry with activity
-- ============================================================================
CREATE OR REPLACE FUNCTION record_daily_mood(
  p_user_id UUID,
  p_entry_date DATE,
  p_overall_mood INTEGER,
  p_emotions JSONB,
  p_energy_level INTEGER DEFAULT NULL,
  p_sleep_quality INTEGER DEFAULT NULL,
  p_notes TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
  v_mood_entry_id UUID;
BEGIN
  INSERT INTO mood_entries (
    user_id,
    entry_date,
    overall_mood,
    emotions,
    energy_level,
    sleep_quality,
    notes
  ) VALUES (
    p_user_id,
    p_entry_date,
    p_overall_mood,
    p_emotions,
    p_energy_level,
    p_sleep_quality,
    p_notes
  )
  ON CONFLICT (user_id, entry_date, entry_time)
  DO UPDATE SET
    overall_mood = EXCLUDED.overall_mood,
    emotions = EXCLUDED.emotions,
    energy_level = EXCLUDED.energy_level,
    sleep_quality = EXCLUDED.sleep_quality,
    notes = EXCLUDED.notes,
    updated_at = NOW()
  RETURNING id INTO v_mood_entry_id;

  RETURN v_mood_entry_id;
END;
$$ LANGUAGE plpgsql;
