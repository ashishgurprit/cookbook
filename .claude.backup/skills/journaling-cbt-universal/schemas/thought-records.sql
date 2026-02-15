-- ============================================================================
-- CBT Thought Records Database Schema
-- ============================================================================
-- Purpose: Core schema for traditional 7-column CBT thought records
-- Framework: PostgreSQL / Supabase compatible
-- Privacy: HIPAA-compliant design with encryption at rest
-- Version: 1.0
-- ============================================================================

-- ============================================================================
-- Table: thought_records
-- Description: Main thought record entries (7-column CBT format)
-- ============================================================================
CREATE TABLE thought_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Column 1: Situation
  situation TEXT NOT NULL, -- What happened? Where? When? Who was involved?
  situation_date TIMESTAMPTZ, -- When the situation occurred (may differ from created_at)

  -- Column 2: Automatic Thoughts
  automatic_thoughts TEXT NOT NULL, -- What went through your mind?
  hot_thought TEXT, -- The most distressing thought (often highlighted)

  -- Column 3: Emotions (stored as JSONB for flexibility)
  emotions JSONB NOT NULL DEFAULT '[]'::jsonb,
  -- Format: [{"emotion": "anxiety", "intensity": 85}, {"emotion": "fear", "intensity": 70}]

  -- Column 4: Physical Sensations
  physical_sensations TEXT[],
  -- Example: ["heart racing", "tight chest", "sweaty palms"]

  -- Column 5: Evidence For
  evidence_for TEXT, -- What supports the automatic thought?

  -- Column 6: Evidence Against
  evidence_against TEXT, -- What contradicts the automatic thought?

  -- Column 7: Balanced Thought
  balanced_thought TEXT, -- More realistic perspective

  -- Post-balancing emotions
  emotions_after JSONB DEFAULT '[]'::jsonb,
  -- Format: Same as emotions, but after challenging the thought

  -- Cognitive distortions identified
  distortions TEXT[], -- e.g., ["catastrophizing", "mind_reading"]

  -- Behavioral response
  behavior_taken TEXT, -- What did you do?
  alternative_behavior TEXT, -- What could you do differently?

  -- Metadata
  therapist_assigned BOOLEAN DEFAULT false, -- Was this assigned homework?
  session_id UUID REFERENCES therapy_sessions(id) ON DELETE SET NULL,
  tags TEXT[], -- For categorization
  is_archived BOOLEAN DEFAULT false,

  -- Sharing and collaboration
  shared_with_therapist BOOLEAN DEFAULT false,
  therapist_notes TEXT, -- Therapist can add notes
  therapist_reviewed_at TIMESTAMPTZ,

  CONSTRAINT valid_emotions CHECK (
    jsonb_typeof(emotions) = 'array'
  ),
  CONSTRAINT valid_emotions_after CHECK (
    jsonb_typeof(emotions_after) = 'array'
  )
);

-- ============================================================================
-- Table: emotion_ratings
-- Description: Normalized emotion tracking (alternative to JSONB for analytics)
-- ============================================================================
CREATE TABLE emotion_ratings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  thought_record_id UUID NOT NULL REFERENCES thought_records(id) ON DELETE CASCADE,
  emotion VARCHAR(50) NOT NULL, -- e.g., "anxiety", "sadness", "anger"
  intensity INTEGER NOT NULL CHECK (intensity >= 0 AND intensity <= 100),
  is_after_balancing BOOLEAN DEFAULT false, -- true if this is post-challenge rating
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  INDEX idx_emotion_ratings_record (thought_record_id),
  INDEX idx_emotion_ratings_emotion (emotion),
  INDEX idx_emotion_ratings_date (created_at)
);

-- ============================================================================
-- Table: cognitive_distortions
-- Description: Master list of cognitive distortions for lookup
-- ============================================================================
CREATE TABLE cognitive_distortions (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  slug VARCHAR(100) NOT NULL UNIQUE, -- e.g., "all_or_nothing"
  description TEXT NOT NULL,
  example TEXT,
  category VARCHAR(50), -- e.g., "thinking_errors", "emotional_reasoning"
  display_order INTEGER DEFAULT 0,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed data for common distortions
INSERT INTO cognitive_distortions (name, slug, description, example, display_order) VALUES
('All-or-Nothing Thinking', 'all_or_nothing', 'Seeing things in black-and-white categories without middle ground.', 'If I''m not perfect, I''m a total failure.', 1),
('Overgeneralization', 'overgeneralization', 'Seeing a single negative event as a never-ending pattern.', 'I failed this test. I always fail everything.', 2),
('Mental Filter', 'mental_filter', 'Focusing only on negatives and ignoring positives.', 'Remembering only the one criticism in a positive review.', 3),
('Disqualifying the Positive', 'disqualify_positive', 'Insisting positive experiences don''t count.', 'They''re just being nice, they don''t mean it.', 4),
('Jumping to Conclusions', 'jumping_conclusions', 'Making negative interpretations without evidence.', 'They didn''t respond, so they must be mad at me.', 5),
('Mind Reading', 'mind_reading', 'Assuming you know what others are thinking.', 'They think I''m boring.', 6),
('Fortune Telling', 'fortune_telling', 'Predicting negative outcomes with certainty.', 'I know I''ll fail the interview.', 7),
('Magnification/Catastrophizing', 'catastrophizing', 'Exaggerating the importance of problems.', 'One mistake will ruin my entire career.', 8),
('Minimization', 'minimization', 'Shrinking the importance of positive events.', 'Anyone could have done what I did.', 9),
('Emotional Reasoning', 'emotional_reasoning', 'Believing that feelings reflect reality.', 'I feel anxious, so there must be danger.', 10),
('Should Statements', 'should_statements', 'Using rigid rules that cause guilt when broken.', 'I should be able to handle this without help.', 11),
('Labeling', 'labeling', 'Assigning global negative labels to yourself or others.', 'I''m a loser / They''re an idiot.', 12),
('Personalization', 'personalization', 'Blaming yourself for events outside your control.', 'It''s my fault the team lost.', 13);

-- ============================================================================
-- Table: thought_record_distortions
-- Description: Many-to-many relationship between thought records and distortions
-- ============================================================================
CREATE TABLE thought_record_distortions (
  thought_record_id UUID NOT NULL REFERENCES thought_records(id) ON DELETE CASCADE,
  distortion_id INTEGER NOT NULL REFERENCES cognitive_distortions(id) ON DELETE CASCADE,
  confidence FLOAT CHECK (confidence >= 0 AND confidence <= 1), -- AI or user confidence
  identified_by VARCHAR(20) NOT NULL CHECK (identified_by IN ('user', 'ai', 'therapist')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  PRIMARY KEY (thought_record_id, distortion_id),
  INDEX idx_tr_distortions_record (thought_record_id),
  INDEX idx_tr_distortions_distortion (distortion_id)
);

-- ============================================================================
-- Table: therapy_sessions (if not already exists)
-- Description: Therapy sessions for linking thought records
-- ============================================================================
CREATE TABLE IF NOT EXISTS therapy_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  therapist_id UUID REFERENCES therapists(id) ON DELETE SET NULL,
  session_date TIMESTAMPTZ NOT NULL,
  session_type VARCHAR(50), -- e.g., "individual", "group", "intake"
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  INDEX idx_sessions_user (user_id),
  INDEX idx_sessions_date (session_date)
);

-- ============================================================================
-- Indexes for Performance
-- ============================================================================
CREATE INDEX idx_thought_records_user ON thought_records(user_id);
CREATE INDEX idx_thought_records_date ON thought_records(created_at);
CREATE INDEX idx_thought_records_situation_date ON thought_records(situation_date);
CREATE INDEX idx_thought_records_shared ON thought_records(shared_with_therapist) WHERE shared_with_therapist = true;
CREATE INDEX idx_thought_records_archived ON thought_records(is_archived) WHERE is_archived = false;

-- GIN index for JSONB emotions (for querying specific emotions)
CREATE INDEX idx_thought_records_emotions ON thought_records USING GIN (emotions);

-- ============================================================================
-- Row Level Security (RLS) - HIPAA Compliance
-- ============================================================================

ALTER TABLE thought_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE emotion_ratings ENABLE ROW LEVEL SECURITY;
ALTER TABLE thought_record_distortions ENABLE ROW LEVEL SECURITY;

-- Users can only access their own thought records
CREATE POLICY thought_records_user_policy ON thought_records
  FOR ALL
  USING (auth.uid() = user_id);

-- Therapists can view records shared with them
CREATE POLICY thought_records_therapist_policy ON thought_records
  FOR SELECT
  USING (
    shared_with_therapist = true
    AND EXISTS (
      SELECT 1 FROM therapist_patient_relationships
      WHERE patient_id = thought_records.user_id
      AND therapist_id = auth.uid()
      AND is_active = true
    )
  );

-- Emotion ratings follow thought record permissions
CREATE POLICY emotion_ratings_policy ON emotion_ratings
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM thought_records
      WHERE id = emotion_ratings.thought_record_id
    )
  );

-- ============================================================================
-- Triggers for updated_at
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER thought_records_updated_at
  BEFORE UPDATE ON thought_records
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Useful Views
-- ============================================================================

-- View: Recent thought records with emotion summary
CREATE VIEW thought_records_summary AS
SELECT
  tr.id,
  tr.user_id,
  tr.created_at,
  tr.situation_date,
  tr.situation,
  tr.automatic_thoughts,
  tr.balanced_thought,
  tr.emotions,
  tr.emotions_after,
  tr.distortions,
  tr.shared_with_therapist,
  -- Calculate emotion intensity change
  (
    SELECT AVG((e->>'intensity')::int)
    FROM jsonb_array_elements(tr.emotions) AS e
  ) AS avg_intensity_before,
  (
    SELECT AVG((e->>'intensity')::int)
    FROM jsonb_array_elements(tr.emotions_after) AS e
  ) AS avg_intensity_after
FROM thought_records tr
WHERE tr.is_archived = false;

-- ============================================================================
-- Analytics Function: Mood trends over time
-- ============================================================================
CREATE OR REPLACE FUNCTION get_mood_trends(
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
    DATE(tr.situation_date) AS date,
    AVG((e->>'intensity')::int) AS avg_intensity,
    COUNT(*)::INTEGER AS count
  FROM thought_records tr,
    jsonb_array_elements(tr.emotions) AS e
  WHERE tr.user_id = p_user_id
    AND tr.situation_date >= NOW() - (p_days || ' days')::INTERVAL
    AND (e->>'emotion')::text = p_emotion
  GROUP BY DATE(tr.situation_date)
  ORDER BY date;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Test Data (for development only - remove in production)
-- ============================================================================
-- Example: Insert a sample thought record
-- INSERT INTO thought_records (user_id, situation, automatic_thoughts, emotions, ...)
-- VALUES (...);
