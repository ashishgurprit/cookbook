-- ============================================================================
-- CBT Homework Assignments Database Schema
-- ============================================================================
-- Purpose: Therapist-assigned CBT exercises and tracking
-- Framework: PostgreSQL / Supabase compatible
-- Version: 1.0
-- ============================================================================

-- ============================================================================
-- Table: homework_assignments
-- Description: CBT homework assigned by therapist
-- ============================================================================
CREATE TABLE homework_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  therapist_id UUID REFERENCES therapists(id) ON DELETE SET NULL,
  session_id UUID REFERENCES therapy_sessions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Assignment details
  title VARCHAR(200) NOT NULL,
  description TEXT NOT NULL,
  homework_type VARCHAR(50) NOT NULL, -- "thought_record", "mood_log", "behavioral_activation", "exposure", "custom"

  -- Scheduling
  assigned_date DATE NOT NULL DEFAULT CURRENT_DATE,
  due_date DATE,
  frequency VARCHAR(50), -- "once", "daily", "weekly", "as_needed"

  -- Instructions
  instructions TEXT,
  resources JSONB, -- Links, files, reference materials
  -- Format: [{"type": "link", "url": "...", "title": "..."}, {"type": "file", "path": "..."}]

  -- Tracking
  status VARCHAR(50) DEFAULT 'assigned', -- "assigned", "in_progress", "completed", "overdue", "cancelled"
  completed_at TIMESTAMPTZ,
  completion_notes TEXT, -- Patient's notes on completion

  -- Therapist feedback
  therapist_reviewed BOOLEAN DEFAULT false,
  therapist_feedback TEXT,
  therapist_reviewed_at TIMESTAMPTZ,

  -- Metadata
  is_archived BOOLEAN DEFAULT false,
  reminders_enabled BOOLEAN DEFAULT true,

  INDEX idx_homework_user (user_id),
  INDEX idx_homework_therapist (therapist_id),
  INDEX idx_homework_status (status),
  INDEX idx_homework_due_date (due_date)
);

-- ============================================================================
-- Table: exposure_hierarchies
-- Description: Gradual exposure planning for anxiety treatment
-- ============================================================================
CREATE TABLE exposure_hierarchies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  therapist_id UUID REFERENCES therapists(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Hierarchy details
  fear_target VARCHAR(200) NOT NULL, -- What are we targeting? e.g., "Public speaking"
  description TEXT,

  -- Status
  is_active BOOLEAN DEFAULT true,
  completed_at TIMESTAMPTZ,

  INDEX idx_exposure_hierarchies_user (user_id),
  INDEX idx_exposure_hierarchies_active (is_active)
);

-- ============================================================================
-- Table: exposure_steps
-- Description: Individual steps in exposure hierarchy
-- ============================================================================
CREATE TABLE exposure_steps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hierarchy_id UUID NOT NULL REFERENCES exposure_hierarchies(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Step details
  situation TEXT NOT NULL, -- What is the exposure task?
  expected_anxiety INTEGER NOT NULL CHECK (expected_anxiety >= 0 AND expected_anxiety <= 100),
  step_order INTEGER NOT NULL, -- Position in hierarchy (lower = easier)

  -- Completion tracking
  status VARCHAR(50) DEFAULT 'not_started', -- "not_started", "in_progress", "completed"
  attempts INTEGER DEFAULT 0,

  INDEX idx_exposure_steps_hierarchy (hierarchy_id),
  INDEX idx_exposure_steps_order (step_order)
);

-- ============================================================================
-- Table: exposure_attempts
-- Description: Each exposure practice session
-- ============================================================================
CREATE TABLE exposure_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  step_id UUID NOT NULL REFERENCES exposure_steps(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  attempt_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Anxiety ratings
  anxiety_before INTEGER CHECK (anxiety_before >= 0 AND anxiety_before <= 100),
  anxiety_peak INTEGER CHECK (anxiety_peak >= 0 AND anxiety_peak <= 100),
  anxiety_after INTEGER CHECK (anxiety_after >= 0 AND anxiety_after <= 100),

  -- Duration
  duration_minutes INTEGER,

  -- Safety behaviors
  safety_behaviors_used TEXT[], -- What avoidance behaviors were used?
  safety_behaviors_notes TEXT,

  -- Learnings
  learning_notes TEXT, -- What did you discover?
  success_rating INTEGER CHECK (success_rating >= 1 AND success_rating <= 10),

  -- Metadata
  notes TEXT,

  INDEX idx_exposure_attempts_step (step_id),
  INDEX idx_exposure_attempts_date (attempt_date)
);

-- ============================================================================
-- Table: safety_behaviors
-- Description: Tracking avoidance/safety behaviors
-- ============================================================================
CREATE TABLE safety_behaviors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Behavior details
  behavior VARCHAR(200) NOT NULL,
  situation TEXT NOT NULL, -- When do you use this behavior?
  fear_addressed VARCHAR(200), -- What are you trying to prevent?

  -- Impact analysis
  short_term_effect TEXT, -- Does it reduce anxiety immediately?
  long_term_effect TEXT, -- Does it maintain the problem?

  -- Tracking
  times_identified INTEGER DEFAULT 0,
  is_target_for_change BOOLEAN DEFAULT false,

  UNIQUE(user_id, behavior)
);

-- ============================================================================
-- Table: core_beliefs
-- Description: Deep-seated beliefs identified in therapy
-- ============================================================================
CREATE TABLE core_beliefs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  therapist_id UUID REFERENCES therapists(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Belief details
  belief_statement TEXT NOT NULL,
  belief_type VARCHAR(50), -- "about_self", "about_others", "about_world"
  valence VARCHAR(50), -- "negative", "positive", "mixed"

  -- Strength tracking
  current_belief_strength INTEGER CHECK (current_belief_strength >= 0 AND current_belief_strength <= 100),

  -- Evidence work
  evidence_for TEXT,
  evidence_against TEXT,

  -- Alternative belief
  alternative_belief TEXT,
  alternative_strength INTEGER CHECK (alternative_strength >= 0 AND alternative_strength <= 100),

  -- Metadata
  is_active_target BOOLEAN DEFAULT true,
  last_reviewed TIMESTAMPTZ,

  INDEX idx_core_beliefs_user (user_id),
  INDEX idx_core_beliefs_type (belief_type)
);

-- ============================================================================
-- Table: values_assessment
-- Description: Personal values clarification for therapy
-- ============================================================================
CREATE TABLE values_assessment (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Value domains
  domain VARCHAR(50) NOT NULL, -- "relationships", "work", "health", "leisure", "spirituality", etc.
  importance INTEGER CHECK (importance >= 0 AND importance <= 10),
  current_satisfaction INTEGER CHECK (current_satisfaction >= 0 AND current_satisfaction <= 10),

  -- Details
  description TEXT, -- What does this value mean to you?
  goals TEXT, -- What goals align with this value?

  UNIQUE(user_id, domain),
  INDEX idx_values_user (user_id)
);

-- ============================================================================
-- Table: relapse_prevention_plan
-- Description: Warning signs and coping strategies for relapse prevention
-- ============================================================================
CREATE TABLE relapse_prevention_plan (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  therapist_id UUID REFERENCES therapists(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Warning signs
  early_warning_signs TEXT[], -- Subtle changes
  moderate_warning_signs TEXT[], -- Clear indicators
  crisis_warning_signs TEXT[], -- Immediate attention needed

  -- Coping strategies
  self_care_strategies TEXT[],
  social_support TEXT[], -- Who to reach out to
  professional_support TEXT[], -- Therapist, crisis line, etc.

  -- Emergency contacts
  emergency_contacts JSONB,
  -- Format: [{"name": "Dr. Smith", "phone": "555-1234", "relationship": "therapist"}]

  is_active BOOLEAN DEFAULT true
);

-- ============================================================================
-- Row Level Security (RLS)
-- ============================================================================
ALTER TABLE homework_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE exposure_hierarchies ENABLE ROW LEVEL SECURITY;
ALTER TABLE exposure_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE exposure_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE safety_behaviors ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_beliefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE values_assessment ENABLE ROW LEVEL SECURITY;
ALTER TABLE relapse_prevention_plan ENABLE ROW LEVEL SECURITY;

-- Policies for user access
CREATE POLICY homework_assignments_user_policy ON homework_assignments
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY exposure_hierarchies_user_policy ON exposure_hierarchies
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY exposure_steps_user_policy ON exposure_steps
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM exposure_hierarchies
      WHERE id = exposure_steps.hierarchy_id
      AND user_id = auth.uid()
    )
  );

CREATE POLICY exposure_attempts_user_policy ON exposure_attempts
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY safety_behaviors_user_policy ON safety_behaviors
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY core_beliefs_user_policy ON core_beliefs
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY values_assessment_user_policy ON values_assessment
  FOR ALL
  USING (auth.uid() = user_id);

CREATE POLICY relapse_prevention_user_policy ON relapse_prevention_plan
  FOR ALL
  USING (auth.uid() = user_id);

-- ============================================================================
-- Triggers
-- ============================================================================
CREATE TRIGGER homework_assignments_updated_at
  BEFORE UPDATE ON homework_assignments
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER values_assessment_updated_at
  BEFORE UPDATE ON values_assessment
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Functions
-- ============================================================================

-- Update homework status based on completion
CREATE OR REPLACE FUNCTION update_homework_status()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
    NEW.status = 'completed';
  ELSIF NEW.due_date < CURRENT_DATE AND NEW.status NOT IN ('completed', 'cancelled') THEN
    NEW.status = 'overdue';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER homework_status_trigger
  BEFORE UPDATE ON homework_assignments
  FOR EACH ROW
  EXECUTE FUNCTION update_homework_status();

-- Update exposure step status based on attempts
CREATE OR REPLACE FUNCTION update_exposure_step_status()
RETURNS TRIGGER AS $$
DECLARE
  v_success_count INTEGER;
BEGIN
  -- Count successful attempts (anxiety reduced significantly)
  SELECT COUNT(*)
  INTO v_success_count
  FROM exposure_attempts
  WHERE step_id = NEW.step_id
    AND anxiety_after < (anxiety_before * 0.5); -- 50% reduction

  -- Update step status if 3+ successful attempts
  IF v_success_count >= 3 THEN
    UPDATE exposure_steps
    SET status = 'completed'
    WHERE id = NEW.step_id;
  ELSIF v_success_count > 0 THEN
    UPDATE exposure_steps
    SET status = 'in_progress'
    WHERE id = NEW.step_id;
  END IF;

  -- Increment attempts counter
  UPDATE exposure_steps
  SET attempts = attempts + 1
  WHERE id = NEW.step_id;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER exposure_attempt_trigger
  AFTER INSERT ON exposure_attempts
  FOR EACH ROW
  EXECUTE FUNCTION update_exposure_step_status();

-- ============================================================================
-- Views
-- ============================================================================

-- View: Homework completion rate
CREATE VIEW homework_completion_stats AS
SELECT
  user_id,
  COUNT(*) AS total_assigned,
  SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
  SUM(CASE WHEN status = 'overdue' THEN 1 ELSE 0 END) AS overdue,
  ROUND(
    (SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END)::NUMERIC / COUNT(*)) * 100,
    2
  ) AS completion_rate
FROM homework_assignments
WHERE is_archived = false
GROUP BY user_id;

-- View: Values gap analysis
CREATE VIEW values_gap_analysis AS
SELECT
  user_id,
  domain,
  importance,
  current_satisfaction,
  (importance - current_satisfaction) AS gap,
  CASE
    WHEN (importance - current_satisfaction) >= 7 THEN 'critical'
    WHEN (importance - current_satisfaction) >= 4 THEN 'significant'
    WHEN (importance - current_satisfaction) >= 2 THEN 'moderate'
    ELSE 'minimal'
  END AS priority_level
FROM values_assessment
ORDER BY gap DESC;
