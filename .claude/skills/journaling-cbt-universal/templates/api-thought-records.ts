/**
 * CBT Thought Records API
 * ===================================
 * CRUD operations for CBT thought records (7-column format)
 *
 * Framework: Next.js App Router (adaptable to Express, FastAPI, etc.)
 * Privacy: HIPAA-compliant with encryption and audit logging
 *
 * IMPORTANT SECURITY NOTES:
 * - All PHI (Protected Health Information) must be encrypted at rest
 * - Implement audit logging for all access
 * - Rate limit to prevent abuse
 * - Validate and sanitize all inputs
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase/server';
import { z } from 'zod'; // For validation

// ============================================================================
// Validation Schemas
// ============================================================================

const EmotionSchema = z.object({
  emotion: z.string().min(1).max(50),
  intensity: z.number().min(0).max(100),
});

const CreateThoughtRecordSchema = z.object({
  situation: z.string().min(1).max(5000),
  situation_date: z.string().datetime().optional(),
  automatic_thoughts: z.string().min(1).max(5000),
  hot_thought: z.string().max(1000).optional(),
  emotions: z.array(EmotionSchema).min(1).max(10),
  physical_sensations: z.array(z.string()).max(20).optional(),
  evidence_for: z.string().max(5000).optional(),
  evidence_against: z.string().max(5000).optional(),
  balanced_thought: z.string().max(5000).optional(),
  emotions_after: z.array(EmotionSchema).max(10).optional(),
  distortions: z.array(z.string()).max(13).optional(),
  behavior_taken: z.string().max(2000).optional(),
  alternative_behavior: z.string().max(2000).optional(),
  tags: z.array(z.string()).max(10).optional(),
  shared_with_therapist: z.boolean().optional(),
});

// ============================================================================
// POST /api/thought-records
// Create a new thought record
// ============================================================================
export async function POST(request: NextRequest) {
  try {
    const supabase = await createServerClient();

    // Authenticate user
    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser();

    if (authError || !user) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Parse and validate request body
    const body = await request.json();
    const validatedData = CreateThoughtRecordSchema.parse(body);

    // Create thought record
    const { data: thoughtRecord, error } = await supabase
      .from('thought_records')
      .insert({
        user_id: user.id,
        ...validatedData,
        situation_date: validatedData.situation_date || new Date().toISOString(),
      })
      .select()
      .single();

    if (error) {
      console.error('Error creating thought record:', error);
      throw error;
    }

    // Log analytics event (non-PHI)
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'thought_record_created',
      event_data: {
        record_id: thoughtRecord.id,
        has_balanced_thought: !!validatedData.balanced_thought,
        num_emotions: validatedData.emotions.length,
        num_distortions: validatedData.distortions?.length || 0,
      },
    });

    return NextResponse.json(thoughtRecord, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation failed', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Error creating thought record:', error);
    return NextResponse.json(
      { error: 'Failed to create thought record' },
      { status: 500 }
    );
  }
}

// ============================================================================
// GET /api/thought-records
// Get all thought records for authenticated user
// ============================================================================
export async function GET(request: NextRequest) {
  try {
    const supabase = await createServerClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const startDate = searchParams.get('start_date');
    const endDate = searchParams.get('end_date');
    const tag = searchParams.get('tag');
    const includeArchived = searchParams.get('include_archived') === 'true';

    // Build query
    let query = supabase
      .from('thought_records')
      .select('*', { count: 'exact' })
      .eq('user_id', user.id)
      .order('situation_date', { ascending: false })
      .range(offset, offset + limit - 1);

    // Apply filters
    if (!includeArchived) {
      query = query.eq('is_archived', false);
    }

    if (startDate) {
      query = query.gte('situation_date', startDate);
    }

    if (endDate) {
      query = query.lte('situation_date', endDate);
    }

    if (tag) {
      query = query.contains('tags', [tag]);
    }

    const { data: thoughtRecords, error, count } = await query;

    if (error) {
      console.error('Error fetching thought records:', error);
      throw error;
    }

    return NextResponse.json({
      data: thoughtRecords,
      pagination: {
        total: count,
        limit,
        offset,
        has_more: count ? offset + limit < count : false,
      },
    });
  } catch (error) {
    console.error('Error fetching thought records:', error);
    return NextResponse.json(
      { error: 'Failed to fetch thought records' },
      { status: 500 }
    );
  }
}

// ============================================================================
// GET /api/thought-records/[id]
// Get a single thought record
// ============================================================================
export async function GET_BY_ID(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const supabase = await createServerClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { data: thoughtRecord, error } = await supabase
      .from('thought_records')
      .select('*')
      .eq('id', params.id)
      .eq('user_id', user.id) // Ensure user owns this record
      .single();

    if (error || !thoughtRecord) {
      return NextResponse.json(
        { error: 'Thought record not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(thoughtRecord);
  } catch (error) {
    console.error('Error fetching thought record:', error);
    return NextResponse.json(
      { error: 'Failed to fetch thought record' },
      { status: 500 }
    );
  }
}

// ============================================================================
// PATCH /api/thought-records/[id]
// Update a thought record
// ============================================================================
export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const supabase = await createServerClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();

    // Validate updates
    const UpdateSchema = CreateThoughtRecordSchema.partial();
    const validatedData = UpdateSchema.parse(body);

    // Update record
    const { data: thoughtRecord, error } = await supabase
      .from('thought_records')
      .update(validatedData)
      .eq('id', params.id)
      .eq('user_id', user.id) // Ensure user owns this record
      .select()
      .single();

    if (error || !thoughtRecord) {
      return NextResponse.json(
        { error: 'Thought record not found or update failed' },
        { status: 404 }
      );
    }

    // Log update event
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'thought_record_updated',
      event_data: {
        record_id: thoughtRecord.id,
        updated_fields: Object.keys(validatedData),
      },
    });

    return NextResponse.json(thoughtRecord);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation failed', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Error updating thought record:', error);
    return NextResponse.json(
      { error: 'Failed to update thought record' },
      { status: 500 }
    );
  }
}

// ============================================================================
// DELETE /api/thought-records/[id]
// Delete (archive) a thought record
// ============================================================================
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const supabase = await createServerClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // For HIPAA compliance, we archive instead of hard delete
    const { data: thoughtRecord, error } = await supabase
      .from('thought_records')
      .update({ is_archived: true })
      .eq('id', params.id)
      .eq('user_id', user.id)
      .select()
      .single();

    if (error || !thoughtRecord) {
      return NextResponse.json(
        { error: 'Thought record not found' },
        { status: 404 }
      );
    }

    // Log deletion event
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'thought_record_archived',
      event_data: {
        record_id: params.id,
      },
    });

    return NextResponse.json({ success: true, archived: true });
  } catch (error) {
    console.error('Error deleting thought record:', error);
    return NextResponse.json(
      { error: 'Failed to delete thought record' },
      { status: 500 }
    );
  }
}

// ============================================================================
// POST /api/thought-records/[id]/distortions
// Add cognitive distortion identification to a thought record
// ============================================================================
export async function ADD_DISTORTIONS(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const supabase = await createServerClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { distortion_ids, identified_by } = body;

    if (!Array.isArray(distortion_ids) || distortion_ids.length === 0) {
      return NextResponse.json(
        { error: 'distortion_ids must be a non-empty array' },
        { status: 400 }
      );
    }

    // Insert distortion associations
    const distortionRecords = distortion_ids.map((distortion_id: number) => ({
      thought_record_id: params.id,
      distortion_id,
      identified_by: identified_by || 'user',
      confidence: 1.0,
    }));

    const { data, error } = await supabase
      .from('thought_record_distortions')
      .insert(distortionRecords)
      .select();

    if (error) {
      console.error('Error adding distortions:', error);
      throw error;
    }

    return NextResponse.json({ success: true, distortions: data });
  } catch (error) {
    console.error('Error adding distortions:', error);
    return NextResponse.json(
      { error: 'Failed to add cognitive distortions' },
      { status: 500 }
    );
  }
}

// ============================================================================
// GET /api/thought-records/analytics/emotion-trends
// Get emotion trends over time for authenticated user
// ============================================================================
export async function GET_EMOTION_TRENDS(request: NextRequest) {
  try {
    const supabase = await createServerClient();

    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const emotion = searchParams.get('emotion') || 'anxiety';
    const days = parseInt(searchParams.get('days') || '30');

    // Call database function
    const { data: trends, error } = await supabase.rpc('get_mood_trends', {
      p_user_id: user.id,
      p_emotion: emotion,
      p_days: days,
    });

    if (error) {
      console.error('Error fetching emotion trends:', error);
      throw error;
    }

    return NextResponse.json({ emotion, days, trends });
  } catch (error) {
    console.error('Error fetching emotion trends:', error);
    return NextResponse.json(
      { error: 'Failed to fetch emotion trends' },
      { status: 500 }
    );
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Calculate emotion intensity improvement
 */
function calculateEmotionImprovement(
  emotionsBefore: Array<{ emotion: string; intensity: number }>,
  emotionsAfter: Array<{ emotion: string; intensity: number }>
): number {
  if (!emotionsAfter || emotionsAfter.length === 0) {
    return 0;
  }

  const avgBefore =
    emotionsBefore.reduce((sum, e) => sum + e.intensity, 0) /
    emotionsBefore.length;

  const avgAfter =
    emotionsAfter.reduce((sum, e) => sum + e.intensity, 0) /
    emotionsAfter.length;

  return avgBefore - avgAfter; // Positive = improvement
}

/**
 * Suggest cognitive distortions based on keywords
 * (Simple AI-free approach - for AI, use OpenAI/Claude API)
 */
function suggestDistortions(automaticThought: string): string[] {
  const suggestions: string[] = [];

  const keywords: Record<string, string> = {
    'always|never|every time': 'overgeneralization',
    'should|must|have to|ought': 'should_statements',
    'terrible|awful|disaster|catastrophe': 'catastrophizing',
    "they think|they're judging": 'mind_reading',
    "I know|it's going to": 'fortune_telling',
    'failure|loser|worthless': 'labeling',
    'my fault|because of me': 'personalization',
  };

  for (const [pattern, distortion] of Object.entries(keywords)) {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(automaticThought)) {
      suggestions.push(distortion);
    }
  }

  return [...new Set(suggestions)]; // Remove duplicates
}
