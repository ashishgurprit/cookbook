/**
 * Admin Affiliates API Route
 * Create and manage affiliate partners
 *
 * Framework: Next.js App Router
 * Adapt for your framework (Express, FastAPI, etc.)
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase/server';
import { isUserAdmin } from '@/lib/admin/helpers';

/**
 * POST /api/admin/affiliates
 * Create a new affiliate
 */
export async function POST(request: NextRequest) {
  try {
    const supabase = await createServerClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    // Verify authentication
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Verify admin access
    const isAdmin = await isUserAdmin(user.id);
    if (!isAdmin) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const body = await request.json();
    const { email, name, commission_tier, custom_code } = body;

    // Validate input
    if (!email || !name) {
      return NextResponse.json(
        { error: 'Email and name are required' },
        { status: 400 }
      );
    }

    if (![1, 2, 3].includes(commission_tier)) {
      return NextResponse.json(
        { error: 'Invalid commission tier' },
        { status: 400 }
      );
    }

    // Generate affiliate code if not provided
    const affiliateCode =
      custom_code ||
      `AFF${Math.random().toString(36).substring(2, 8).toUpperCase()}`;

    // Determine commission rate based on tier
    const commissionRates: { [key: number]: number } = {
      1: 30, // 30% for tier 1
      2: 40, // 40% for tier 2
      3: 50, // 50% for tier 3
    };

    const commissionRate = commissionRates[commission_tier] || 30;

    // Create affiliate
    // Note: In production, you'd first create/find the affiliate user
    // For this example, we're using the admin's user_id as placeholder
    const { data: affiliate, error } = await supabase
      .from('affiliates')
      .insert({
        user_id: user.id, // Replace with actual affiliate user ID
        affiliate_code: affiliateCode,
        commission_tier,
        commission_rate: commissionRate,
        is_active: true,
        metadata: {
          name,
          email,
          created_by_admin: user.id,
          created_at: new Date().toISOString(),
        },
      })
      .select()
      .single();

    if (error) {
      console.error('Error creating affiliate:', error);
      throw error;
    }

    // Log admin action
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'admin_affiliate_created',
      event_data: {
        affiliate_id: affiliate.id,
        affiliate_code: affiliateCode,
        commission_tier,
      },
    });

    return NextResponse.json(affiliate);
  } catch (error) {
    console.error('Error creating affiliate:', error);
    return NextResponse.json(
      { error: 'Failed to create affiliate' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/admin/affiliates
 * Get all affiliates with filtering
 */
export async function GET(request: NextRequest) {
  try {
    const supabase = await createServerClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user || !(await isUserAdmin(user.id))) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Get query parameters
    const { searchParams } = new URL(request.url);
    const isActive = searchParams.get('active');
    const tier = searchParams.get('tier');

    // Build query
    let query = supabase
      .from('affiliates')
      .select(`
        *,
        affiliate_referrals (
          id,
          revenue_cents,
          commission_cents,
          referred_at,
          converted_at
        )
      `)
      .order('total_revenue_cents', { ascending: false });

    // Apply filters
    if (isActive !== null) {
      query = query.eq('is_active', isActive === 'true');
    }

    if (tier) {
      query = query.eq('commission_tier', parseInt(tier));
    }

    const { data: affiliates, error } = await query;

    if (error) {
      console.error('Error fetching affiliates:', error);
      throw error;
    }

    return NextResponse.json(affiliates);
  } catch (error) {
    console.error('Error fetching affiliates:', error);
    return NextResponse.json(
      { error: 'Failed to fetch affiliates' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/admin/affiliates/[id]
 * Update affiliate (deactivate, change tier, etc.)
 */
export async function PATCH(request: NextRequest) {
  try {
    const supabase = await createServerClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user || !(await isUserAdmin(user.id))) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { affiliate_id, is_active, commission_tier } = body;

    const updates: any = {};

    if (typeof is_active === 'boolean') {
      updates.is_active = is_active;
    }

    if (commission_tier && [1, 2, 3].includes(commission_tier)) {
      updates.commission_tier = commission_tier;
      const commissionRates = { 1: 30, 2: 40, 3: 50 };
      updates.commission_rate = commissionRates[commission_tier as keyof typeof commissionRates];
    }

    updates.updated_at = new Date().toISOString();

    const { data: affiliate, error } = await supabase
      .from('affiliates')
      .update(updates)
      .eq('id', affiliate_id)
      .select()
      .single();

    if (error) {
      console.error('Error updating affiliate:', error);
      throw error;
    }

    // Log admin action
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'admin_affiliate_updated',
      event_data: {
        affiliate_id,
        updates,
      },
    });

    return NextResponse.json(affiliate);
  } catch (error) {
    console.error('Error updating affiliate:', error);
    return NextResponse.json(
      { error: 'Failed to update affiliate' },
      { status: 500 }
    );
  }
}
