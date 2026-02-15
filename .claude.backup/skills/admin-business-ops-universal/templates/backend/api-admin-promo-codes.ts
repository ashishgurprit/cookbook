/**
 * Admin Promo Codes API Route
 * Create and manage promotional discount codes
 *
 * Framework: Next.js App Router
 * Adapt for your framework (Express, FastAPI, etc.)
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase/server';
import { isUserAdmin } from '@/lib/admin/helpers';

/**
 * POST /api/admin/promo-codes
 * Create a new promo code
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
    const {
      code,
      description,
      discount_type,
      discount_value,
      applies_to,
      max_uses,
      valid_from,
      valid_until,
      stripe_coupon_id,
    } = body;

    // Validate input
    if (!code || !discount_type || discount_value === undefined) {
      return NextResponse.json(
        { error: 'Code, discount_type, and discount_value are required' },
        { status: 400 }
      );
    }

    // Validate discount type
    if (!['percentage', 'fixed_amount', 'trial_extension'].includes(discount_type)) {
      return NextResponse.json(
        { error: 'Invalid discount_type. Must be: percentage, fixed_amount, or trial_extension' },
        { status: 400 }
      );
    }

    // Validate discount value
    if (discount_type === 'percentage' && (discount_value < 0 || discount_value > 100)) {
      return NextResponse.json(
        { error: 'Percentage discount must be between 0 and 100' },
        { status: 400 }
      );
    }

    if (discount_type === 'fixed_amount' && discount_value < 0) {
      return NextResponse.json(
        { error: 'Fixed amount discount must be positive' },
        { status: 400 }
      );
    }

    // Normalize code to uppercase
    const normalizedCode = code.toUpperCase();

    // Create promo code
    const { data: promoCode, error } = await supabase
      .from('promo_codes')
      .insert({
        code: normalizedCode,
        description,
        discount_type,
        discount_value,
        applies_to: applies_to || [],
        max_uses: max_uses || null,
        valid_from: valid_from || new Date().toISOString(),
        valid_until: valid_until || null,
        stripe_coupon_id: stripe_coupon_id || null,
        created_by: user.id,
        is_active: true,
      })
      .select()
      .single();

    if (error) {
      console.error('Error creating promo code:', error);

      // Check for duplicate code
      if (error.code === '23505') {
        return NextResponse.json(
          { error: 'Promo code already exists' },
          { status: 409 }
        );
      }

      throw error;
    }

    // Log admin action
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'admin_promo_code_created',
      event_data: {
        promo_code_id: promoCode.id,
        code: normalizedCode,
        discount_type,
        discount_value,
      },
    });

    return NextResponse.json(promoCode);
  } catch (error) {
    console.error('Error creating promo code:', error);
    return NextResponse.json(
      { error: 'Failed to create promo code' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/admin/promo-codes
 * Get all promo codes with filtering
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
    const discountType = searchParams.get('type');

    // Build query
    let query = supabase
      .from('promo_codes')
      .select(`
        *,
        promo_code_redemptions (
          id,
          user_id,
          discount_amount_cents,
          redeemed_at
        )
      `)
      .order('created_at', { ascending: false });

    // Apply filters
    if (isActive !== null) {
      query = query.eq('is_active', isActive === 'true');
    }

    if (discountType) {
      query = query.eq('discount_type', discountType);
    }

    const { data: promoCodes, error } = await query;

    if (error) {
      console.error('Error fetching promo codes:', error);
      throw error;
    }

    // Calculate usage statistics
    const promoCodesWithStats = promoCodes.map((code) => ({
      ...code,
      redemption_count: code.promo_code_redemptions?.length || 0,
      total_discount_cents: code.promo_code_redemptions?.reduce(
        (sum: number, r: any) => sum + (r.discount_amount_cents || 0),
        0
      ) || 0,
    }));

    return NextResponse.json(promoCodesWithStats);
  } catch (error) {
    console.error('Error fetching promo codes:', error);
    return NextResponse.json(
      { error: 'Failed to fetch promo codes' },
      { status: 500 }
    );
  }
}

/**
 * PATCH /api/admin/promo-codes/[id]
 * Update promo code (deactivate, extend validity, etc.)
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
    const {
      promo_code_id,
      is_active,
      max_uses,
      valid_until,
      description,
    } = body;

    const updates: any = {};

    if (typeof is_active === 'boolean') {
      updates.is_active = is_active;
    }

    if (max_uses !== undefined) {
      updates.max_uses = max_uses;
    }

    if (valid_until) {
      updates.valid_until = valid_until;
    }

    if (description) {
      updates.description = description;
    }

    updates.updated_at = new Date().toISOString();

    const { data: promoCode, error } = await supabase
      .from('promo_codes')
      .update(updates)
      .eq('id', promo_code_id)
      .select()
      .single();

    if (error) {
      console.error('Error updating promo code:', error);
      throw error;
    }

    // Log admin action
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'admin_promo_code_updated',
      event_data: {
        promo_code_id,
        updates,
      },
    });

    return NextResponse.json(promoCode);
  } catch (error) {
    console.error('Error updating promo code:', error);
    return NextResponse.json(
      { error: 'Failed to update promo code' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/admin/promo-codes/[id]
 * Delete promo code (only if never used)
 */
export async function DELETE(request: NextRequest) {
  try {
    const supabase = await createServerClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user || !(await isUserAdmin(user.id))) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const promoCodeId = searchParams.get('id');

    if (!promoCodeId) {
      return NextResponse.json(
        { error: 'Promo code ID required' },
        { status: 400 }
      );
    }

    // Check if promo code has been used
    const { data: redemptions } = await supabase
      .from('promo_code_redemptions')
      .select('id')
      .eq('promo_code_id', promoCodeId)
      .limit(1);

    if (redemptions && redemptions.length > 0) {
      return NextResponse.json(
        { error: 'Cannot delete promo code that has been used. Deactivate it instead.' },
        { status: 400 }
      );
    }

    // Delete promo code
    const { error } = await supabase
      .from('promo_codes')
      .delete()
      .eq('id', promoCodeId);

    if (error) {
      console.error('Error deleting promo code:', error);
      throw error;
    }

    // Log admin action
    await supabase.from('analytics_events').insert({
      user_id: user.id,
      event_type: 'admin_promo_code_deleted',
      event_data: {
        promo_code_id: promoCodeId,
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Error deleting promo code:', error);
    return NextResponse.json(
      { error: 'Failed to delete promo code' },
      { status: 500 }
    );
  }
}
