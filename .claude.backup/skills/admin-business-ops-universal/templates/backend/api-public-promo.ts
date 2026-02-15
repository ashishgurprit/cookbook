/**
 * Public Promo Code API
 * Validate and apply promo codes during checkout
 *
 * Framework: Next.js App Router
 * Adapt for your framework (Express, FastAPI, etc.)
 */

import { NextRequest, NextResponse } from 'next/server';
import { createServerClient } from '@/lib/supabase/server';

/**
 * POST /api/promo/validate
 * Validate promo code and return discount details
 *
 * Body:
 * {
 *   "code": "LAUNCH50",
 *   "subscription_tier": "pro",
 *   "user_id": "optional-user-id"
 * }
 */
export async function POST(request: NextRequest) {
  try {
    const supabase = await createServerClient();
    const body = await request.json();
    const { code, subscription_tier, user_id } = body;

    if (!code || !subscription_tier) {
      return NextResponse.json(
        { error: 'Code and subscription_tier are required' },
        { status: 400 }
      );
    }

    const normalizedCode = code.toUpperCase();

    // Get promo code
    const { data: promoCode, error } = await supabase
      .from('promo_codes')
      .select('*')
      .eq('code', normalizedCode)
      .eq('is_active', true)
      .single();

    if (error || !promoCode) {
      return NextResponse.json(
        {
          valid: false,
          error: 'Invalid promo code',
        },
        { status: 404 }
      );
    }

    // Validation checks
    const now = new Date();

    // Check if code has started
    if (promoCode.valid_from && new Date(promoCode.valid_from) > now) {
      return NextResponse.json({
        valid: false,
        error: 'This promo code is not yet active',
      });
    }

    // Check if code has expired
    if (promoCode.valid_until && new Date(promoCode.valid_until) < now) {
      return NextResponse.json({
        valid: false,
        error: 'This promo code has expired',
      });
    }

    // Check max uses
    if (promoCode.max_uses && promoCode.current_uses >= promoCode.max_uses) {
      return NextResponse.json({
        valid: false,
        error: 'This promo code has reached its usage limit',
      });
    }

    // Check if applies to this subscription tier
    if (
      promoCode.applies_to &&
      promoCode.applies_to.length > 0 &&
      !promoCode.applies_to.includes(subscription_tier)
    ) {
      return NextResponse.json({
        valid: false,
        error: `This promo code does not apply to the ${subscription_tier} plan`,
      });
    }

    // Check if user has already used this code
    if (user_id) {
      const { data: existingRedemption } = await supabase
        .from('promo_code_redemptions')
        .select('id')
        .eq('promo_code_id', promoCode.id)
        .eq('user_id', user_id)
        .single();

      if (existingRedemption) {
        return NextResponse.json({
          valid: false,
          error: 'You have already used this promo code',
        });
      }
    }

    // Code is valid - return discount details
    return NextResponse.json({
      valid: true,
      promo_code: {
        id: promoCode.id,
        code: promoCode.code,
        description: promoCode.description,
        discount_type: promoCode.discount_type,
        discount_value: promoCode.discount_value,
        stripe_coupon_id: promoCode.stripe_coupon_id,
      },
    });
  } catch (error) {
    console.error('Error validating promo code:', error);
    return NextResponse.json(
      { error: 'Failed to validate promo code' },
      { status: 500 }
    );
  }
}

/**
 * Helper function to calculate discount amount
 * Call this from your checkout/payment processing code
 */
export async function calculateDiscount(
  promoCodeId: string,
  subscriptionPriceCents: number
): Promise<number> {
  const supabase = await createServerClient();

  const { data: promoCode } = await supabase
    .from('promo_codes')
    .select('discount_type, discount_value')
    .eq('id', promoCodeId)
    .single();

  if (!promoCode) {
    return 0;
  }

  if (promoCode.discount_type === 'percentage') {
    // Calculate percentage discount
    return Math.round((subscriptionPriceCents * promoCode.discount_value) / 100);
  }

  if (promoCode.discount_type === 'fixed_amount') {
    // Fixed amount discount (in cents)
    return Math.min(promoCode.discount_value, subscriptionPriceCents);
  }

  // Trial extension doesn't affect price
  return 0;
}

/**
 * Helper function to record promo code redemption
 * Call this after successful payment
 */
export async function recordRedemption(
  promoCodeId: string,
  userId: string,
  subscriptionId: string,
  discountAmountCents: number
): Promise<void> {
  const supabase = await createServerClient();

  // Record redemption
  await supabase.from('promo_code_redemptions').insert({
    promo_code_id: promoCodeId,
    user_id: userId,
    subscription_id: subscriptionId,
    discount_amount_cents: discountAmountCents,
  });

  // Increment usage counter
  await supabase.rpc('increment_promo_usage', {
    promo_id: promoCodeId,
  });

  // Log event
  await supabase.from('analytics_events').insert({
    user_id: userId,
    event_type: 'promo_code_redeemed',
    event_data: {
      promo_code_id: promoCodeId,
      discount_amount_cents: discountAmountCents,
      subscription_id: subscriptionId,
    },
  });
}

/**
 * Database function to increment promo code usage
 * Add this to your database schema:
 *
 * CREATE OR REPLACE FUNCTION increment_promo_usage(promo_id UUID)
 * RETURNS VOID AS $$
 * BEGIN
 *   UPDATE promo_codes
 *   SET current_uses = current_uses + 1
 *   WHERE id = promo_id;
 * END;
 * $$ LANGUAGE plpgsql;
 */
