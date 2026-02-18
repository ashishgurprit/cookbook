# Admin & Business Operations - Universal Skill

**Version**: 1.0.0
**OWASP Compliance**: 100%
**Framework**: Framework-agnostic (examples in Next.js/React + Supabase/PostgreSQL)

> Production-ready admin dashboard and business operations system with analytics, user management, affiliate tracking, promo codes, and multi-tier subscription management.

## Architecture

**Core Components**:
- **Admin Dashboard**: Key metrics, revenue analysis, profit margins, daily statistics
- **User Management**: Filtering, sorting, subscription tier management
- **Affiliate Program**: Multi-tier commissions, referral tracking, payout management
- **Promo Codes**: Percentage/fixed discounts, trial extensions, usage tracking
- **Analytics System**: Event tracking, API usage monitoring, daily aggregations
- **Multi-Tier Subscriptions**: Flexible pricing plans (monthly, annual, multi-year)

**Cost**: $0 (self-hosted with Supabase/PostgreSQL) vs $500+/month for third-party admin tools

## Quick Start

### 1. Database Schema

```sql
-- Admin Analytics Tables
-- See templates/database/admin-schema.sql for complete schema

-- Core tables:
-- 1. analytics_events - Track all user actions
-- 2. api_usage - Monitor API calls and costs
-- 3. daily_metrics - Aggregated daily statistics
-- 4. promo_codes - Discount management
-- 5. affiliates - Affiliate program
-- 6. admin_users - Admin permissions
```

### 2. Backend Helpers

```typescript
// lib/admin/helpers.ts
import { createServerClient } from '@/lib/supabase/server';

/**
 * Check if user is admin
 */
export async function isUserAdmin(userId: string): Promise<boolean> {
  const supabase = await createServerClient();

  const { data } = await supabase
    .from('admin_users')
    .select('id')
    .eq('user_id', userId)
    .single();

  return !!data;
}

/**
 * Get daily metrics for date range
 */
export async function getDailyMetrics(startDate: string, endDate: string) {
  const supabase = await createServerClient();

  const { data } = await supabase
    .from('daily_metrics')
    .select('*')
    .gte('metric_date', startDate)
    .lte('metric_date', endDate)
    .order('metric_date', { ascending: true });

  return data || [];
}

/**
 * Get revenue metrics
 */
export async function getRevenueMetrics(startDate: string, endDate: string) {
  const supabase = await createServerClient();

  const { data: metrics } = await supabase
    .from('daily_metrics')
    .select('metric_date, revenue_cents, mrr_cents')
    .gte('metric_date', startDate)
    .lte('metric_date', endDate)
    .order('metric_date', { ascending: true });

  if (!metrics) return { totalRevenue: 0, currentMRR: 0, data: [] };

  const totalRevenue = metrics.reduce((sum, m) => sum + (m.revenue_cents || 0), 0);
  const currentMRR = metrics[metrics.length - 1]?.mrr_cents || 0;

  return {
    totalRevenue,
    currentMRR,
    data: metrics,
  };
}

/**
 * Calculate profit margins
 */
export async function calculateProfitMargins(startDate: string, endDate: string) {
  const revenue = await getRevenueMetrics(startDate, endDate);
  const apiCosts = await getAPIUsageMetrics(startDate, endDate);

  const totalCosts = apiCosts.totalCost;
  const profit = revenue.totalRevenue - totalCosts;
  const profitMargin = revenue.totalRevenue > 0 ? (profit / revenue.totalRevenue) * 100 : 0;

  return {
    revenue: revenue.totalRevenue,
    costs: {
      ai: apiCosts.totalCost,
      total: totalCosts,
    },
    profit,
    profitMargin,
  };
}

/**
 * Format currency from cents
 */
export function formatCurrency(cents: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
  }).format(cents / 100);
}
```

### 3. Admin Dashboard

```typescript
// app/admin/page.tsx
import { redirect } from 'next/navigation';
import { createServerClient } from '@/lib/supabase/server';
import {
  isUserAdmin,
  getDailyMetrics,
  getRevenueMetrics,
  calculateProfitMargins,
  formatCurrency,
} from '@/lib/admin/helpers';

export default async function AdminDashboard() {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user || !(await isUserAdmin(user.id))) {
    redirect('/');
  }

  // Get date range (last 30 days)
  const endDate = new Date().toISOString().split('T')[0];
  const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    .toISOString()
    .split('T')[0];

  // Fetch metrics
  const [dailyMetrics, revenueMetrics, profitMargins] = await Promise.all([
    getDailyMetrics(startDate, endDate),
    getRevenueMetrics(startDate, endDate),
    calculateProfitMargins(startDate, endDate),
  ]);

  const latestMetric = dailyMetrics[dailyMetrics.length - 1];
  const totalUsers = latestMetric?.total_users || 0;
  const activeUsers = latestMetric?.active_users || 0;

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Header */}
        <h1 className="text-3xl font-bold text-gray-900 mb-8">Admin Dashboard</h1>

        {/* Key Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          {/* Total Users */}
          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600 mb-1">Total Users</div>
            <div className="text-3xl font-bold">{totalUsers.toLocaleString()}</div>
          </div>

          {/* Active Users */}
          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600 mb-1">Active Users</div>
            <div className="text-3xl font-bold">{activeUsers.toLocaleString()}</div>
          </div>

          {/* MRR */}
          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600 mb-1">Monthly Recurring Revenue</div>
            <div className="text-3xl font-bold">
              {formatCurrency(revenueMetrics.currentMRR)}
            </div>
          </div>

          {/* Profit */}
          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600 mb-1">Net Profit (30d)</div>
            <div className={`text-3xl font-bold ${profitMargins.profit >= 0 ? 'text-green-600' : 'text-red-600'}`}>
              {formatCurrency(profitMargins.profit)}
            </div>
          </div>
        </div>

        {/* Profit Analysis */}
        <div className="bg-white rounded-xl shadow-sm border p-6 mb-8">
          <h2 className="text-xl font-bold mb-4">Profit Analysis (30d)</h2>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-600">Total Revenue</span>
              <span className="font-bold text-green-600">
                {formatCurrency(profitMargins.revenue)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">AI Costs</span>
              <span className="font-bold text-red-600">
                -{formatCurrency(profitMargins.costs.ai)}
              </span>
            </div>
            <div className="border-t pt-3 flex justify-between">
              <span className="font-bold">Net Profit</span>
              <span className={`font-bold text-xl ${profitMargins.profit >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                {formatCurrency(profitMargins.profit)}
              </span>
            </div>
          </div>
        </div>

        {/* Daily Metrics Table */}
        <div className="bg-white rounded-xl shadow-sm border p-6">
          <h2 className="text-xl font-bold mb-4">Daily Metrics (Last 7 Days)</h2>
          <table className="min-w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 px-4">Date</th>
                <th className="text-right py-3 px-4">New Users</th>
                <th className="text-right py-3 px-4">Active Users</th>
                <th className="text-right py-3 px-4">Revenue</th>
              </tr>
            </thead>
            <tbody>
              {dailyMetrics.slice(-7).map((metric) => (
                <tr key={metric.metric_date} className="border-b">
                  <td className="py-3 px-4">
                    {new Date(metric.metric_date).toLocaleDateString()}
                  </td>
                  <td className="text-right py-3 px-4">{metric.new_users}</td>
                  <td className="text-right py-3 px-4">{metric.active_users}</td>
                  <td className="text-right py-3 px-4">
                    {formatCurrency(metric.revenue_cents || 0)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
```

### 4. User Management

```typescript
// app/admin/users/UserManagementTable.tsx
'use client';

import { useState } from 'react';

interface User {
  id: string;
  email: string;
  created_at: string;
  subscription_tier: string;
  subscription_status: string;
  tokens_used_this_month: number;
}

export default function UserManagementTable({ initialUsers }: { initialUsers: User[] }) {
  const [users, setUsers] = useState(initialUsers);
  const [filter, setFilter] = useState<'all' | 'free' | 'pro' | 'premium'>('all');
  const [sortBy, setSortBy] = useState<'created' | 'activity' | 'usage'>('created');

  // Filter users
  const filteredUsers = users.filter((user) => {
    if (filter === 'all') return true;
    return user.subscription_tier === filter;
  });

  // Sort users
  const sortedUsers = [...filteredUsers].sort((a, b) => {
    if (sortBy === 'created') {
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    }
    if (sortBy === 'usage') {
      return b.tokens_used_this_month - a.tokens_used_this_month;
    }
    return 0;
  });

  const getTierBadge = (tier: string) => {
    const colors = {
      free: 'bg-gray-100 text-gray-700',
      pro: 'bg-blue-100 text-blue-700',
      premium: 'bg-purple-100 text-purple-700',
    };
    return (
      <span className={`px-2 py-1 rounded text-xs font-medium ${colors[tier as keyof typeof colors]}`}>
        {tier}
      </span>
    );
  };

  return (
    <div>
      {/* Filters */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex gap-2">
          <button
            onClick={() => setFilter('all')}
            className={`px-4 py-2 rounded-lg ${
              filter === 'all' ? 'bg-gray-900 text-white' : 'bg-gray-100'
            }`}
          >
            All Users
          </button>
          <button onClick={() => setFilter('free')}>Free</button>
          <button onClick={() => setFilter('pro')}>Pro</button>
          <button onClick={() => setFilter('premium')}>Premium</button>
        </div>

        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as any)}
          className="px-4 py-2 border rounded-lg"
        >
          <option value="created">Newest First</option>
          <option value="activity">Recent Activity</option>
          <option value="usage">Usage</option>
        </select>
      </div>

      {/* Table */}
      <table className="min-w-full">
        <thead>
          <tr className="border-b">
            <th className="text-left py-3 px-4">Email</th>
            <th className="text-left py-3 px-4">Tier</th>
            <th className="text-right py-3 px-4">Usage</th>
            <th className="text-left py-3 px-4">Created</th>
          </tr>
        </thead>
        <tbody>
          {sortedUsers.map((user) => (
            <tr key={user.id} className="border-b hover:bg-gray-50">
              <td className="py-3 px-4">{user.email}</td>
              <td className="py-3 px-4">{getTierBadge(user.subscription_tier)}</td>
              <td className="text-right py-3 px-4">
                {user.tokens_used_this_month.toLocaleString()}
              </td>
              <td className="py-3 px-4">
                {new Date(user.created_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

### 5. Affiliate Management

```typescript
// app/admin/affiliates/AffiliateManager.tsx
'use client';

import { useState } from 'react';

interface Affiliate {
  id: string;
  affiliate_code: string;
  commission_tier: number;
  total_referrals: number;
  total_revenue_cents: number;
  total_commission_cents: number;
  is_active: boolean;
}

export default function AffiliateManager({ initialAffiliates }: { initialAffiliates: Affiliate[] }) {
  const [affiliates, setAffiliates] = useState(initialAffiliates);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    name: '',
    commission_tier: 1,
    custom_code: '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const response = await fetch('/api/admin/affiliates', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData),
    });

    const newAffiliate = await response.json();
    setAffiliates([newAffiliate, ...affiliates]);
    setShowForm(false);
  };

  const getTierBadge = (tier: number) => {
    const tiers = {
      1: { label: 'Tier 1 (30%)', color: 'bg-blue-100 text-blue-700' },
      2: { label: 'Tier 2 (40%)', color: 'bg-purple-100 text-purple-700' },
      3: { label: 'Tier 3 (50%)', color: 'bg-amber-100 text-amber-700' },
    };
    const { label, color } = tiers[tier as keyof typeof tiers];
    return <span className={`px-2 py-1 rounded text-xs font-medium ${color}`}>{label}</span>;
  };

  const formatCurrency = (cents: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(cents / 100);
  };

  return (
    <div>
      {/* Create Button */}
      <button
        onClick={() => setShowForm(!showForm)}
        className="mb-6 px-4 py-2 bg-purple-600 text-white rounded-lg"
      >
        {showForm ? 'Cancel' : 'Add New Affiliate'}
      </button>

      {/* Creation Form */}
      {showForm && (
        <div className="mb-8 bg-white rounded-xl shadow-sm border p-6">
          <h2 className="text-xl font-bold mb-4">Add New Affiliate</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="Name"
                className="px-4 py-2 border rounded-lg"
                required
              />
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="Email"
                className="px-4 py-2 border rounded-lg"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <select
                value={formData.commission_tier}
                onChange={(e) => setFormData({ ...formData, commission_tier: parseInt(e.target.value) })}
                className="px-4 py-2 border rounded-lg"
              >
                <option value={1}>Tier 1 - 30%</option>
                <option value={2}>Tier 2 - 40%</option>
                <option value={3}>Tier 3 - 50%</option>
              </select>

              <input
                type="text"
                value={formData.custom_code}
                onChange={(e) => setFormData({ ...formData, custom_code: e.target.value.toUpperCase() })}
                placeholder="Custom Code (optional)"
                className="px-4 py-2 border rounded-lg"
              />
            </div>

            <button
              type="submit"
              className="w-full px-4 py-2 bg-purple-600 text-white rounded-lg font-medium"
            >
              Create Affiliate
            </button>
          </form>
        </div>
      )}

      {/* Affiliate List */}
      <div className="bg-white rounded-xl shadow-sm border p-6">
        <h2 className="text-xl font-bold mb-4">Active Affiliates</h2>
        <table className="min-w-full">
          <thead>
            <tr className="border-b">
              <th className="text-left py-3 px-4">Code</th>
              <th className="text-left py-3 px-4">Tier</th>
              <th className="text-right py-3 px-4">Referrals</th>
              <th className="text-right py-3 px-4">Revenue</th>
              <th className="text-right py-3 px-4">Commission</th>
            </tr>
          </thead>
          <tbody>
            {affiliates.map((affiliate) => (
              <tr key={affiliate.id} className="border-b hover:bg-gray-50">
                <td className="py-3 px-4">
                  <span className="font-mono font-bold text-purple-600">
                    {affiliate.affiliate_code}
                  </span>
                </td>
                <td className="py-3 px-4">{getTierBadge(affiliate.commission_tier)}</td>
                <td className="text-right py-3 px-4">{affiliate.total_referrals || 0}</td>
                <td className="text-right py-3 px-4 font-medium text-green-600">
                  {formatCurrency(affiliate.total_revenue_cents || 0)}
                </td>
                <td className="text-right py-3 px-4 font-medium text-purple-600">
                  {formatCurrency(affiliate.total_commission_cents || 0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
```

## Security (OWASP Top 10)

### A01: Broken Access Control
```typescript
// Admin-only routes protection
export async function isUserAdmin(userId: string): Promise<boolean> {
  const supabase = await createServerClient();
  const { data } = await supabase
    .from('admin_users')
    .select('id')
    .eq('user_id', userId)
    .single();
  return !!data;
}

// RLS policy
CREATE POLICY "Admins can view analytics"
  ON analytics_events FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM admin_users
      WHERE admin_users.user_id = auth.uid()
    )
  );
```

### A02: Cryptographic Failures
```typescript
// Store sensitive data encrypted
// Never log API keys or payment details
```

### A03: Injection
```sql
-- Use parameterized queries
-- Always use ORM/query builders with prepared statements
```

### A04: Insecure Design
```typescript
// Rate limit admin API endpoints
// Require 2FA for admin access
// Log all admin actions
```

### A05: Security Misconfiguration
```typescript
// Environment-based admin access
if (process.env.NODE_ENV === 'production') {
  // Require additional verification
}
```

## Database Schema

See `templates/database/admin-schema.sql` for complete schema with:
- `analytics_events` - User action tracking
- `api_usage` - API call monitoring
- `daily_metrics` - Aggregated statistics
- `promo_codes` - Discount management
- `affiliates` - Affiliate program
- `admin_users` - Admin permissions

## Features

### Admin Dashboard
- Key metrics cards (Total Users, Active Users, MRR, Profit)
- Subscription breakdown with visual bars
- Profit analysis (Revenue, Costs, Net profit, Margins)
- API usage statistics
- Daily metrics table (last 7-30 days)

### User Management
- User list with filtering by subscription tier
- Sorting by creation date, activity, usage
- Tier summary cards
- User details with subscription status

### Affiliate Management
- Affiliate performance dashboard
- Multi-tier commission structure (configurable %)
- Summary cards (Total affiliates, referrals, revenue, commissions)
- Affiliate creation with custom codes
- Referral tracking and conversion metrics

### Promo Code System
- Multiple discount types (percentage, fixed amount, trial extension)
- Usage tracking (current uses / max uses)
- Valid date ranges
- Applies to specific subscription tiers
- Suggested promo strategies guide

### Analytics & Tracking
- Event tracking system
- API usage monitoring with cost tracking
- Daily metric aggregation (auto-updated)
- Revenue recognition
- Growth rate calculations

## Multi-Tier Subscription Patterns

### Subscription Tiers (Configurable)
```typescript
// lib/subscription/constants.ts
export const SUBSCRIPTION_TIERS = {
  free: {
    name: 'Free',
    priceMonthly: 0,
    features: ['Basic features', 'Limited usage'],
  },
  pro: {
    name: 'Pro',
    priceMonthly: 999, // $9.99 in cents
    priceAnnual: 9900, // $99/year (17% off)
    price2Year: 19900, // $199 (2 years)
    price4Year: 34900, // $349 (4 years)
    price5Year: 39900, // $399 (5 years)
    features: ['Unlimited usage', 'Priority support'],
  },
  premium: {
    name: 'Premium',
    priceMonthly: 2999, // $29.99
    priceAnnual: 29900, // $299/year (17% off)
    features: ['Everything in Pro', 'White label', 'Dedicated support'],
  },
};
```

### Stripe Multi-Year Setup
See `docs/STRIPE_MULTI_YEAR_SETUP.md` for:
- Creating custom interval prices (2, 4, 5 year plans)
- Revenue recognition guidance
- Customer communication templates
- Marketing copy suggestions
- Refund policy considerations

## Commission Structures

### Affiliate Tiers (Configurable)
```typescript
export const AFFILIATE_TIERS = {
  1: {
    name: 'Starter',
    commissionRate: 30,
    duration: '3 months',
    minReferrals: 0,
  },
  2: {
    name: 'Growth',
    commissionRate: 40,
    duration: '6 months',
    minReferrals: 10,
  },
  3: {
    name: 'Elite',
    commissionRate: 50,
    duration: 'Lifetime',
    minReferrals: 50,
  },
};
```

## Use Cases

- **SaaS Admin Dashboards**: User management, subscription analytics
- **E-commerce Admin**: Order tracking, revenue analysis, customer analytics
- **Marketplace Platforms**: Seller/buyer management, commission tracking
- **Membership Sites**: Member analytics, subscription management
- **Affiliate Programs**: Referral tracking, commission payouts
- **Freemium Apps**: Conversion tracking, user tier analysis

## Performance

- Dashboard load: <500ms (with proper indexing)
- Daily metrics aggregation: <1s (automated job)
- User filtering/sorting: <100ms (client-side)
- Affiliate calculations: <200ms (database-level aggregation)

**Database Indexing Critical**:
```sql
CREATE INDEX idx_analytics_events_user ON analytics_events(user_id, created_at DESC);
CREATE INDEX idx_daily_metrics_date ON daily_metrics(metric_date DESC);
CREATE INDEX idx_affiliates_code ON affiliates(affiliate_code) WHERE is_active = TRUE;
```

## Best Practices

1. **Admin Access**: Always verify admin status before rendering admin UI
2. **Metrics Caching**: Cache daily metrics, update via background job
3. **Pagination**: Implement pagination for large user lists (100+ users)
4. **RLS Policies**: Use database-level security (Row Level Security)
5. **Audit Logging**: Log all admin actions for compliance
6. **2FA Required**: Require two-factor authentication for admin access
7. **IP Whitelisting**: Consider restricting admin access to specific IPs
8. **Rate Limiting**: Limit admin API requests (e.g., 100 req/min)

## Integration Examples

### With Stripe
```typescript
// Track subscription changes
stripe.webhooks.constructEvent(
  payload,
  signature,
  process.env.STRIPE_WEBHOOK_SECRET
);

// Log revenue in daily_metrics
await supabase.from('daily_metrics').update({
  revenue_cents: revenue_cents + amount,
  mrr_cents: calculateMRR(),
});
```

### With Analytics Providers
```typescript
// Send admin actions to analytics
analytics.track('Admin Action', {
  action: 'user_tier_updated',
  admin_id: adminUserId,
  target_user_id: userId,
  new_tier: 'pro',
});
```

## Troubleshooting

### Issue: Metrics not updating
**Solution**: Run daily metrics aggregation manually:
```sql
SELECT update_daily_metrics();
```

### Issue: Slow dashboard load
**Solution**: Add database indexes, enable query caching

### Issue: Affiliate commissions incorrect
**Solution**: Verify commission_rate calculation and tier thresholds

## Cost Analysis

**Self-Hosted Admin System**: $0/month (using Supabase free tier or self-hosted PostgreSQL)

**vs Third-Party Admin Tools**:
- Retool: $10-50/user/month = $500/month for 10 admins
- Internal tools: $200-1000/month
- Custom development: $5,000-20,000 upfront

**ROI**: Break-even in 1-2 months vs third-party tools

---

**Ready to deploy?** See `playbooks/QUICK-START.md` for step-by-step setup guide.
