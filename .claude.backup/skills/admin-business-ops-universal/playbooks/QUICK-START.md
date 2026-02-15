# Admin & Business Operations - Quick Start Guide

**Setup Time**: 30-45 minutes
**Prerequisites**: PostgreSQL or Supabase, React/Next.js (or adapt to your stack)

---

## Phase 1: Database Setup (10 minutes)

### Step 1.1: Run Schema Migration

```bash
# Option A: If using Supabase
supabase migration new admin_analytics
# Copy contents of templates/database/admin-schema.sql
supabase db push

# Option B: If using PostgreSQL directly
psql your_database < templates/database/admin-schema.sql
```

### Step 1.2: Create Your First Admin User

```sql
-- Replace YOUR_USER_ID_HERE with your actual user ID
INSERT INTO admin_users (user_id, role, permissions)
VALUES (
  'YOUR_USER_ID_HERE',
  'super_admin',
  '{"manage_users": true, "manage_affiliates": true, "manage_promo_codes": true}'::jsonb
);
```

### Step 1.3: Verify Tables Created

```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'analytics_events',
    'api_usage',
    'daily_metrics',
    'promo_codes',
    'affiliates',
    'admin_users'
  );
```

Should return 6 tables.

---

## Phase 2: Backend Implementation (15 minutes)

### Step 2.1: Create Admin Helpers

Create `lib/admin/helpers.ts`:

```typescript
import { createServerClient } from '@/lib/supabase/server';

export async function isUserAdmin(userId: string): Promise<boolean> {
  const supabase = await createServerClient();
  const { data } = await supabase
    .from('admin_users')
    .select('id')
    .eq('user_id', userId)
    .single();
  return !!data;
}

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

export async function getRevenueMetrics(startDate: string, endDate: string) {
  const supabase = await createServerClient();
  const { data: metrics } = await supabase
    .from('daily_metrics')
    .select('metric_date, revenue_cents, mrr_cents')
    .gte('metric_date', startDate)
    .lte('metric_date', endDate);

  if (!metrics) return { totalRevenue: 0, currentMRR: 0, data: [] };

  const totalRevenue = metrics.reduce((sum, m) => sum + (m.revenue_cents || 0), 0);
  const currentMRR = metrics[metrics.length - 1]?.mrr_cents || 0;

  return { totalRevenue, currentMRR, data: metrics };
}

export function formatCurrency(cents: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
  }).format(cents / 100);
}
```

### Step 2.2: Create API Routes

Create `app/api/admin/affiliates/route.ts`:

Copy from `templates/backend/api-admin-affiliates.ts`

**Adapt for your framework:**
- **Express**: Use `router.post('/api/admin/affiliates', ...)`
- **FastAPI**: Use `@app.post("/api/admin/affiliates")`
- **Django**: Create view in `views.py`

---

## Phase 3: Frontend Dashboard (15 minutes)

### Step 3.1: Create Admin Dashboard

Create `app/admin/page.tsx`:

```typescript
import { redirect } from 'next/navigation';
import { createServerClient } from '@/lib/supabase/server';
import {
  isUserAdmin,
  getDailyMetrics,
  getRevenueMetrics,
  formatCurrency,
} from '@/lib/admin/helpers';

export default async function AdminDashboard() {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();

  // Protect admin route
  if (!user || !(await isUserAdmin(user.id))) {
    redirect('/');
  }

  // Get metrics
  const endDate = new Date().toISOString().split('T')[0];
  const startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    .toISOString()
    .split('T')[0];

  const [dailyMetrics, revenueMetrics] = await Promise.all([
    getDailyMetrics(startDate, endDate),
    getRevenueMetrics(startDate, endDate),
  ]);

  const latestMetric = dailyMetrics[dailyMetrics.length - 1];

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-8">Admin Dashboard</h1>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600">Total Users</div>
            <div className="text-3xl font-bold">
              {latestMetric?.total_users || 0}
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600">Active Users</div>
            <div className="text-3xl font-bold">
              {latestMetric?.active_users || 0}
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border p-6">
            <div className="text-sm text-gray-600">MRR</div>
            <div className="text-3xl font-bold">
              {formatCurrency(revenueMetrics.currentMRR)}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
```

### Step 3.2: Add Navigation Links

In your main navigation/layout:

```typescript
{isAdmin && (
  <Link href="/admin" className="px-4 py-2 bg-purple-600 text-white rounded">
    Admin Dashboard
  </Link>
)}
```

---

## Phase 4: Setup Metrics Aggregation (5 minutes)

### Option A: Cron Job (Recommended)

```bash
# Add to crontab (daily at midnight)
0 0 * * * psql your_database -c "SELECT update_daily_metrics();"
```

### Option B: GitHub Actions

Create `.github/workflows/daily-metrics.yml`:

```yaml
name: Update Daily Metrics
on:
  schedule:
    - cron: '0 0 * * *' # Daily at midnight UTC

jobs:
  update-metrics:
    runs-on: ubuntu-latest
    steps:
      - name: Update metrics
        run: |
          psql $DATABASE_URL -c "SELECT update_daily_metrics();"
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

### Option C: Supabase Edge Function

Create Supabase Edge Function that runs daily.

---

## Phase 5: Smoke Tests (5 minutes)

### Test 1: Admin Access

1. Log in with your admin user
2. Navigate to `/admin`
3. Should see dashboard with metrics

### Test 2: Create Affiliate

```bash
curl -X POST http://localhost:3000/api/admin/affiliates \
  -H "Content-Type: application/json" \
  -d '{
    "email": "partner@example.com",
    "name": "Partner Name",
    "commission_tier": 1
  }'
```

Should return affiliate object with generated code.

### Test 3: Verify Metrics

```sql
SELECT * FROM daily_metrics ORDER BY metric_date DESC LIMIT 7;
```

Should show last 7 days of data.

### Test 4: Check RLS Policies

Try accessing as non-admin user:

```sql
SET ROLE authenticated;
SELECT * FROM analytics_events;
```

Should return 0 rows if not admin.

---

## Phase 6: Customization Checklist

### [ ] Update Subscription Tiers

Edit `daily_metrics` table columns to match your tiers:
```sql
ALTER TABLE daily_metrics
  RENAME COLUMN pro_users TO your_tier_name_users;
```

### [ ] Customize Metrics

Add your app-specific metrics to `daily_metrics`:
```sql
ALTER TABLE daily_metrics
  ADD COLUMN custom_metric INTEGER DEFAULT 0;
```

### [ ] Update `update_daily_metrics()` Function

Modify to calculate your custom metrics.

### [ ] Configure Affiliate Commission Rates

Edit commission tiers in API route or database:
```typescript
const commissionRates = {
  1: 30, // Change to your rates
  2: 40,
  3: 50,
};
```

### [ ] Add Promo Code Types

Customize discount types for your use case.

### [ ] Setup Email Notifications

Add email alerts for:
- New affiliates
- High-value referrals
- Promo code usage spikes

---

## Phase 7: Production Checklist

### Security

- [ ] Enable 2FA for all admin users
- [ ] Add IP whitelisting for admin routes (optional)
- [ ] Review and test all RLS policies
- [ ] Audit log all admin actions
- [ ] Set up rate limiting on admin API routes

### Performance

- [ ] Add database indexes (already in schema)
- [ ] Enable query caching for metrics
- [ ] Implement pagination for user lists (100+ users)
- [ ] Setup CDN for admin assets

### Monitoring

- [ ] Setup error tracking (Sentry, Rollbar)
- [ ] Add performance monitoring
- [ ] Create alerts for:
  - Failed daily metric updates
  - Unusual admin activity
  - API errors

### Compliance

- [ ] GDPR: Add data export functionality
- [ ] SOC 2: Audit trail for all admin actions
- [ ] PCI-DSS: If handling payments, ensure compliance

---

## Troubleshooting

### Issue: "Cannot read properties of undefined (reading 'total_users')"

**Solution**: Run `SELECT update_daily_metrics();` to populate initial data.

### Issue: "Unauthorized" when accessing /admin

**Solution**: Verify you're in the `admin_users` table:
```sql
SELECT * FROM admin_users WHERE user_id = 'YOUR_USER_ID';
```

### Issue: Metrics not updating

**Solution**: Check cron job is running:
```bash
# View cron logs
grep CRON /var/log/syslog
```

Or run manually:
```sql
SELECT update_daily_metrics();
```

### Issue: Slow dashboard load

**Solution**: Check database indexes exist:
```sql
SELECT * FROM pg_indexes WHERE tablename = 'daily_metrics';
```

---

## Next Steps

1. **Add More Pages**:
   - User management (`/admin/users`)
   - Affiliate management (`/admin/affiliates`)
   - Promo codes (`/admin/promo-codes`)

2. **Implement Charts**:
   - Install Chart.js or Recharts
   - Add revenue trend charts
   - User growth visualizations

3. **Setup Webhooks**:
   - Stripe webhooks for revenue tracking
   - Payment processor webhooks

4. **Add Exports**:
   - CSV export for metrics
   - PDF reports for stakeholders

5. **Mobile Admin App**:
   - Build React Native app
   - Key metrics dashboard
   - Push notifications for alerts

---

## Cost Breakdown

| Component | Monthly Cost |
|-----------|--------------|
| Supabase (Free tier) | $0 |
| PostgreSQL (Self-hosted) | $0 |
| Compute (minimal) | $5-10 |
| **Total** | **$5-10/month** |

vs Third-Party Admin Tools: $200-1000/month

**ROI**: Break-even in 1 month, save $2,400-12,000/year

---

## Support

- **Documentation**: See `SKILL.md` for complete reference
- **Database Schema**: `templates/database/admin-schema.sql`
- **API Examples**: `templates/backend/`
- **Frontend Components**: `SKILL.md` code examples

**Questions?** Check the troubleshooting section or review the full implementation in SKILL.md.
