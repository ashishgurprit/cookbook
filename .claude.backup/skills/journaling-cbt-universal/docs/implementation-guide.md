# CBT Journaling Module - Implementation Guide

**Step-by-step guide to integrate this module into your psychology practice app**

---

## Prerequisites

Before implementation:
- [ ] Signed BAA with hosting provider (Supabase, AWS, etc.)
- [ ] HIPAA security risk assessment completed
- [ ] Privacy policy drafted and reviewed by legal counsel
- [ ] Development environment with PostgreSQL database
- [ ] Understanding of your framework (Next.js, Express, Django, etc.)

---

## Phase 1: Database Setup (Week 1)

### Step 1.1: Install Database

**Option A: Supabase (Recommended)**
```bash
# Create Supabase project
npx supabase init
npx supabase start

# Enable encryption at rest in Supabase dashboard
# Settings → Database → Enable Point-in-Time Recovery
```

**Option B: Self-hosted PostgreSQL**
```bash
# Install PostgreSQL 14+
brew install postgresql@14

# Enable encryption
# Configure postgresql.conf:
# ssl = on
# ssl_cert_file = '/path/to/cert.pem'
```

### Step 1.2: Run Schema Migrations

```bash
# Run schemas in order:
psql -U postgres -d your_db -f schemas/thought-records.sql
psql -U postgres -d your_db -f schemas/mood-tracking.sql
psql -U postgres -d your_db -f schemas/homework-assignments.sql
```

### Step 1.3: Enable Row-Level Security

Verify RLS is enabled:
```sql
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
AND tablename IN ('thought_records', 'mood_entries', 'homework_assignments');
```

All should show `rowsecurity = true`.

### Step 1.4: Test Database Policies

```sql
-- Test as a user
SET ROLE authenticated;
SET request.jwt.claim.sub = 'test-user-id';

-- Should only return records for test-user-id
SELECT * FROM thought_records;
```

---

## Phase 2: Backend API Implementation (Week 2-3)

### Step 2.1: Install Dependencies

**Next.js:**
```bash
npm install @supabase/supabase-js zod
npm install --save-dev @types/node
```

**Express:**
```bash
npm install express @supabase/supabase-js zod express-rate-limit helmet
```

**FastAPI (Python):**
```bash
pip install fastapi supabase pydantic python-jose
```

### Step 2.2: Configure Supabase Client

**Next.js** (`lib/supabase/server.ts`):
```typescript
import { createServerClient as createClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

export async function createServerClient() {
  const cookieStore = cookies();

  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) {
          return cookieStore.get(name)?.value;
        },
      },
    }
  );
}
```

### Step 2.3: Implement API Routes

Copy and adapt templates:
```bash
# Copy API templates to your project
cp templates/api-thought-records.ts app/api/thought-records/route.ts

# Adapt to your framework
# - Update imports
# - Update authentication method
# - Add error tracking (Sentry)
```

### Step 2.4: Add Authentication

**Supabase Auth** (Recommended):
```typescript
// Set up authentication
const { data, error } = await supabase.auth.signInWithPassword({
  email: 'user@example.com',
  password: 'password',
});

// Enable MFA for therapists
await supabase.auth.mfa.enroll({
  factorType: 'totp',
});
```

### Step 2.5: Implement Audit Logging

```typescript
// Middleware for all API routes
export async function auditMiddleware(
  userId: string,
  action: string,
  resourceType: string,
  resourceId: string | null
) {
  await supabase.from('audit_logs').insert({
    user_id: userId,
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    timestamp: new Date().toISOString(),
    ip_address: request.ip,
    user_agent: request.headers.get('user-agent'),
  });
}
```

### Step 2.6: Add Rate Limiting

**Next.js (Vercel):**
```typescript
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 requests per minute
});

export async function POST(request: NextRequest) {
  const ip = request.ip ?? '127.0.0.1';
  const { success } = await ratelimit.limit(ip);

  if (!success) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 });
  }

  // Continue...
}
```

**Express:**
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
});

app.use('/api/', limiter);
```

---

## Phase 3: Frontend Implementation (Week 4-5)

### Step 3.1: Design System

Use the specs in `component-thought-record.md`:
- Create reusable form components
- Implement emotion selector
- Build distortion checklist
- Add loading states

### Step 3.2: Thought Record Form

```typescript
'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const thoughtRecordSchema = z.object({
  situation: z.string().min(1, 'Situation is required'),
  automatic_thoughts: z.string().min(1, 'Thoughts are required'),
  emotions: z.array(z.object({
    emotion: z.string(),
    intensity: z.number().min(0).max(100),
  })).min(1, 'At least one emotion required'),
});

export function ThoughtRecordForm() {
  const { register, handleSubmit, formState: { errors } } = useForm({
    resolver: zodResolver(thoughtRecordSchema),
  });

  const onSubmit = async (data) => {
    const res = await fetch('/api/thought-records', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });

    if (res.ok) {
      // Success - redirect or show success message
      router.push('/journal');
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <label>What happened?</label>
      <textarea {...register('situation')} />
      {errors.situation && <span>{errors.situation.message}</span>}

      {/* Add emotion selector, evidence fields, etc. */}
    </form>
  );
}
```

### Step 3.3: Mood Tracking Dashboard

```typescript
'use client';

import { useEffect, useState } from 'react';
import { Line } from 'react-chartjs-2';

export function MoodTrendChart({ userId }: { userId: string }) {
  const [trendData, setTrendData] = useState(null);

  useEffect(() => {
    fetch(`/api/analytics/emotion-trends?emotion=anxiety&days=30`)
      .then((res) => res.json())
      .then((data) => setTrendData(data));
  }, []);

  if (!trendData) return <div>Loading...</div>;

  const chartData = {
    labels: trendData.trends.map((t) => t.date),
    datasets: [
      {
        label: 'Anxiety Intensity',
        data: trendData.trends.map((t) => t.avg_intensity),
        borderColor: 'rgb(239, 68, 68)',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
      },
    ],
  };

  return <Line data={chartData} />;
}
```

### Step 3.4: Cognitive Distortion Helper

```typescript
export function DistortionSelector({ onSelect }: { onSelect: (ids: number[]) => void }) {
  const [selected, setSelected] = useState<number[]>([]);

  const distortions = [
    { id: 1, name: 'All-or-Nothing Thinking', description: 'Seeing things in black and white...' },
    { id: 2, name: 'Overgeneralization', description: 'Single event as pattern...' },
    // ... fetch from database
  ];

  return (
    <div>
      <h3>Which thinking patterns do you notice?</h3>
      {distortions.map((d) => (
        <label key={d.id}>
          <input
            type="checkbox"
            checked={selected.includes(d.id)}
            onChange={(e) => {
              if (e.target.checked) {
                setSelected([...selected, d.id]);
              } else {
                setSelected(selected.filter((id) => id !== d.id));
              }
            }}
          />
          <strong>{d.name}</strong>: {d.description}
        </label>
      ))}
      <button onClick={() => onSelect(selected)}>Save</button>
    </div>
  );
}
```

---

## Phase 4: Security Hardening (Week 6)

### Step 4.1: Enable HTTPS

**Production (Vercel/Netlify):**
- Automatic HTTPS
- Configure custom domain

**Self-hosted:**
```bash
# Install Let's Encrypt
sudo certbot --nginx -d yourdomain.com
```

### Step 4.2: Configure CSP Headers

**Next.js** (`next.config.js`):
```javascript
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: https:",
              "font-src 'self' data:",
              "connect-src 'self' https://your-supabase-url.supabase.co",
            ].join('; '),
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },
};
```

### Step 4.3: Scrub PHI from Error Logs

**Sentry Configuration:**
```typescript
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  beforeSend(event) {
    // Remove PHI fields
    if (event.request?.data) {
      delete event.request.data.situation;
      delete event.request.data.automatic_thoughts;
      delete event.request.data.notes;
    }
    return event;
  },
});
```

### Step 4.4: Session Security

```typescript
// Configure secure cookies
export const sessionConfig = {
  cookieName: 'session',
  password: process.env.SESSION_SECRET, // 32+ character random string
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 60 * 15, // 15 minutes
    path: '/',
  },
};

// Auto-logout on inactivity
useEffect(() => {
  let timeout;
  const resetTimer = () => {
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      supabase.auth.signOut();
      router.push('/login?reason=timeout');
    }, 15 * 60 * 1000); // 15 minutes
  };

  window.addEventListener('mousemove', resetTimer);
  window.addEventListener('keypress', resetTimer);

  return () => {
    window.removeEventListener('mousemove', resetTimer);
    window.removeEventListener('keypress', resetTimer);
    clearTimeout(timeout);
  };
}, []);
```

---

## Phase 5: Testing (Week 7)

### Step 5.1: Unit Tests

```typescript
// __tests__/api/thought-records.test.ts
import { POST } from '@/app/api/thought-records/route';

describe('Thought Records API', () => {
  it('creates a thought record', async () => {
    const mockRequest = new NextRequest('http://localhost/api/thought-records', {
      method: 'POST',
      body: JSON.stringify({
        situation: 'Test situation',
        automatic_thoughts: 'Test thought',
        emotions: [{ emotion: 'anxiety', intensity: 70 }],
      }),
    });

    const response = await POST(mockRequest);
    expect(response.status).toBe(201);
  });

  it('rejects unauthenticated requests', async () => {
    // Mock unauthenticated state
    const response = await POST(mockRequestWithoutAuth);
    expect(response.status).toBe(401);
  });
});
```

### Step 5.2: Integration Tests

```typescript
// Test full workflow
it('user can create and retrieve thought record', async () => {
  // 1. Sign in
  const { data: authData } = await supabase.auth.signInWithPassword({
    email: 'test@example.com',
    password: 'testpass',
  });

  // 2. Create thought record
  const createResponse = await fetch('/api/thought-records', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${authData.session.access_token}`,
    },
    body: JSON.stringify({
      situation: 'Test',
      automatic_thoughts: 'Test thought',
      emotions: [{ emotion: 'anxiety', intensity: 80 }],
    }),
  });

  expect(createResponse.status).toBe(201);

  // 3. Retrieve thought record
  const getResponse = await fetch('/api/thought-records', {
    headers: {
      Authorization: `Bearer ${authData.session.access_token}`,
    },
  });

  const { data } = await getResponse.json();
  expect(data.length).toBeGreaterThan(0);
});
```

### Step 5.3: Security Tests

```bash
# Run penetration testing
npm install -g owasp-zap

# SQL injection tests
sqlmap -u "http://localhost:3000/api/thought-records" --batch

# XSS tests
# Test with payloads like: <script>alert('XSS')</script>
```

---

## Phase 6: Deployment (Week 8)

### Step 6.1: Pre-Deployment Checklist

- [ ] All tests passing
- [ ] Security headers configured
- [ ] Rate limiting enabled
- [ ] Audit logging verified
- [ ] Backup & restore tested
- [ ] Privacy policy live
- [ ] BAAs signed
- [ ] HIPAA training completed

### Step 6.2: Deploy to Production

**Vercel:**
```bash
vercel --prod
```

**AWS:**
```bash
# Configure environment variables
aws ssm put-parameter --name /app/supabase-url --value "..." --type SecureString

# Deploy with CloudFormation/CDK
cdk deploy --all
```

### Step 6.3: Post-Deployment

- [ ] Smoke tests (create, read, update, delete)
- [ ] Monitor error logs (Sentry, CloudWatch)
- [ ] Verify backups running
- [ ] Test disaster recovery
- [ ] Schedule security audit

---

## Phase 7: Ongoing Maintenance

### Monthly Tasks

- [ ] Review audit logs for suspicious activity
- [ ] Test backup restoration
- [ ] Review access controls
- [ ] Update dependencies (security patches)

### Quarterly Tasks

- [ ] HIPAA compliance training refresher
- [ ] Security risk assessment
- [ ] Vendor BAA renewals
- [ ] Disaster recovery drill

### Annual Tasks

- [ ] Comprehensive security audit
- [ ] Penetration testing
- [ ] Privacy policy review
- [ ] Professional liability insurance renewal

---

## Troubleshooting

### Issue: Row-Level Security blocking queries

**Symptom:** Queries return empty results

**Solution:**
```sql
-- Verify policies are correct
SELECT * FROM pg_policies WHERE tablename = 'thought_records';

-- Test as user
SET ROLE authenticated;
SET request.jwt.claim.sub = 'user-id-here';
SELECT * FROM thought_records;
```

### Issue: Rate limiting too aggressive

**Symptom:** Legitimate users getting 429 errors

**Solution:**
```typescript
// Increase limits for authenticated users
const limit = isAuthenticated ? 100 : 10;
const { success } = await ratelimit.limit(ip, { limit });
```

### Issue: Slow queries

**Symptom:** API responses > 1 second

**Solution:**
```sql
-- Add indexes
CREATE INDEX idx_thought_records_user_date
ON thought_records(user_id, situation_date DESC);

-- Analyze query performance
EXPLAIN ANALYZE
SELECT * FROM thought_records WHERE user_id = '...';
```

---

## Support & Resources

**Documentation:**
- Supabase Docs: https://supabase.com/docs
- HIPAA Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/index.html

**Community:**
- GitHub Issues: [Link to your repo]
- Discord: [Your support channel]

---

*Version: 1.0*
*Last Updated: 2026-01-19*
