# Privacy & HIPAA Compliance Guide

**For CBT Journaling Module in Psychology Practice Applications**

**IMPORTANT:** This guide provides technical implementation guidelines. It is NOT legal advice. Consult with a healthcare compliance attorney before deploying in a clinical setting.

---

## Overview

When implementing CBT journaling features in psychology practice apps, you must comply with:

1. **HIPAA** (Health Insurance Portability and Accountability Account) - US healthcare privacy law
2. **HITECH Act** - Extends HIPAA to electronic health records
3. **State-specific laws** - Some states have additional requirements
4. **GDPR** - If serving EU residents
5. **Professional ethics codes** (APA, NASW, ACA)

---

## HIPAA Requirements

### Protected Health Information (PHI)

**What is PHI?**
Any individually identifiable health information, including:
- Patient names, contact information
- Therapy notes, thought records, mood logs
- Diagnosis, treatment plans
- Any health-related data linked to an individual

**PHI in CBT Module:**
- ✅ Thought records - PHI
- ✅ Mood entries - PHI
- ✅ Homework assignments - PHI
- ✅ Therapy session notes - PHI
- ❌ Anonymized, aggregated analytics - Not PHI

### Technical Safeguards Required

#### 1. Encryption

**At Rest:**
- All PHI must be encrypted using AES-256 or equivalent
- Database-level encryption (e.g., Supabase encryption at rest)
- File encryption for exported data

**In Transit:**
- TLS 1.2 or higher for all API calls
- Certificate pinning recommended for mobile apps
- No PHI in URL parameters (use POST body)

```typescript
// ✅ GOOD: PHI in encrypted request body
fetch('/api/thought-records', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ situation: 'Patient note...' })
});

// ❌ BAD: PHI in URL
fetch(`/api/thought-records?situation=${patientNote}`);
```

#### 2. Access Controls

**Authentication:**
- Multi-factor authentication (MFA) required for therapists
- Strong password requirements (12+ chars, complexity)
- Session timeout after 15 minutes of inactivity
- Account lockout after 5 failed login attempts

**Authorization (Row-Level Security):**
```sql
-- Example: Users can only access their own data
CREATE POLICY thought_records_user_policy ON thought_records
  FOR ALL
  USING (auth.uid() = user_id);

-- Therapists can view shared records only
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
```

#### 3. Audit Logging

Log all access to PHI:
- Who accessed what data
- When (timestamp)
- What action (create, read, update, delete)
- Result (success/failure)

**Implementation:**
```sql
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_id UUID NOT NULL,
  action VARCHAR(50) NOT NULL, -- 'create', 'read', 'update', 'delete'
  resource_type VARCHAR(100) NOT NULL, -- 'thought_record', 'mood_entry', etc.
  resource_id UUID,
  ip_address INET,
  user_agent TEXT,
  result VARCHAR(20) NOT NULL, -- 'success', 'failure', 'unauthorized'
  metadata JSONB
);

-- Retain audit logs for 6+ years per HIPAA
```

Middleware example:
```typescript
// Audit log middleware
export async function auditLog(
  userId: string,
  action: string,
  resourceType: string,
  resourceId: string | null,
  result: string
) {
  await supabase.from('audit_logs').insert({
    user_id: userId,
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    ip_address: request.ip,
    user_agent: request.headers.get('user-agent'),
    result,
  });
}
```

#### 4. Data Backup & Recovery

**Requirements:**
- Automatic encrypted backups daily
- Offsite backup storage (different geographic region)
- Disaster recovery plan with RTO < 24 hours
- Backup restoration testing quarterly

**Supabase Example:**
- Enable daily point-in-time recovery
- Replicate to separate region
- Test restoration monthly

#### 5. Data Retention & Destruction

**Retention Policies:**
- Active records: As long as clinically necessary
- Inactive records (patient discharged): Minimum 7 years (varies by state)
- Minors: Until age 18 + 7 years (in most states)
- Audit logs: 6 years minimum

**Secure Deletion:**
- Never hard delete PHI immediately
- Use soft deletion (archive flag) for recovery period
- After retention period, use secure erasure:
  - Overwrite data 3+ times
  - Use database-level encryption key destruction
  - Document deletion in audit log

```sql
-- Soft delete (archive)
UPDATE thought_records SET is_archived = true WHERE id = ?;

-- Hard delete after retention period (automated job)
DELETE FROM thought_records
WHERE is_archived = true
AND updated_at < NOW() - INTERVAL '7 years';
```

---

## Business Associate Agreements (BAA)

### Required BAAs

If you use third-party services that access PHI, you MUST have signed BAAs:

**Common Services Requiring BAA:**
- ✅ Hosting provider (AWS, Google Cloud, Azure)
- ✅ Database (Supabase, Postgres, MongoDB)
- ✅ Email service (SendGrid, Mailgun) - if sending PHI
- ✅ Analytics (if tracking PHI) - Mixpanel, Amplitude
- ✅ Cloud storage (S3, Google Cloud Storage)
- ✅ SMS/notifications (Twilio) - if sending PHI

**Services NOT Requiring BAA (if no PHI access):**
- ❌ CDN (CloudFlare) - static assets only
- ❌ Payment processor (Stripe) - if no PHI in transactions
- ❌ Error tracking (Sentry) - if PHI is scrubbed from errors

**Vendor BAA Checklist:**
- Supabase: [Yes, provides BAA](https://supabase.com/docs/guides/platform/hipaa)
- AWS: [Yes, via AWS Artifact](https://aws.amazon.com/compliance/hipaa-compliance/)
- Vercel: [Yes, on Enterprise plan](https://vercel.com/docs/security/hipaa)
- OpenAI: [Not yet HIPAA-compliant as of 2026](https://platform.openai.com/docs/privacy)

⚠️ **CRITICAL:** Do NOT send PHI to OpenAI, Claude, or other AI APIs unless they provide a BAA. Use AI only for de-identified data.

---

## Security Best Practices

### 1. Input Validation & Sanitization

Prevent SQL injection, XSS:
```typescript
import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';

// Validate input
const schema = z.object({
  situation: z.string().min(1).max(5000),
  emotions: z.array(z.object({
    emotion: z.string(),
    intensity: z.number().min(0).max(100)
  }))
});

// Sanitize HTML (if allowing rich text)
const sanitized = DOMPurify.sanitize(userInput);
```

### 2. Rate Limiting

Prevent brute force and DoS attacks:
```typescript
// Example with Vercel Rate Limiting
import { rateLimit } from '@/lib/rate-limit';

const limiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  uniqueTokenPerInterval: 500,
});

export async function POST(request: NextRequest) {
  const ip = request.ip ?? '127.0.0.1';
  const { success } = await limiter.check(10, ip); // 10 requests per minute

  if (!success) {
    return NextResponse.json(
      { error: 'Rate limit exceeded' },
      { status: 429 }
    );
  }

  // Continue with request...
}
```

### 3. Error Handling

Never expose sensitive information in error messages:
```typescript
// ❌ BAD: Leaks database structure
catch (error) {
  return NextResponse.json({ error: error.message }, { status: 500 });
}

// ✅ GOOD: Generic error message, log details server-side
catch (error) {
  console.error('Thought record creation failed:', error);
  await logErrorToSentry(error); // With PHI scrubbed
  return NextResponse.json(
    { error: 'Failed to create thought record. Please try again.' },
    { status: 500 }
  );
}
```

### 4. Session Management

```typescript
// Secure session configuration
const sessionConfig = {
  httpOnly: true, // Prevent XSS
  secure: process.env.NODE_ENV === 'production', // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 60 * 15, // 15 minute timeout
  path: '/',
};

// Auto-logout after inactivity
let inactivityTimeout: NodeJS.Timeout;

function resetInactivityTimer() {
  clearTimeout(inactivityTimeout);
  inactivityTimeout = setTimeout(() => {
    // Log user out
    supabase.auth.signOut();
  }, 15 * 60 * 1000); // 15 minutes
}

// Reset on user activity
document.addEventListener('mousemove', resetInactivityTimer);
document.addEventListener('keypress', resetInactivityTimer);
```

---

## Patient Rights Under HIPAA

### Right to Access

Patients can request copies of their data within 30 days:

**Implementation:**
```typescript
// Export all patient data
export async function exportPatientData(userId: string) {
  const supabase = createServerClient();

  const [thoughtRecords, moodEntries, activities] = await Promise.all([
    supabase.from('thought_records').select('*').eq('user_id', userId),
    supabase.from('mood_entries').select('*').eq('user_id', userId),
    supabase.from('activity_log').select('*').eq('user_id', userId),
  ]);

  return {
    export_date: new Date().toISOString(),
    patient_id: userId,
    data: {
      thought_records: thoughtRecords.data,
      mood_entries: moodEntries.data,
      activities: activities.data,
    },
  };
}

// Provide as encrypted PDF or JSON download
```

### Right to Amend

Patients can request corrections:
- Allow users to edit their entries
- Maintain version history (don't overwrite)
- Log amendments in audit trail

### Right to Delete

Patients can request deletion of their data:
- Provide "Delete My Account" feature
- Retain minimum data required by law
- Document deletion requests

```typescript
export async function deletePatientAccount(userId: string) {
  const supabase = createServerClient();

  // Audit the deletion request
  await supabase.from('audit_logs').insert({
    user_id: userId,
    action: 'account_deletion_requested',
    timestamp: new Date().toISOString(),
  });

  // Anonymize or delete after retention period
  // For immediate deletion (with patient consent):
  await supabase.from('thought_records').delete().eq('user_id', userId);
  await supabase.from('mood_entries').delete().eq('user_id', userId);
  await supabase.auth.admin.deleteUser(userId);
}
```

---

## GDPR Compliance (for EU users)

If serving EU residents, additional requirements:

### 1. Consent

- Explicit, informed consent before collecting data
- Separate consent for different data uses
- Easy to withdraw consent

### 2. Data Minimization

- Only collect data necessary for therapy
- Don't collect optional fields by default

### 3. Privacy by Design

- Privacy settings default to most restrictive
- Clear privacy policy
- Data protection impact assessment (DPIA)

### 4. Right to Portability

- Allow users to export data in machine-readable format (JSON, CSV)

### 5. Right to be Forgotten

- Delete data upon request (unless legally required to retain)

---

## Mobile App Specific Considerations

### iOS/Android Security

```swift
// iOS: Secure Keychain storage for tokens
import KeychainSwift

let keychain = KeychainSwift()
keychain.set(accessToken, forKey: "auth_token")

// Enable biometric authentication
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
  localizedReason: "Access your therapy journal")
```

```kotlin
// Android: EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
  .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
  .build()

val sharedPreferences = EncryptedSharedPreferences.create(
  context,
  "secure_prefs",
  masterKey,
  EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
  EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

### Prevent Screenshots

```swift
// iOS: Prevent screenshots of sensitive screens
NotificationCenter.default.addObserver(
  forName: UIApplication.userDidTakeScreenshotNotification,
  object: nil,
  queue: .main
) { _ in
  // Log screenshot attempt
  analytics.logEvent("screenshot_attempted")
  // Optionally blur screen
}

// Hide content when app goes to background
NotificationCenter.default.addObserver(
  forName: UIApplication.willResignActiveNotification,
  object: nil,
  queue: .main
) { _ in
  // Show privacy screen
  showPrivacyOverlay()
}
```

```kotlin
// Android: FLAG_SECURE prevents screenshots
window.setFlags(
  WindowManager.LayoutParams.FLAG_SECURE,
  WindowManager.LayoutParams.FLAG_SECURE
)
```

---

## Breach Notification Requirements

If PHI is compromised, you must:

1. **Notify affected patients** within 60 days
2. **Notify HHS** (Department of Health & Human Services) if > 500 patients
3. **Notify media** if > 500 patients in same jurisdiction
4. **Document the breach** - what happened, when, impact, remediation

**Breach Response Plan:**
- Contain the breach immediately
- Assess scope (how many records, what data)
- Notify legal counsel
- Preserve evidence
- Notify affected parties
- Implement remediation

---

## Recommended Security Checklist

### Before Launch

- [ ] BAAs signed with all subprocessors
- [ ] Encryption enabled (at rest & in transit)
- [ ] Row-level security policies implemented
- [ ] Audit logging enabled
- [ ] Authentication with MFA
- [ ] Session timeout configured (15 min)
- [ ] Rate limiting implemented
- [ ] Input validation & sanitization
- [ ] Error messages don't leak PHI
- [ ] Backup & disaster recovery tested
- [ ] Privacy policy published
- [ ] HIPAA training for staff
- [ ] Security risk assessment completed
- [ ] Penetration testing completed
- [ ] Data retention policies documented

### Ongoing

- [ ] Quarterly access reviews
- [ ] Monthly backup restoration tests
- [ ] Annual HIPAA compliance training
- [ ] Annual security risk assessments
- [ ] Incident response drills
- [ ] Vendor BAA renewals
- [ ] Audit log reviews (weekly)

---

## Resources

**Official Guidelines:**
- [HHS HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [HHS Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

**Compliance Tools:**
- [Aptible](https://www.aptible.com/) - HIPAA-compliant hosting
- [Drata](https://drata.com/) - Compliance automation
- [Vanta](https://www.vanta.com/) - Security & compliance monitoring

**Legal:**
- Consult healthcare compliance attorney
- Review state-specific telehealth laws
- Professional liability insurance

---

*Document Version: 1.0*
*Last Updated: 2026-01-19*
*Disclaimer: This is technical guidance, not legal advice*
