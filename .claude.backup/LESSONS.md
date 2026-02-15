# Lessons Learned - Master Repository

> Consolidated lessons from ALL projects using Streamlined Development.
> These are cross-project patterns that apply universally.

**Last Updated**: 2026-01-25
**Total Lessons**: 17
**Contributing Projects**: 4

---

## How to Use This File

1. **Before Starting Work**: Review lessons in your current work category
2. **During Work**: Apply prevention patterns from relevant lessons
3. **After Work**: Use `/project:post-mortem` to capture new lessons
4. **Contribute Back**: Use `~/streamlined-development/scripts/contribute-lesson.sh`

---

## Contributed from multi-agent-flow-content-pipeline (2026-01-18)

### LESSON: WordPress Plugin APIs May Not Match Your Assumptions
**Date**: 2026-01-18
**Category**: API Contracts
**Project**: multi-agent-flow-content-pipeline

**Symptom**: REST API returned 404 when posting to `/smap/v1/post` endpoint with content payload.

**Root Cause**: The WordPress social media plugin expects to share *existing* WordPress posts via `/share/{post_id}`, not create new posts from external data. The plugin architecture assumes WordPress is the source of truth for content.

**Solution**:
```python
# WRONG: Trying to create new posts
payload = {"title": "...", "content": "...", "image_url": "..."}
response = requests.post(f"{api_url}/post", json=payload)

# CORRECT: Share existing WordPress posts
wp_post_id = get_wordpress_post_id(slug="story-slug")
response = requests.post(f"{api_url}/share/{wp_post_id}", json={"networks": ["instagram"]})
```

**Prevention**:
- [x] Always read plugin source code (`class-smap-rest-api.php`) before integration
- [x] Check `register_rest_route()` calls to see actual endpoints
- [x] Test with OPTIONS request to discover available routes
- [ ] Add integration test that verifies endpoint structure
- [ ] Document expected API contract in integration plan

**Impact**: 15 minutes debugging, no production impact

---

### LESSON: WordPress Application Passwords Use Basic Auth, Not Bearer Tokens
**Date**: 2026-01-18
**Category**: Authentication & Identity
**Project**: multi-agent-flow-content-pipeline

**Symptom**: 401 Unauthorized error with message "Sorry, you are not allowed to do that" when using Bearer token authentication.

**Root Cause**: WordPress REST API uses Basic Authentication with Application Passwords, not Bearer token authentication. Application Passwords are WordPress's recommended authentication method for REST API access.

**Solution**:
```python
# WRONG: Bearer token
headers = {"Authorization": f"Bearer {api_key}"}
response = requests.post(url, headers=headers)

# CORRECT: Basic Auth with Application Password
response = requests.post(
    url,
    auth=(username, app_password),  # Use requests.auth
    headers={"Content-Type": "application/json"}
)
```

**Prevention**:
- [x] Always check WordPress REST API authentication docs first
- [x] Test authentication separately before full integration
- [x] Use `requests.auth` tuple for Basic Auth (cleaner than manual headers)
- [ ] Add authentication test to test suite
- [ ] Document WordPress authentication requirements in README

**Impact**: 10 minutes debugging, no production impact

---

### LESSON: Ayrshare Social Media API Has Long Processing Times (60+ seconds)
**Date**: 2026-01-18
**Category**: API Contracts / Performance
**Project**: multi-agent-flow-content-pipeline

**Symptom**: API calls timing out after 30 seconds with `ReadTimeout` error, but Instagram posts still appeared successfully.

**Root Cause**: Ayrshare's social media posting API can take 30-60+ seconds to process and post content to platforms. The default 30-second timeout was too aggressive. The plugin calls Ayrshare synchronously, so the WordPress REST API doesn't return until Ayrshare completes.

**Solution**:
```python
# WRONG: Default 30-second timeout
response = requests.post(url, json=payload, timeout=30)

# CORRECT: 90-second timeout for social media APIs
response = requests.post(
    url,
    json=payload,
    timeout=90  # Ayrshare can take 60+ seconds to post
)
```

**Why 90 seconds**:
- Ayrshare must upload images to each platform
- Each platform has different APIs with varying response times
- AI optimization (if enabled) adds 10-20 seconds
- Multiple platforms post sequentially, not in parallel

**Prevention**:
- [x] Set timeout to 90 seconds for social media posting
- [ ] Add retry logic for timeout errors (post may have succeeded)
- [ ] Consider async job queue for social media posting
- [ ] Add monitoring for API response times
- [ ] Document expected processing times in README

**Alternative Approaches Considered**:
1. **Async job queue**: Background worker posts to social media (best for scale)
2. **Fire-and-forget**: Don't wait for response (risk: no error handling)
3. **Polling**: Check status endpoint after initial request (complex)

**Chose**: Synchronous with 90s timeout (simplest, acceptable for current scale)

**Impact**: 5 minutes debugging, no production impact, post succeeded despite timeout

---

### LESSON: Test-Develop-Deploy With Real Integration Points Early
**Date**: 2026-01-18
**Category**: Testing Strategies
**Project**: multi-agent-flow-content-pipeline

**Symptom**: Multiple integration mismatches discovered only during end-to-end testing (wrong endpoint, wrong auth, wrong timeout).

**Root Cause**: Unit tests with mocks passed 100%, but real API integration had different contract than assumed. Mock-based testing validated our assumptions, not reality.

**What Went Well**:
- ✅ 27 unit tests caught all business logic issues
- ✅ Comprehensive mocking ensured testability
- ✅ Quick iteration during unit testing phase

**What Went Poorly**:
- ❌ Integration test created after implementation (should be during)
- ❌ API contract assumptions not validated early
- ❌ Real API behavior discovered late (timeout, auth, endpoints)

**Solution**:
1. **Write integration test FIRST** (before implementation)
2. **Test against real API** in development environment
3. **Keep unit tests for business logic**
4. **Use integration tests to validate assumptions**

**Prevention Checklist**:
- [ ] Create `tests/integration_test_*.py` before writing agent code
- [ ] Test authentication separately before full implementation
- [ ] Test with real API endpoints (not mocks) in dev environment
- [ ] Document actual API behavior (timeouts, rate limits, quirks)
- [ ] Run integration tests in CI/CD pipeline with test credentials

**Future Pattern**:
```python
# Step 1: Write integration test FIRST
def test_wordpress_api_share_post():
    """Integration test - hits real API"""
    agent = SocialMediaPublisherAgent()
    wp_post_id = agent._get_wordpress_post_id("test-slug")
    assert wp_post_id is not None  # Validates API contract

# Step 2: Implement based on what integration test reveals
# Step 3: Add unit tests for edge cases
```

**Impact**: 30 minutes total debugging, but prevented production issues

---

### LESSON: WordPress Plugin Deployment Requires Manual Steps
**Date**: 2026-01-18
**Category**: Deployment & Infrastructure
**Project**: multi-agent-flow-content-pipeline

**Symptom**: Plugin not available via WordPress plugin repository, required ZIP upload.

**Root Cause**: Custom WordPress plugin built in this project is not published to wordpress.org plugin repository. Manual installation required.

**Deployment Steps** (for future reference):
1. Build plugin: `cd social-media-autopost-plugin/wordpress && zip -r plugin.zip .`
2. Upload to WordPress admin: Plugins → Add New → Upload Plugin
3. Activate plugin
4. Configure Ayrshare API key in Settings → Social Media AutoPost
5. Connect platforms in Ayrshare dashboard
6. Test with a single post

**Prevention**:
- [x] Document deployment steps in deployment guide
- [ ] Create deployment script/checklist
- [ ] Consider publishing plugin to wordpress.org (if applicable)
- [ ] Add deployment verification test
- [ ] Create rollback plan

**Future Automation Opportunities**:
- WP-CLI for automated plugin installation
- Terraform/Ansible for infrastructure-as-code
- Automated deployment pipeline

**Impact**: Manual deployment required, documented for future

---


---

## Contributed from claude-essay-agent (2026-01-22)

### LESSON: API Request Default Values Must Match Tier Restrictions
**Date**: 2026-01-22
**Category**: API Contracts
**Project**: claude-essay-agent

**Symptom**: Free plan users received "Social media posts is not available on the free plan" error when creating blogs, even though there was no toggle to disable social posts.

**Root Cause**: The `include_social_posts` parameter in `BlogGenerationRequest` defaulted to `True`, but free tier doesn't allow social media posts (`social_media_enabled=False` in tier config). When users didn't explicitly set the field, the default triggered the tier restriction.

**Solution**:
```python
# WRONG: Default value conflicts with free tier restrictions
include_social_posts: bool = Field(True, description="Generate social media posts")

# CORRECT: Default to most restrictive (works for all tiers)
include_social_posts: bool = Field(False, description="Generate social media posts")
```

**Prevention**:
- Review all request model defaults against tier restrictions
- Default optional premium features to `False`
- Add test: "Free tier user can submit request with all defaults"
- Consider auto-downgrading requested features instead of blocking

---

### LESSON: Wix Plan ID Mapping Must Include All Variants
**Date**: 2026-01-22
**Category**: Payment Integration
**Project**: claude-essay-agent

**Symptom**: After upgrading subscription in Wix, the dashboard still showed the free plan.

**Root Cause**: `WIX_PLAN_MAPPING` dictionary only included short plan IDs (`starter`, `pro`), but Wix webhooks send hyphenated IDs (`starter-plan`, `pro-plan`). When the plan ID wasn't found, it defaulted to starter with a silent failure in plan assignment.

**Solution**:
```python
WIX_PLAN_MAPPING = {
    # Support BOTH formats
    "starter": {"plan_type": "starter", "credits": 10},
    "starter-plan": {"plan_type": "starter", "credits": 10},  # Added
    "pro": {"plan_type": "pro", "credits": 40},
    "pro-plan": {"plan_type": "pro", "credits": 40},  # Added
    "agency": {"plan_type": "agency", "credits": 150},  # Added
    "agency-plan": {"plan_type": "agency", "credits": 150},
}
```

**Prevention**:
- Log incoming plan IDs in webhook handlers
- Add test: Verify all Wix plan IDs from Dev Center are mapped
- Raise error (don't default) when plan ID not recognized
- Document plan ID format in integration notes

---

### LESSON: Firebase Admin SDK Must Initialize Before Request Handlers
**Date**: 2026-01-21
**Category**: Authentication & Identity
**Project**: claude-essay-agent

**Symptom**: All signup requests failed with "The default Firebase app does not exist" error.

**Root Cause**: Firebase Admin SDK was initialized inside a lazy-loading pattern in `security.py`, but production deployment didn't trigger the initialization before the first request came in.

**Solution**:
```python
# In main.py lifespan startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Firebase Admin SDK on startup
    try:
        from src.security import _initialize_firebase
        firebase_app = _initialize_firebase()
        if firebase_app:
            logger.info("Firebase Admin SDK initialized")
    except Exception as e:
        logger.warning(f"Firebase initialization error: {e}")
    yield
```

**Prevention**:
- Add health check endpoint that verifies Firebase connection
- Test startup sequence in CI/CD pipeline
- Document all required service initializations in startup

---

### LESSON: Firebase Custom UID Must Be Valid UUID Format
**Date**: 2026-01-21
**Category**: Database & Data Types
**Project**: claude-essay-agent

**Symptom**: User registration failed with "badly formed hexadecimal UUID string" when storing user in database.

**Root Cause**: Firebase `create_user()` generates its own UID format which is NOT a valid UUID. The database `users.id` column expects a UUID. Code tried to parse Firebase UID as UUID.

**Solution**:
```python
# Generate UUID FIRST, then pass to Firebase
from uuid import uuid4, UUID

user_uuid = uuid4()
user_id = str(user_uuid)

# Create Firebase user with OUR UUID as their UID
firebase_user = firebase_auth.create_user(
    uid=user_id,  # Use our UUID
    email=email,
    password=password,
)

# Use UUID object for database
user = User(id=user_uuid, ...)  # Use UUID object, not string
```

**Prevention**:
- Generate all IDs in application code, pass to external services
- Never assume external service IDs match your format
- Add type hints distinguishing `str` vs `UUID` in function signatures

---

### LESSON: Database Migrations Must Be Verified in Production
**Date**: 2026-01-21
**Category**: Database & Data Types
**Project**: claude-essay-agent

**Symptom**: All signups failed with "relation 'signup_attempts' does not exist" even though migration was created.

**Root Cause**: Alembic migration existed locally but was never applied to Railway PostgreSQL. Railway doesn't auto-run migrations - they must be executed manually or via deployment hook.

**Solution**:
```bash
# Manual migration via Railway CLI
railway connect Postgres-wIiW
\i anti_abuse_migration.sql

# Or via railway run
railway run alembic upgrade head
```

**Prevention**:
- Add migration status check to pre-deployment checklist
- Include `alembic current` in health check endpoint
- Document migration process in deployment runbook
- Consider auto-migration in railway.json start command

---

### LESSON: iOS App Icon Must Match Exact Dimensions
**Date**: 2026-01-22
**Category**: Deployment & Infrastructure
**Project**: claude-essay-agent

**Symptom**: iOS build failed with "AppIcon did not have any applicable content" error.

**Root Cause**: `AppIcon-512@2x.png` was 1000x1000 pixels but `Contents.json` specified 1024x1024 (512pt @ 2x scale).

**Solution**:
```bash
# Resize to exact required dimensions
sips -z 1024 1024 AppIcon-512@2x.png --out AppIcon-512@2x.png
```

**Prevention**:
- Validate asset dimensions in CI/CD
- Use asset generation tool that produces correct sizes
- Add iOS build to PR checks

---

## General Development Practices

### LESSON: Use pnpm Instead of npm/yarn for 50-70% Disk Space Savings
**Date**: 2026-01-22
**Category**: Performance & Infrastructure
**Project**: General (applicable to all Node.js projects)

**Symptom**:
- `node_modules` directories consuming 500MB-2GB per project
- 20-30 projects = 10-30GB of disk space
- Slow `npm install` times (2-5 minutes per project)
- CI/CD pipelines taking 5-10 minutes just for dependency installation

**Root Cause**:
npm and yarn create **full copies** of every dependency in every project. If you have React installed in 20 projects, you have 20 copies of React on disk, even though they're the same version.

**Solution - Migrate to pnpm**:

pnpm uses a **content-addressable store** with hard links:
- All packages stored once in `~/.pnpm-store`
- Projects link to the global store instead of copying
- Result: 50-70% disk space reduction

**Migration Steps**:

```bash
# 1. Install pnpm globally
curl -fsSL https://get.pnpm.io/install.sh | sh -

# 2. Migrate single project
cd /path/to/project
rm -rf node_modules package-lock.json yarn.lock
pnpm install

# 3. Test the project
pnpm dev
pnpm build
pnpm test

# 4. Commit the lockfile
git add pnpm-lock.yaml
git commit -m "chore: Migrate to pnpm for reduced disk usage"
```

**Or use the migration script**:

```bash
# Migrate single project
~/streamlined-development/scripts/migrate-to-pnpm.sh /path/to/project

# Migrate all projects in ~/Development
~/streamlined-development/scripts/batch-migrate-to-pnpm.sh

# Dry run to see what would change
~/streamlined-development/scripts/batch-migrate-to-pnpm.sh --dry-run
```

**Command Equivalents**:

| npm | pnpm |
|-----|------|
| `npm install` | `pnpm install` |
| `npm install <pkg>` | `pnpm add <pkg>` |
| `npm install -D <pkg>` | `pnpm add -D <pkg>` |
| `npm uninstall <pkg>` | `pnpm remove <pkg>` |
| `npm run dev` | `pnpm dev` |
| `npx <cmd>` | `pnpm dlx <cmd>` |

**Real-World Impact**:

Before (npm):
```
blog-automation/node_modules:     512MB
claude-essay-agent/node_modules:  728MB
enterprise-translation/node_modules: 1.2GB
nextjs-app/node_modules:          450MB
...
Total for 20 projects: ~15GB
```

After (pnpm):
```
blog-automation/node_modules:     120MB (links)
claude-essay-agent/node_modules:  180MB (links)
enterprise-translation/node_modules: 250MB (links)
nextjs-app/node_modules:          90MB (links)
~/.pnpm-store:                    2GB (actual packages)
...
Total: ~5GB (67% savings)
```

**Troubleshooting**:

**Issue**: "Cannot find module 'X'"
- **Cause**: Phantom dependency - you were using a package not listed in package.json
- **Fix**: `pnpm add <missing-package>`

**Issue**: Build fails after migration
- **Cause**: pnpm is stricter about dependency resolution
- **Fix**: Add `.npmrc` with `shamefully-hoist=true` (temporary)
- **Better fix**: Declare all dependencies properly in package.json

**CI/CD Configuration**:

GitHub Actions:
```yaml
- uses: pnpm/action-setup@v2
  with:
    version: 8

- uses: actions/setup-node@v4
  with:
    node-version: 18
    cache: 'pnpm'

- run: pnpm install --frozen-lockfile
- run: pnpm build
```

Docker:
```dockerfile
FROM node:18-alpine

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

CMD ["pnpm", "start"]
```

**Prevention**:
- Use pnpm for all new Node.js projects
- Add `.npmrc` to projects for team consistency
- Update README.md to document pnpm usage
- Configure CI/CD pipelines to use pnpm
- Run `pnpm store prune` occasionally to clean unused packages

**Benefits**:
- ✅ 50-70% disk space savings
- ✅ 2-3x faster installations
- ✅ Strict dependency resolution (no phantom deps)
- ✅ Better monorepo support
- ✅ Faster CI/CD pipelines
- ✅ Compatible with all existing npm scripts

**When to use**:
- Any Node.js/TypeScript project
- Projects with large dependency trees
- Monorepos
- Teams with multiple projects
- CI/CD pipelines that are slow

**When NOT to use**:
- Very old projects with complex npm-specific build processes
- If team refuses to adopt new tooling
- CI/CD systems that don't support pnpm (rare)

**Resources**:
- pnpm migration skill: `.claude/skills/pnpm-migration/SKILL.md`
- Migration script: `scripts/migrate-to-pnpm.sh`
- Batch migration: `scripts/batch-migrate-to-pnpm.sh`
- Official docs: https://pnpm.io

---

## Contributed from Enterprise-Translation-System (2026-01-22)

### LESSON: Apple OAuth vs Google OAuth - Different Callback Mechanisms
**Date**: 2026-01-18
**Category**: Authentication & Identity
**Project**: Enterprise-Translation-System

**Symptom**:
- Apple OAuth registration failed with CORS error: `{"error":"Internal server error","message":"Not allowed by CORS"}`
- Backend crashed with: `Error: Email not provided by OAuth provider` followed by `TypeError: cb is not a function`
- Google OAuth worked perfectly

**Root Cause**:
Apple Sign In uses a fundamentally different callback mechanism than Google:

| Provider | Callback Method | Origin Header | Email Location |
|----------|----------------|---------------|----------------|
| Google OAuth | GET redirect via user's browser | Your frontend domain | `profile.emails[0].value` |
| Apple OAuth | **POST from Apple's servers** | `appleid.apple.com` | `idToken.email` (not in profile) |

The global CORS middleware in `backend/server.js` blocked Apple's POST request because `appleid.apple.com` wasn't in the allowed origins list. Route-level CORS headers were applied too late in the middleware chain.

**Solution**:

```javascript
// backend/server.js - Dynamic CORS based on request path
app.use((req, res, next) => {
  // Special handling for Apple OAuth callback - allow any origin
  if (req.path === '/api/auth/oauth/apple/callback') {
    return cors({
      origin: true, // Allow any origin for Apple callback
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    })(req, res, next);
  }

  // Normal CORS for other routes
  cors({ /* ... normal config ... */ })(req, res, next);
});
```

```javascript
// backend/routes/oauthRoutes.js - Extract email from idToken
passport.use('apple', new AppleStrategy({
  clientID: process.env.APPLE_CLIENT_ID,
  teamID: process.env.APPLE_TEAM_ID,
  keyID: process.env.APPLE_KEY_ID,
  key: process.env.APPLE_PRIVATE_KEY,
  callbackURL: `${BACKEND_URL}/api/auth/oauth/apple/callback`,
  scope: ['name', 'email']
}, async (accessToken, refreshToken, idToken, profile, cb) => {
  try {
    // Apple provides email in idToken, not profile
    if (idToken && idToken.email && !profile.emails) {
      profile.emails = [{ value: idToken.email }];
    }

    const user = await findOrCreateOAuthUser('apple', profile, accessToken, refreshToken);
    return cb(null, user);
  } catch (error) {
    console.error('Apple OAuth error:', error);
    return cb(error, null);
  }
}));
```

**Prevention**:
- Test OAuth providers locally BEFORE deploying to production
- Document OAuth provider differences in integration docs
- Add automated test that verifies Apple callback accepts POST from any origin
- Add integration test that mocks Apple's server-to-server POST
- Create pre-deployment checklist for OAuth changes
- Add monitoring/alerts for OAuth callback failures

---

### LESSON: Firebase Auth vs Passport.js for OAuth - Choose Firebase
**Date**: 2026-01-19
**Category**: Authentication & Identity
**Project**: Enterprise-Translation-System

**Symptom**:
- Passport.js Apple strategy crashed: `secretOrPrivateKey must be an asymmetric key when using ES256`
- Multiple attempts to fix private key formatting failed
- Library proved unreliable for Apple OAuth despite working for Google

**Root Cause**:
1. **Passport.js Apple Strategy Fragility**: The `@nicokaiser/passport-apple` library has poor ES256 key parsing
2. **Key Format Complexity**: Apple requires ES256 private keys, which Passport.js handles inconsistently
3. **Better Alternative Exists**: Firebase Auth handles Apple Sign-In natively with better reliability

**Solution - Migrate to Firebase Auth**:

```javascript
// backend/services/firebaseAuthService.js
const admin = require('firebase-admin');

function initializeFirebaseAdmin() {
  const credentialsJson = process.env.FIREBASE_CREDENTIALS_JSON;
  let serviceAccount;

  try {
    // Support base64-encoded credentials
    const decoded = Buffer.from(credentialsJson, 'base64').toString('utf-8');
    serviceAccount = JSON.parse(decoded);
  } catch (e) {
    // Fallback to direct JSON with newline handling
    serviceAccount = JSON.parse(credentialsJson.replace(/\\\\n/g, '\n'));
  }

  return admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: process.env.FIREBASE_PROJECT_ID
  });
}

async function verifyFirebaseToken(idToken) {
  const decodedToken = await admin.auth().verifyIdToken(idToken);
  return {
    uid: decodedToken.uid,
    email: decodedToken.email,
    emailVerified: decodedToken.email_verified,
    displayName: decodedToken.name,
    provider: decodedToken.firebase.sign_in_provider // 'apple.com' or 'google.com'
  };
}
```

```typescript
// frontend/src/hooks/useFirebaseAuth.ts
import { signInWithPopup, OAuthProvider, GoogleAuthProvider } from 'firebase/auth';

export function useFirebaseAuth() {
  const appleProvider = new OAuthProvider('apple.com');
  const googleProvider = new GoogleAuthProvider();

  const signInWithApple = async () => {
    const result = await signInWithPopup(auth, appleProvider);
    const idToken = await getIdToken(result.user);

    // Send to backend
    const response = await fetch('/api/auth/firebase/signin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ idToken })
    });

    return await response.json();
  };

  return { signInWithApple };
}
```

**Database Schema Changes**:

```prisma
model User {
  id          String   @id @default(uuid())
  email       String   @unique
  firebaseUid String?  @unique  // Add this field
  // ... other fields
}
```

**Benefits of Firebase Auth over Passport.js**:
- ✅ Apple Sign-In works reliably (no ES256 key issues)
- ✅ Google OAuth works identically
- ✅ Better error messages and debugging
- ✅ No CORS complexity (frontend handles OAuth popup)
- ✅ Unified authentication flow for multiple providers
- ✅ Better documentation and community support

**Prevention**:
- Always create frontend `.env` locally before building
- Use `tar.gz` instead of ZIP for cross-platform file uploads (Windows → Linux)
- Add cache-busting headers to nginx config
- Document Firebase setup in project documentation
- Add automated test for Firebase Auth flow
- Pre-deployment checklist: verify .env files, clear caches, test OAuth

---

## Template for New Lessons

Use this template when contributing lessons back to master:

```markdown
### LESSON: [Short descriptive title]
**Date**: YYYY-MM-DD
**Category**: [API Contracts / Authentication / Performance / Testing / Deployment / etc.]
**Project**: [project-name]

**Symptom**: [What went wrong or what was observed]

**Root Cause**: [Why it happened]

**Solution**:
[Code example or step-by-step fix]

**Prevention**:
- [ ] Checklist item 1
- [ ] Checklist item 2

**Impact**: [Time spent, production impact]
```

---

## Lesson Categories

- **API Contracts**: Integration assumptions, endpoint discovery, API behavior
- **Authentication & Identity**: Auth methods, credentials, permissions
- **Performance**: Timeouts, rate limits, optimization
- **Testing Strategies**: Integration vs unit tests, test ordering
- **Deployment & Infrastructure**: Deployment steps, automation
- **Database & Persistence**: Schema, migrations, queries
- **Security**: OWASP, authentication, authorization
- **Error Handling**: Logging, monitoring, debugging
- **Developer Experience**: Tooling, productivity, workflows
- **Architecture Decisions**: Design patterns, technology selection

---

## Contributing Lessons

To contribute lessons from your project to master:

```bash
# Interactive: Select which lessons to contribute
~/streamlined-development/scripts/contribute-lesson.sh

# Automatic: Contribute all lessons
~/streamlined-development/scripts/contribute-lesson.sh --all
```

Lessons contributed to master will be synced to all other projects automatically.

---

## Contributed from Business-Thinking-Frameworks (2026-01-19)

### LESSON: Firebase OAuth Mobile vs Desktop Requires Different Flow Detection
**Date**: 2026-01-19
**Category**: Authentication & Identity
**Project**: Business-Thinking-Frameworks

**Context**: Implementing Firebase OAuth for Google and Apple sign-in

**Challenge**: Firebase OAuth has two flows:
- `signInWithPopup()` - Works on desktop but triggers popup blockers on mobile
- `signInWithRedirect()` - Works on mobile but causes unnecessary redirects on desktop

**Solution**:
```typescript
const isMobile = (): boolean => {
  if (typeof window === 'undefined') return false;
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    navigator.userAgent
  );
};

export const signInWithGoogle = async (): Promise<User | null> => {
  if (isMobile()) {
    await signInWithRedirect(auth, googleProvider);
    return null; // Redirect will handle the rest
  } else {
    const result = await signInWithPopup(auth, googleProvider);
    return result.user;
  }
};
```

**Key Insight**:
- Desktop flow returns user immediately → can migrate guest data synchronously
- Mobile flow returns null → must handle redirect result in callback page
- SSR consideration: Check `typeof window !== 'undefined'` before accessing navigator

**Prevention**:
- [x] Document mobile vs desktop flows in integration guide
- [x] Create dedicated callback page for redirect handling
- [x] Add useEffect in callback to process redirects
- [ ] Add E2E tests for both flows

---

### LESSON: Zustand Persistence Must Be Partial for Complex Objects
**Date**: 2026-01-19
**Category**: State Management
**Project**: Business-Thinking-Frameworks

**Symptom**: Full state persistence causes hydration mismatches in Next.js SSR with Firebase User objects

**Root Cause**: Firebase User object contains methods/functions that cannot be serialized to localStorage

**Solution**:
```typescript
export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,          // NOT persisted
      loading: true,       // NOT persisted
      isGuest: false,      // Persisted
      guestData: null,     // Persisted
      // ... actions
    }),
    {
      name: 'app-auth',
      partialize: (state) => ({
        guestData: state.guestData,  // Only persist serializable data
        isGuest: state.isGuest,
      }),
    }
  )
);
```

**Why This Works**:
- Guest data is plain JSON → safe to persist
- User object from Firebase → reconstructed on every page load via onAuthStateChanged
- Prevents hydration errors from SSR/client mismatch

**Prevention**:
- [x] Only persist serializable data
- [x] Use partialize to whitelist persisted fields
- [x] Let Firebase SDK manage auth state rehydration
- [ ] Add test for localStorage serialization

---

### LESSON: Firebase Admin SDK Requires String Replacement for Private Keys
**Date**: 2026-01-19
**Category**: Environment & Configuration
**Project**: Business-Thinking-Frameworks

**Symptom**: Admin SDK initialization fails with "invalid private key" error

**Root Cause**: Environment variables escape newlines as `\n` (two characters), but private keys need actual newline characters

**Solution**:
```typescript
// lib/firebase/admin.ts
adminApp = initializeApp({
  credential: cert({
    projectId,
    clientEmail,
    privateKey: privateKey.replace(/\\n/g, '\n'),  // Critical!
  }),
});
```

**Why This Happens**:
- `.env.local` stores multi-line keys as: `"-----BEGIN PRIVATE KEY-----\nABC...\n-----END..."`
- process.env reads this as literal string with backslash-n
- Private key parser expects actual newlines (ASCII 10)

**Prevention**:
- [x] Document in .env.example: "Keep quotes around private key"
- [x] Add replace() call in admin initialization
- [x] Add helpful error message if credentials missing
- [ ] Add validation test for private key format

---

### LESSON: Next.js Middleware Cookie Check Cannot Verify Token Validity
**Date**: 2026-01-19
**Category**: Security
**Project**: Business-Thinking-Frameworks

**Context**: Implementing route protection in Next.js middleware

**Trade-off Decision**: Basic cookie check in middleware, full token verification in API routes

**Why Not Full Verification in Middleware**:
```typescript
// middleware.ts - Basic check only
const hasAuthCookie = request.cookies.has('__session');
if (isProtectedRoute && !hasAuthCookie) {
  return NextResponse.redirect(new URL('/auth', request.url));
}
```

**Limitations**:
- Middleware runs on Edge runtime → cannot use Firebase Admin SDK
- Cookie presence ≠ valid token (could be expired or tampered)
- This is UX optimization, NOT security enforcement

**Security Enforcement Happens In API Routes**:
```typescript
const decodedToken = await verifyIdToken(token);
if (!decodedToken) {
  return unauthorizedResponse();
}
```

**Key Principle**: Middleware for UX (prevent unnecessary page loads), API routes for security (validate every request)

**Prevention**:
- [x] Document this trade-off in security guide
- [x] Add comment in middleware.ts explaining limitations
- [x] Ensure ALL API routes verify tokens
- [ ] Add security audit checklist

---

## Contributed from Enterprise-Translation-System (2026-01-19)

### LESSON: Apple OAuth vs Google OAuth - Different Callback Mechanisms
**Date**: 2026-01-19
**Category**: Authentication & Identity
**Project**: Enterprise-Translation-System

**Symptom**:
- Apple OAuth registration failed with CORS error: `Not allowed by CORS`
- Backend crashed with: `Error: Email not provided by OAuth provider`
- Google OAuth worked perfectly

**Root Cause**:
Apple Sign In uses a fundamentally different callback mechanism than Google:

| Provider | Callback Method | Origin Header | Email Location |
|----------|----------------|---------------|----------------|
| Google OAuth | GET redirect via user's browser | Your frontend domain | `profile.emails[0].value` |
| Apple OAuth | **POST from Apple's servers** | `appleid.apple.com` | `idToken.email` (not in profile) |

The global CORS middleware blocked Apple's POST request because `appleid.apple.com` wasn't in allowed origins.

**Solution**:
```javascript
// server.js - Dynamic CORS based on request path
app.use((req, res, next) => {
  if (req.path === '/api/auth/oauth/apple/callback') {
    return cors({
      origin: true, // Allow any origin for Apple callback
      credentials: true,
    })(req, res, next);
  }

  cors({ /* normal config */ })(req, res, next);
});
```

```javascript
// Extract email from idToken for Apple
passport.use('apple', new AppleStrategy({
  // ... config
}, async (accessToken, refreshToken, idToken, profile, cb) => {
  // Apple provides email in idToken, not profile
  if (idToken && idToken.email && !profile.emails) {
    profile.emails = [{ value: idToken.email }];
  }

  const user = await findOrCreateOAuthUser('apple', profile);
  return cb(null, user);
}));
```

**Prevention**:
- [x] Test OAuth providers locally BEFORE production
- [x] Document OAuth provider differences in setup guide
- [ ] Add automated test that verifies Apple callback accepts POST
- [ ] Create pre-deployment checklist for OAuth changes

---

### LESSON: Firebase Auth vs Passport.js for OAuth - Choose Firebase
**Date**: 2026-01-19
**Category**: Authentication & Identity
**Project**: Enterprise-Translation-System

**Symptom**:
- Passport.js Apple OAuth crashes: `secretOrPrivateKey must be an asymmetric key when using ES256`
- Multiple attempts to fix private key formatting fail
- Library proves unreliable despite working for Google

**Root Cause**:
1. Passport.js Apple Strategy has poor ES256 key parsing
2. Key format complexity with Apple's ES256 requirements
3. Better alternative exists: Firebase Auth handles Apple Sign-In natively

**Solution - Use Firebase Auth Instead**:

```javascript
// Backend: Firebase Admin SDK for token verification
const admin = require('firebase-admin');

async function verifyFirebaseToken(idToken) {
  const decodedToken = await admin.auth().verifyIdToken(idToken);
  return {
    uid: decodedToken.uid,
    email: decodedToken.email,
    emailVerified: decodedToken.email_verified,
    provider: decodedToken.firebase.sign_in_provider
  };
}

router.post('/firebase/signin', async (req, res) => {
  const { idToken } = req.body;
  const firebaseUser = await verifyFirebaseToken(idToken);

  // Find or create user in your database
  let user = await findUserByFirebaseUid(firebaseUser.uid);
  if (!user) {
    user = await createUser({
      email: firebaseUser.email,
      firebaseUid: firebaseUser.uid,
      emailVerified: true
    });
  }

  const tokens = await generateTokens(user);
  res.json({ user, accessToken: tokens.accessToken });
});
```

```typescript
// Frontend: Firebase SDK for OAuth popup
import { signInWithPopup, OAuthProvider } from 'firebase/auth';

const appleProvider = new OAuthProvider('apple.com');

const signInWithApple = async () => {
  const result = await signInWithPopup(auth, appleProvider);
  const idToken = await getIdToken(result.user);

  const response = await fetch('/api/auth/firebase/signin', {
    method: 'POST',
    body: JSON.stringify({ idToken })
  });

  return await response.json();
};
```

**Benefits of Firebase Auth over Passport.js**:
- ✅ Apple Sign-In works reliably (no ES256 key parsing issues)
- ✅ Google OAuth works identically (unified flow)
- ✅ Better error messages and debugging
- ✅ No CORS complexity (frontend handles OAuth popup)
- ✅ Handles token refresh automatically
- ✅ Works with multiple providers: Apple, Google, Microsoft, GitHub

**Database Schema**:
```prisma
model User {
  id          String   @id @default(uuid())
  email       String   @unique
  firebaseUid String?  @unique  // Link to Firebase Auth user
}
```

**Deployment Considerations**:
1. Frontend environment variables required for build
2. Backend needs Firebase credentials (base64-encoded service account JSON)
3. Apple Developer Console: Add Firebase Auth domain to allowed domains

**Prevention**:
- [x] Create .env.example with Firebase variable names
- [x] Document Firebase setup in project README
- [ ] Add E2E test for Firebase Auth flow
- [ ] Pre-deployment checklist: verify .env files exist

**When NOT to use this pattern**:
- Server-side OAuth without frontend JavaScript
- Native mobile apps (use Firebase native SDKs)
- Already have working Passport.js OAuth and don't need Apple

**Status**: Production-tested, Apple + Google OAuth working reliably

---

## Contributed from Enterprise-Translation-System (2026-01-25)

### LESSON: React Destructuring Variable Names Must Be Unique Across Hooks
**Date**: 2026-01-25
**Category**: React / State Management
**Project**: Enterprise-Translation-System

**Symptom**: TypeScript error "Cannot redeclare block-scoped variable 'mode'" when using multiple hooks that export similarly-named variables.

**Root Cause**: Two hooks exported a variable named `mode`:
- `useGTSTheme()` returns `{ mode }` for theme mode ('light' | 'dark')
- `useMediaRecorder()` returns `{ mode }` for recording mode ('idle' | 'recording')

When destructured in the same component, both variables collide.

**Solution**:
```typescript
// WRONG: Variable collision
const { mode, toggleMode } = useGTSTheme();
const { mode, startRecording } = useMediaRecorder(); // Error!

// CORRECT: Rename on destructure
const { mode: themeMode, toggleMode, setMode: setThemeMode } = useGTSTheme();
const { mode: recordingMode, startRecording } = useMediaRecorder();

const darkMode = themeMode === 'dark';
```

**Prevention**:
- [x] Use descriptive prefixes when destructuring hooks with common names
- [x] Consider hook naming: `useTheme` could return `themeMode` instead of `mode`
- [ ] Add ESLint rule for duplicate variable names in same scope
- [ ] Document hook return types in JSDoc

**Impact**: 5 minutes debugging, no production impact

---

### LESSON: API Endpoint Naming Must Be Consistent (camelCase vs kebab-case)
**Date**: 2026-01-25
**Category**: API Contracts
**Project**: Enterprise-Translation-System

**Symptom**: Frontend test called `/api/translate-text` but got 404. Actual endpoint was `/api/translateText`.

**Root Cause**: Inconsistent naming convention across API endpoints. Some used kebab-case, others camelCase.

**Solution**:
```javascript
// Document and enforce naming convention
// Option A: camelCase (JavaScript native)
app.post('/api/translateText', ...)

// Option B: kebab-case (REST convention)
app.post('/api/translate-text', ...)

// Pick ONE and use everywhere. This project uses camelCase.
```

**Prevention**:
- [x] Document API naming convention in README
- [x] Use consistent convention across all endpoints
- [ ] Add OpenAPI/Swagger spec that enforces naming
- [ ] Create API client that generates endpoints from spec
- [ ] Add integration test that lists all endpoints

**Impact**: 10 minutes debugging test failures

---

### LESSON: E2E Test Dependencies Must Be Installed Separately
**Date**: 2026-01-25
**Category**: Testing Strategies
**Project**: Enterprise-Translation-System

**Symptom**: E2E test failed with "Cannot find module 'socket.io-client'" even though backend uses socket.io.

**Root Cause**: Frontend tests run in isolation and need WebSocket client dependency. The backend has `socket.io` (server), but tests need `socket.io-client` (client).

**Solution**:
```bash
# In tests/ directory or project root
npm install socket.io-client --save-dev

# In test file
const { io } = require('socket.io-client');
const socket = io('http://localhost:5000');
```

**Prevention**:
- [x] Document test dependencies in README
- [x] Create separate `tests/package.json` or add to devDependencies
- [ ] Add `npm run test:setup` script that installs test deps
- [ ] CI pipeline should install test dependencies explicitly

**Impact**: 2 minutes to identify, immediate fix

---

### LESSON: Git Working Directory May Not Match Git History
**Date**: 2026-01-25
**Category**: Git / Version Control
**Project**: Streamlined-Development

**Symptom**: `.claude/commands/` folder documented everywhere but didn't exist in working directory. Commands like `/project:post-mortem` failed.

**Root Cause**: Files existed in git history but were deleted from working directory without being committed as deletions. Git status showed clean because files were never tracked in current state.

**Solution**:
```bash
# Check if files exist in git history
git ls-tree -r HEAD --name-only | grep "commands/"

# Restore from specific commit
git show <commit>:.claude/commands/post-mortem.md

# Restore entire folder from history
git checkout <commit> -- .claude/commands/
```

**Prevention**:
- [x] After major git operations, verify critical folders with `ls`
- [x] Add folder structure verification to CI
- [ ] Create `.claude/commands/.gitkeep` to ensure folder is tracked
- [ ] Add pre-commit hook that verifies expected folders exist

**Impact**: 15 minutes searching for "lost" files that were in history all along

---

