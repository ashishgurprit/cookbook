# Firebase Authentication - Quick Start Guide

**Time to implement**: 15-30 minutes
**Difficulty**: Beginner
**Platforms**: Web, iOS, Android

This guide will get you up and running with Firebase Authentication in under 30 minutes.

---

## Table of Contents

1. [Firebase Project Setup](#1-firebase-project-setup)
2. [Backend Setup](#2-backend-setup)
3. [Frontend Setup (Web)](#3-frontend-setup-web)
4. [Mobile Setup (iOS/Android)](#4-mobile-setup)
5. [Database Setup](#5-database-setup)
6. [Testing](#6-testing)
7. [Production Checklist](#7-production-checklist)

---

## 1. Firebase Project Setup

### Step 1.1: Create Firebase Project (3 minutes)

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project"
3. Enter project name (e.g., "my-app")
4. Disable Google Analytics (optional, can enable later)
5. Click "Create project"

### Step 1.2: Enable Authentication Methods (2 minutes)

1. In Firebase Console, go to **Authentication** → **Sign-in method**
2. Enable the auth methods you need:
   - **Email/Password**: Click Enable → Save
   - **Google**: Click Enable → Save
   - **Apple**: Click Enable → Configure (requires Apple Developer account)
   - **Phone**: Click Enable → Save (requires Blaze plan for production)

### Step 1.3: Get Firebase Credentials (2 minutes)

#### For Web:

1. In Firebase Console, go to **Project settings** (gear icon)
2. Under "Your apps", click "Web" (</> icon)
3. Register app with nickname
4. Copy the Firebase config:

```javascript
const firebaseConfig = {
  apiKey: "AIzaSy...",
  authDomain: "my-app.firebaseapp.com",
  projectId: "my-app",
  storageBucket: "my-app.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abc123"
};
```

#### For Backend:

1. In Firebase Console, go to **Project settings** → **Service accounts**
2. Click "Generate new private key"
3. Save JSON file as `firebase-credentials.json`

---

## 2. Backend Setup

Choose your backend framework:

### Option A: Python/FastAPI (5 minutes)

#### Install dependencies:

```bash
pip install fastapi uvicorn firebase-admin asyncpg python-dotenv
```

#### Create `.env`:

```bash
FIREBASE_CREDENTIALS_PATH=firebase-credentials.json
DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
```

#### Copy template:

```bash
cp templates/backend/python-firebase-admin.py app/auth.py
```

#### Run server:

```bash
uvicorn app.auth:app --reload
```

### Option B: Node.js/Express (5 minutes)

#### Install dependencies:

```bash
npm install express firebase-admin pg cors helmet morgan
npm install -D typescript @types/node @types/express ts-node
```

#### Create `.env`:

```bash
FIREBASE_CREDENTIALS_PATH=./firebase-credentials.json
DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
PORT=8000
```

#### Copy template:

```bash
cp templates/backend/nodejs-firebase-admin.ts src/auth.ts
```

#### Run server:

```bash
npm run dev
```

---

## 3. Frontend Setup (Web)

### Step 3.1: Install Dependencies (1 minute)

```bash
npm install firebase
```

### Step 3.2: Environment Variables (1 minute)

Create `.env.local`:

```bash
NEXT_PUBLIC_FIREBASE_API_KEY=AIzaSy...
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=my-app.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=my-app
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=my-app.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=123456789
NEXT_PUBLIC_FIREBASE_APP_ID=1:123456789:web:abc123

# Backend API
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### Step 3.3: Copy Templates (2 minutes)

```bash
# Copy Firebase config
cp templates/frontend/firebase-config.ts lib/firebase-config.ts

# Copy auth hook
cp templates/frontend/useAuth.ts lib/useAuth.ts

# Copy login form
cp templates/frontend/LoginForm.tsx components/auth/LoginForm.tsx

# Copy signup form
cp templates/frontend/SignupForm.tsx components/auth/SignupForm.tsx

# Copy API client
cp templates/frontend/api-client.ts lib/api-client.ts
```

### Step 3.4: Add AuthProvider to App (1 minute)

```tsx
// app/layout.tsx (Next.js) or App.tsx (React)
import { AuthProvider } from '@/lib/useAuth';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

### Step 3.5: Use Login Form (1 minute)

```tsx
// app/login/page.tsx
import LoginForm from '@/components/auth/LoginForm';

export default function LoginPage() {
  return <LoginForm />;
}
```

---

## 4. Mobile Setup

### iOS (Swift) - 10 minutes

#### Step 4.1: Install Firebase SDK

Add to `Podfile`:

```ruby
pod 'FirebaseAuth'
pod 'GoogleSignIn'
```

Run:

```bash
pod install
```

#### Step 4.2: Add GoogleService-Info.plist

1. In Firebase Console, go to **Project settings** → **iOS**
2. Register app with Bundle ID
3. Download `GoogleService-Info.plist`
4. Add to Xcode project root

#### Step 4.3: Configure App Delegate

```swift
import FirebaseCore

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
  func application(_ application: UIApplication,
                   didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    FirebaseApp.configure()
    return true
  }
}
```

#### Step 4.4: Copy Templates

```bash
cp templates/mobile/ios/AuthManager.swift YourApp/Auth/AuthManager.swift
cp templates/mobile/ios/LoginView.swift YourApp/Views/LoginView.swift
```

### Android (Kotlin) - 10 minutes

#### Step 4.1: Add Firebase SDK

In `build.gradle` (project):

```gradle
buildscript {
  dependencies {
    classpath 'com.google.gms:google-services:4.4.0'
  }
}
```

In `build.gradle` (app):

```gradle
plugins {
  id 'com.google.gms.google-services'
}

dependencies {
  implementation platform('com.google.firebase:firebase-bom:32.7.0')
  implementation 'com.google.firebase:firebase-auth-ktx'
  implementation 'com.google.android.gms:play-services-auth:20.7.0'
  implementation 'androidx.security:security-crypto:1.1.0-alpha06'
}
```

#### Step 4.2: Add google-services.json

1. In Firebase Console, go to **Project settings** → **Android**
2. Register app with package name
3. Download `google-services.json`
4. Add to `app/` directory

#### Step 4.3: Copy Templates

```bash
cp templates/mobile/android/AuthManager.kt app/src/main/java/com/example/app/auth/AuthManager.kt
cp templates/mobile/android/LoginActivity.kt app/src/main/java/com/example/app/ui/auth/LoginActivity.kt
```

---

## 5. Database Setup

### Step 5.1: Run Migration (2 minutes)

```bash
# Copy schema
cp templates/database/firebase-sync-schema.sql migrations/001_firebase_auth.sql

# Run migration
psql $DATABASE_URL < migrations/001_firebase_auth.sql
```

### Step 5.2: Verify Tables (1 minute)

```sql
-- Check tables were created
\dt

-- Expected tables:
-- users
-- user_profiles
-- user_auth_providers
-- user_sessions
-- auth_audit_log
```

---

## 6. Testing

### Test Email/Password Auth (3 minutes)

#### Frontend:

1. Start your app: `npm run dev`
2. Go to login page: `http://localhost:3000/login`
3. Click "Sign up" and create account
4. Check email for verification link
5. Sign in with email/password

#### Backend:

```bash
# Test token verification
curl -X POST http://localhost:8000/auth/tokens/verify \
  -H "Authorization: Bearer YOUR_ID_TOKEN"

# Test protected route
curl http://localhost:8000/me \
  -H "Authorization: Bearer YOUR_ID_TOKEN"
```

### Test Google Sign In (2 minutes)

1. Click "Continue with Google"
2. Select Google account
3. Grant permissions
4. Should be signed in automatically

### Test Database Sync (1 minute)

```sql
-- Check user was created
SELECT * FROM users;

-- Check auth providers
SELECT * FROM user_auth_providers;

-- Check audit log
SELECT * FROM auth_audit_log ORDER BY created_at DESC LIMIT 10;
```

---

## 7. Production Checklist

### Security

- [ ] Enable App Check for mobile apps
- [ ] Set up CORS allowed origins
- [ ] Configure authorized domains in Firebase Console
- [ ] Enable MFA for admin accounts
- [ ] Set up rate limiting on API endpoints
- [ ] Review and tighten RLS policies

### Monitoring

- [ ] Set up Firebase Authentication monitoring
- [ ] Configure error tracking (Sentry, etc.)
- [ ] Set up database query monitoring
- [ ] Enable audit logging for sensitive operations

### Performance

- [ ] Enable connection pooling for database
- [ ] Set up CDN for static assets
- [ ] Implement token caching on frontend
- [ ] Configure Firebase session timeouts

### Compliance

- [ ] Add Terms of Service and Privacy Policy links
- [ ] Implement account deletion (GDPR)
- [ ] Set up data retention policies
- [ ] Configure password reset email templates

---

## Common Issues & Solutions

### Issue: "Firebase: Error (auth/configuration-not-found)"

**Solution**: Make sure `GoogleService-Info.plist` (iOS) or `google-services.json` (Android) is added to your project.

### Issue: "CORS error when calling backend"

**Solution**: Update CORS configuration in backend:

```python
# Python/FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Add your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Issue: "Token verification fails"

**Solution**:
1. Check that `firebase-credentials.json` is in the correct location
2. Verify the token is being sent in `Authorization: Bearer {token}` header
3. Ensure the token hasn't expired (tokens last 1 hour)

### Issue: "Google Sign In not working on iOS"

**Solution**:
1. Check that `REVERSED_CLIENT_ID` is added to URL schemes in Info.plist
2. Verify Bundle ID matches Firebase Console configuration

---

## Next Steps

1. **Customize Auth Flow**: Modify templates to match your UI/UX
2. **Add Custom Claims**: Implement role-based access control
3. **Set Up Email Templates**: Customize verification and password reset emails
4. **Enable Additional Providers**: Add Facebook, Twitter, GitHub, or Phone auth
5. **Implement Account Linking**: Allow users to link multiple auth providers
6. **Add Session Management**: Track active sessions and allow users to revoke them

---

## Resources

- [Firebase Auth Documentation](https://firebase.google.com/docs/auth)
- [Firebase Admin SDK Reference](https://firebase.google.com/docs/reference/admin)
- [Security Best Practices](https://firebase.google.com/docs/auth/admin/manage-users)
- [OWASP Authentication Guide](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

## Need Help?

- Check `SKILL.md` for detailed implementation guide
- Review code templates in `templates/` directory
- See `TROUBLESHOOTING.md` for common issues
- Consult Firebase documentation for provider-specific setup

**Estimated Total Time**: 15-30 minutes for basic setup
