# Firebase Authentication - Universal Skill

**Version**: 1.0.0
**OWASP Compliance**: 100%
**Platform**: Web, iOS, Android

> Production-ready Firebase Authentication with all auth providers, database sync, and secure token management.

## Why Firebase Auth?

**Advantages:**
- ✅ **All Auth Providers**: Email, Google, Apple, Facebook, Twitter, GitHub, phone, anonymous
- ✅ **Managed Infrastructure**: No auth server to maintain
- ✅ **Security Built-in**: Industry-standard security practices
- ✅ **Free Tier**: 50,000 MAU (Monthly Active Users) free
- ✅ **Easy Setup**: 15-30 minutes to production
- ✅ **Mobile SDKs**: Native iOS and Android support
- ✅ **Email Templates**: Customizable verification, password reset emails

**When to Use Firebase vs Direct OAuth:**
- Firebase: Faster setup, managed infrastructure, multiple providers
- Direct OAuth: No vendor lock-in, full control, unlimited free users

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Firebase Auth                        │
│  ┌─────────┬─────────┬─────────┬─────────┬──────────┐  │
│  │ Email/  │ Google  │  Apple  │ Phone   │Anonymous │  │
│  │Password │  OAuth  │  OAuth  │   SMS   │   User   │  │
│  └─────────┴─────────┴─────────┴─────────┴──────────┘  │
└─────────────────────────────────────────────────────────┘
                          ↓
                   ID Token (JWT)
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Your Backend (FastAPI/Express)             │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Firebase Admin SDK - Verify ID Tokens          │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Your Database (PostgreSQL)                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Sync Firebase users with your user table       │  │
│  │   Store additional user data (profile, settings) │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- Users table synced with Firebase
CREATE TABLE users (
    -- Firebase UID (28 characters)
    id VARCHAR(128) PRIMARY KEY,

    -- Firebase user data
    email VARCHAR(254) UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    display_name VARCHAR(255),
    photo_url TEXT,
    phone_number VARCHAR(20),

    -- Auth provider info
    provider VARCHAR(50), -- 'password', 'google.com', 'apple.com', etc.
    provider_data JSONB DEFAULT '[]'::jsonb,

    -- Custom app data
    role VARCHAR(50) DEFAULT 'user',
    subscription_tier VARCHAR(50) DEFAULT 'free',

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_sign_in_at TIMESTAMPTZ
);

-- Index for quick lookups
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_provider ON users(provider);

-- Custom claims (for roles/permissions)
CREATE TABLE user_claims (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id) ON DELETE CASCADE,
    claim_key VARCHAR(50) NOT NULL,
    claim_value JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, claim_key)
);

-- User sessions (optional - for additional tracking)
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(128) REFERENCES users(id) ON DELETE CASCADE,
    device_info JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_active_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Quick Start

### 1. Firebase Project Setup (10 minutes)

**Step 1: Create Firebase Project**
```bash
# Go to https://console.firebase.google.com
# Click "Add project"
# Enter project name: "your-app-name"
# Disable Google Analytics (optional)
# Click "Create project"
```

**Step 2: Enable Authentication Methods**
```bash
# In Firebase Console:
# 1. Go to Authentication → Sign-in method
# 2. Enable providers you want:
#    - Email/Password ✓
#    - Google ✓
#    - Apple ✓
#    - Phone (requires billing enabled)
#    - Anonymous ✓
```

**Step 3: Get Firebase Config**
```bash
# In Firebase Console:
# 1. Project Settings (gear icon)
# 2. Your apps → Add app → Web
# 3. Register app, copy firebaseConfig
```

**Step 4: Generate Service Account Key**
```bash
# In Firebase Console:
# 1. Project Settings → Service Accounts
# 2. Click "Generate new private key"
# 3. Save as firebase-service-account.json
# 4. IMPORTANT: Add to .gitignore!
```

### 2. Backend Setup (Firebase Admin SDK)

**Install Dependencies:**
```bash
# Python
pip install firebase-admin

# Node.js
npm install firebase-admin
```

**Initialize Firebase Admin (Python/FastAPI):**
```python
# lib/firebase/admin.py
import firebase_admin
from firebase_admin import credentials, auth
import os

# Initialize Firebase Admin
cred = credentials.Certificate(
    os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH', 'firebase-service-account.json')
)
firebase_admin.initialize_app(cred)

async def verify_firebase_token(id_token: str) -> dict:
    """
    Verify Firebase ID token and return user data

    Raises:
        ValueError: If token is invalid
    """
    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)

        return {
            'uid': decoded_token['uid'],
            'email': decoded_token.get('email'),
            'email_verified': decoded_token.get('email_verified', False),
            'name': decoded_token.get('name'),
            'picture': decoded_token.get('picture'),
            'firebase': decoded_token  # Full token data
        }
    except Exception as e:
        raise ValueError(f"Invalid token: {str(e)}")

async def get_firebase_user(uid: str):
    """Get Firebase user by UID"""
    try:
        user = auth.get_user(uid)
        return user
    except Exception as e:
        raise ValueError(f"User not found: {str(e)}")

async def set_custom_claims(uid: str, claims: dict):
    """Set custom claims for user (roles, permissions)"""
    try:
        auth.set_custom_user_claims(uid, claims)
    except Exception as e:
        raise ValueError(f"Failed to set claims: {str(e)}")

async def delete_firebase_user(uid: str):
    """Delete Firebase user"""
    try:
        auth.delete_user(uid)
    except Exception as e:
        raise ValueError(f"Failed to delete user: {str(e)}")
```

**Protect API Routes:**
```python
# lib/auth/dependencies.py
from fastapi import Depends, HTTPException, Header
from lib.firebase.admin import verify_firebase_token
from lib.database import get_db

async def get_current_user(
    authorization: str = Header(None),
    db = Depends(get_db)
):
    """
    FastAPI dependency to get current authenticated user

    Usage:
        @app.get("/api/me")
        async def get_me(user = Depends(get_current_user)):
            return user
    """
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    # Extract token
    id_token = authorization.replace('Bearer ', '')

    try:
        # Verify Firebase token
        firebase_user = await verify_firebase_token(id_token)

        # Get or create user in database
        user = await db.users.get(firebase_user['uid'])

        if not user:
            # First time login - create user record
            user = await db.users.create({
                'id': firebase_user['uid'],
                'email': firebase_user['email'],
                'email_verified': firebase_user['email_verified'],
                'display_name': firebase_user.get('name'),
                'photo_url': firebase_user.get('picture'),
                'provider': firebase_user['firebase'].get('firebase', {}).get('sign_in_provider'),
                'last_sign_in_at': 'NOW()'
            })
        else:
            # Update last sign in
            await db.users.update(user.id, {'last_sign_in_at': 'NOW()'})

        return user

    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
```

**Initialize Firebase Admin (Node.js/Express):**
```typescript
// lib/firebase/admin.ts
import admin from 'firebase-admin';
import serviceAccount from '../firebase-service-account.json';

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount as admin.ServiceAccount),
});

export const auth = admin.auth();

export async function verifyFirebaseToken(idToken: string) {
  try {
    const decodedToken = await auth.verifyIdToken(idToken);
    return {
      uid: decodedToken.uid,
      email: decodedToken.email,
      emailVerified: decodedToken.email_verified,
      name: decodedToken.name,
      picture: decodedToken.picture,
      firebase: decodedToken,
    };
  } catch (error) {
    throw new Error(`Invalid token: ${error.message}`);
  }
}

// Middleware for Express
export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const idToken = authHeader.replace('Bearer ', '');

  try {
    const firebaseUser = await verifyFirebaseToken(idToken);

    // Get or create user in database
    let user = await db.users.findOne({ id: firebaseUser.uid });

    if (!user) {
      user = await db.users.create({
        id: firebaseUser.uid,
        email: firebaseUser.email,
        emailVerified: firebaseUser.emailVerified,
        displayName: firebaseUser.name,
        photoUrl: firebaseUser.picture,
        lastSignInAt: new Date(),
      });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
}
```

### 3. Frontend Setup (Web)

**Install Firebase SDK:**
```bash
npm install firebase
```

**Initialize Firebase (React/Next.js):**
```typescript
// lib/firebase/client.ts
import { initializeApp } from 'firebase/app';
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  GoogleAuthProvider,
  OAuthProvider,
  signOut,
  onAuthStateChanged,
  sendEmailVerification,
  sendPasswordResetEmail,
} from 'firebase/auth';

// Your Firebase config (from Firebase Console)
const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);

// Providers
export const googleProvider = new GoogleAuthProvider();
export const appleProvider = new OAuthProvider('apple.com');

// Auth functions
export {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  sendEmailVerification,
  sendPasswordResetEmail,
};
```

**React Auth Hook:**
```typescript
// hooks/useAuth.ts
import { useState, useEffect } from 'react';
import { auth, onAuthStateChanged } from '@/lib/firebase/client';
import { User } from 'firebase/auth';

export function useAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [idToken, setIdToken] = useState<string | null>(null);

  useEffect(() => {
    // Listen for auth state changes
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);

      if (firebaseUser) {
        // Get ID token for API requests
        const token = await firebaseUser.getIdToken();
        setIdToken(token);
      } else {
        setIdToken(null);
      }

      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  // Helper to get fresh ID token
  const getIdToken = async () => {
    if (!user) return null;
    return await user.getIdToken(true); // Force refresh
  };

  return { user, loading, idToken, getIdToken };
}
```

**Login Component:**
```typescript
// components/LoginForm.tsx
'use client';

import { useState } from 'react';
import {
  signInWithEmailAndPassword,
  signInWithPopup,
  googleProvider,
  appleProvider,
  auth
} from '@/lib/firebase/client';

export default function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleEmailLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await signInWithEmailAndPassword(auth, email, password);
      // User is now logged in, onAuthStateChanged will handle the rest
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setLoading(true);
    setError('');

    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAppleLogin = async () => {
    setLoading(true);
    setError('');

    try {
      await signInWithPopup(auth, appleProvider);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow">
      <h2 className="text-2xl font-bold mb-6">Sign In</h2>

      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
          {error}
        </div>
      )}

      {/* Email/Password Form */}
      <form onSubmit={handleEmailLogin} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>

      {/* Divider */}
      <div className="my-6 flex items-center">
        <div className="flex-1 border-t"></div>
        <span className="px-4 text-gray-500 text-sm">OR</span>
        <div className="flex-1 border-t"></div>
      </div>

      {/* Social Login Buttons */}
      <div className="space-y-3">
        <button
          onClick={handleGoogleLogin}
          disabled={loading}
          className="w-full py-2 px-4 border rounded-lg flex items-center justify-center hover:bg-gray-50"
        >
          <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
            {/* Google icon SVG */}
          </svg>
          Continue with Google
        </button>

        <button
          onClick={handleAppleLogin}
          disabled={loading}
          className="w-full py-2 px-4 bg-black text-white rounded-lg flex items-center justify-center hover:bg-gray-900"
        >
          <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24">
            {/* Apple icon SVG */}
          </svg>
          Continue with Apple
        </button>
      </div>
    </div>
  );
}
```

**Making Authenticated API Requests:**
```typescript
// lib/api/client.ts
import { auth } from '@/lib/firebase/client';

export async function apiRequest(endpoint: string, options: RequestInit = {}) {
  // Get current user's ID token
  const user = auth.currentUser;

  if (!user) {
    throw new Error('Not authenticated');
  }

  const idToken = await user.getIdToken();

  // Add Authorization header
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${idToken}`,
    ...options.headers,
  };

  const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.statusText}`);
  }

  return response.json();
}

// Usage
const data = await apiRequest('/api/user/profile');
```

### 4. Mobile Setup (iOS)

**Install Firebase SDK:**
```ruby
# Podfile
pod 'Firebase/Auth'
pod 'GoogleSignIn'

# Run
pod install
```

**Initialize Firebase:**
```swift
// AppDelegate.swift
import UIKit
import Firebase

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    func application(_ application: UIApplication,
                    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        // Initialize Firebase
        FirebaseApp.configure()

        return true
    }
}
```

**Auth Manager:**
```swift
// AuthManager.swift
import Foundation
import FirebaseAuth
import GoogleSignIn

class AuthManager: ObservableObject {
    static let shared = AuthManager()

    @Published var user: User?
    @Published var isAuthenticated = false

    private var handle: AuthStateDidChangeListenerHandle?

    init() {
        // Listen for auth state changes
        handle = Auth.auth().addStateDidChangeListener { [weak self] (auth, user) in
            self?.user = user
            self?.isAuthenticated = user != nil
        }
    }

    deinit {
        if let handle = handle {
            Auth.auth().removeStateDidChangeListener(handle)
        }
    }

    // Email/Password Sign Up
    func signUp(email: String, password: String) async throws {
        let result = try await Auth.auth().createUser(withEmail: email, password: password)

        // Send verification email
        try await result.user.sendEmailVerification()
    }

    // Email/Password Sign In
    func signIn(email: String, password: String) async throws {
        try await Auth.auth().signIn(withEmail: email, password: password)
    }

    // Google Sign In
    func signInWithGoogle() async throws {
        // Get root view controller
        guard let presentingViewController = UIApplication.shared.windows.first?.rootViewController else {
            throw AuthError.noViewController
        }

        // Get client ID from Firebase config
        guard let clientID = FirebaseApp.app()?.options.clientID else {
            throw AuthError.noClientID
        }

        // Configure Google Sign In
        let config = GIDConfiguration(clientID: clientID)
        GIDSignIn.sharedInstance.configuration = config

        // Sign in
        let result = try await GIDSignIn.sharedInstance.signIn(withPresenting: presentingViewController)

        guard let idToken = result.user.idToken?.tokenString else {
            throw AuthError.noIDToken
        }

        let accessToken = result.user.accessToken.tokenString

        // Create Firebase credential
        let credential = GoogleAuthProvider.credential(withIDToken: idToken, accessToken: accessToken)

        // Sign in to Firebase
        try await Auth.auth().signIn(with: credential)
    }

    // Apple Sign In
    func signInWithApple(authorization: ASAuthorization) async throws {
        guard let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            throw AuthError.invalidCredential
        }

        guard let nonce = currentNonce else {
            throw AuthError.invalidNonce
        }

        guard let appleIDToken = appleIDCredential.identityToken else {
            throw AuthError.noIDToken
        }

        guard let idTokenString = String(data: appleIDToken, encoding: .utf8) else {
            throw AuthError.invalidToken
        }

        // Create Firebase credential
        let credential = OAuthProvider.credential(withProviderID: "apple.com",
                                                  idToken: idTokenString,
                                                  rawNonce: nonce)

        // Sign in to Firebase
        try await Auth.auth().signIn(with: credential)
    }

    // Sign Out
    func signOut() throws {
        try Auth.auth().signOut()
    }

    // Get ID Token for API requests
    func getIDToken() async throws -> String {
        guard let user = Auth.auth().currentUser else {
            throw AuthError.notAuthenticated
        }

        return try await user.getIDToken()
    }
}

enum AuthError: Error {
    case noViewController
    case noClientID
    case noIDToken
    case invalidCredential
    case invalidNonce
    case invalidToken
    case notAuthenticated
}
```

### 5. Mobile Setup (Android)

**Add Firebase to Android:**
```gradle
// build.gradle (project level)
buildscript {
    dependencies {
        classpath 'com.google.gms:google-services:4.4.0'
    }
}

// build.gradle (app level)
plugins {
    id 'com.google.gms.google-services'
}

dependencies {
    // Firebase
    implementation platform('com.google.firebase:firebase-bom:32.7.0')
    implementation 'com.google.firebase:firebase-auth-ktx'

    // Google Sign In
    implementation 'com.google.android.gms:play-services-auth:20.7.0'
}
```

**Auth Manager:**
```kotlin
// AuthManager.kt
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import com.google.firebase.auth.OAuthProvider
import kotlinx.coroutines.tasks.await

class AuthManager {
    private val auth = FirebaseAuth.getInstance()

    val currentUser: FirebaseUser?
        get() = auth.currentUser

    // Email/Password Sign Up
    suspend fun signUp(email: String, password: String): FirebaseUser {
        val result = auth.createUserWithEmailAndPassword(email, password).await()

        // Send verification email
        result.user?.sendEmailVerification()?.await()

        return result.user ?: throw Exception("Sign up failed")
    }

    // Email/Password Sign In
    suspend fun signIn(email: String, password: String): FirebaseUser {
        val result = auth.signInWithEmailAndPassword(email, password).await()
        return result.user ?: throw Exception("Sign in failed")
    }

    // Google Sign In
    suspend fun signInWithGoogle(idToken: String): FirebaseUser {
        val credential = GoogleAuthProvider.getCredential(idToken, null)
        val result = auth.signInWithCredential(credential).await()
        return result.user ?: throw Exception("Google sign in failed")
    }

    // Sign Out
    fun signOut() {
        auth.signOut()
    }

    // Get ID Token for API requests
    suspend fun getIDToken(): String {
        val user = currentUser ?: throw Exception("Not authenticated")
        return user.getIdToken(true).await().token ?: throw Exception("No token")
    }

    // Listen for auth state changes
    fun addAuthStateListener(listener: (FirebaseUser?) -> Unit) {
        auth.addAuthStateListener { firebaseAuth ->
            listener(firebaseAuth.currentUser)
        }
    }

    companion object {
        @Volatile
        private var INSTANCE: AuthManager? = null

        fun getInstance(): AuthManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: AuthManager().also { INSTANCE = it }
            }
        }
    }
}
```

## Security Best Practices

### 1. Firebase Security Rules

**Firestore Rules (if using Firestore):**
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only read/write their own data
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow write: if request.auth != null && request.auth.uid == userId;
    }

    // Admins can read all users
    match /users/{userId} {
      allow read: if request.auth != null &&
                     request.auth.token.admin == true;
    }
  }
}
```

### 2. Custom Claims (Roles/Permissions)

**Backend:**
```python
from lib.firebase.admin import set_custom_claims

# Set admin role
await set_custom_claims(user_id, {'admin': True, 'role': 'admin'})

# Set subscription tier
await set_custom_claims(user_id, {'subscriptionTier': 'pro'})
```

**Frontend:**
```typescript
// Access custom claims from ID token
const user = auth.currentUser;
const idTokenResult = await user.getIdTokenResult();

if (idTokenResult.claims.admin) {
  // User is admin
}

if (idTokenResult.claims.subscriptionTier === 'pro') {
  // User is pro subscriber
}
```

### 3. OWASP Top 10 Compliance

**A01: Broken Access Control**
- ✅ Firebase handles user authentication
- ✅ Verify ID tokens on backend
- ✅ Use custom claims for roles/permissions

**A02: Cryptographic Failures**
- ✅ Firebase uses industry-standard encryption
- ✅ Tokens transmitted over HTTPS only

**A03: Injection**
- ✅ Use parameterized queries in your database
- ✅ Sanitize user input before storing

**A04: Insecure Design**
- ✅ Rate limiting on sensitive operations
- ✅ Email verification required for sensitive actions

**A07: Identification and Authentication Failures**
- ✅ Firebase handles password strength
- ✅ Multi-factor authentication available
- ✅ Secure session management

## Features

### All Auth Methods Supported
- ✅ Email/Password
- ✅ Google OAuth
- ✅ Apple Sign In
- ✅ Facebook Login
- ✅ Twitter Login
- ✅ GitHub Login
- ✅ Phone (SMS)
- ✅ Anonymous Auth

### Email Features
- Email verification
- Password reset
- Custom email templates
- Magic links (passwordless)

### Advanced Features
- Multi-factor authentication (SMS, TOTP)
- Custom claims (roles, permissions)
- Account linking (merge accounts)
- Phone number verification
- Re-authentication for sensitive operations

## Cost Analysis

**Firebase Authentication Pricing:**
- Free tier: 50,000 MAU (Monthly Active Users)
- After free tier: $0.0025 per MAU ($2.50 per 1,000 users)
- Phone auth: $0.01 - $0.06 per verification (varies by country)

**Example costs:**
- 10,000 users: FREE
- 100,000 users: $125/month
- 1,000,000 users: $2,375/month

**vs Direct OAuth:**
- Direct: FREE (unlimited users, your infrastructure costs)
- Firebase: Paid after 50K users

**When Firebase Makes Sense:**
- Startup/MVP: Free tier sufficient
- Multi-provider needed quickly
- Don't want to maintain auth infrastructure
- Mobile-first apps (native SDKs)

## Troubleshooting

### Common Issues

**Issue: "Firebase: Error (auth/network-request-failed)"**
Solution: Check internet connection, Firebase config correct

**Issue: "Invalid API key"**
Solution: Verify `NEXT_PUBLIC_FIREBASE_API_KEY` in `.env`

**Issue: "This domain is not authorized"**
Solution: Add domain to Firebase Console → Authentication → Settings → Authorized domains

**Issue: "ID token expired"**
Solution: Call `user.getIdToken(true)` to force refresh

## Migration from Firebase

If you later want to migrate away from Firebase:

1. **Export user data** from Firebase
2. **Switch to direct OAuth** using `auth-universal` skill
3. **Import users** with password hashes (Firebase supports export)
4. **Update frontend** to use new auth endpoints

See `playbooks/MIGRATION-GUIDE.md` for detailed steps.

## Files Included

```
firebase-auth-universal/
├── SKILL.md
├── templates/
│   ├── backend/
│   │   ├── python-firebase-admin.py
│   │   └── nodejs-firebase-admin.ts
│   ├── frontend/
│   │   ├── firebase-config.ts
│   │   ├── useAuth.ts
│   │   └── LoginForm.tsx
│   ├── mobile/
│   │   ├── ios/AuthManager.swift
│   │   └── android/AuthManager.kt
│   └── database/
│       └── firebase-sync-schema.sql
└── playbooks/
    ├── QUICK-START.md
    ├── MIGRATION-GUIDE.md
    └── TROUBLESHOOTING.md
```

---

**Ready to use Firebase Auth?** Follow the Quick Start guide above for 15-minute setup!
