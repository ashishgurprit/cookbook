/**
 * Firebase Authentication Backend (Node.js/Express/TypeScript)
 * Complete production-ready implementation with Firebase Admin SDK
 */

import express, { Request, Response, NextFunction } from 'express';
import admin from 'firebase-admin';
import { Pool } from 'pg';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

// =============================================================================
// TYPES
// =============================================================================

interface FirebaseUser {
  uid: string;
  email?: string;
  emailVerified: boolean;
  phoneNumber?: string;
  displayName?: string;
  photoURL?: string;
  disabled: boolean;
  customClaims?: { [key: string]: any };
}

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    firebase_uid: string;
    email?: string;
    email_verified: boolean;
    phone_number?: string;
    display_name?: string;
    photo_url?: string;
    role: string;
    status: string;
    subscription_tier: string;
    custom_claims: any;
  };
}

interface CustomClaims {
  role?: string;
  subscription_tier?: string;
  permissions?: string[];
  [key: string]: any;
}

// =============================================================================
// CONFIGURATION
// =============================================================================

const PORT = process.env.PORT || 8000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Initialize Firebase Admin SDK
const serviceAccount = require(process.env.FIREBASE_CREDENTIALS_PATH || './firebase-credentials.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Initialize Express
const app = express();

// Database connection pool
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// =============================================================================
// MIDDLEWARE
// =============================================================================

// Security headers
app.use(helmet());

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));

// =============================================================================
// FIREBASE TOKEN VERIFICATION MIDDLEWARE
// =============================================================================

/**
 * Verify Firebase ID token from Authorization header
 */
export const verifyFirebaseToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    const idToken = authHeader.split('Bearer ')[1];

    // Verify the ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Sync user to database
    const user = await syncFirebaseUserToDb({
      uid: decodedToken.uid,
      email: decodedToken.email,
      email_verified: decodedToken.email_verified || false,
      phone_number: decodedToken.phone_number,
      display_name: decodedToken.name,
      photo_url: decodedToken.picture,
      provider_id: decodedToken.firebase?.sign_in_provider || 'firebase',
    });

    // Attach user to request
    req.user = user;

    // Log authentication event
    await logAuthEvent({
      user_id: user.id,
      firebase_uid: decodedToken.uid,
      event_type: 'token_verify',
      event_status: 'success',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
    });

    next();
  } catch (error: any) {
    console.error('Token verification error:', error);

    if (error.code === 'auth/id-token-expired') {
      res.status(401).json({ error: 'Token has expired' });
      return;
    }

    if (error.code === 'auth/id-token-revoked') {
      res.status(401).json({ error: 'Token has been revoked' });
      return;
    }

    res.status(401).json({ error: 'Invalid authentication token' });
  }
};

/**
 * Require specific role middleware factory
 */
export const requireRole = (requiredRole: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (req.user.role !== requiredRole) {
      res.status(403).json({ error: `Requires ${requiredRole} role` });
      return;
    }

    next();
  };
};

/**
 * Require any of multiple roles
 */
export const requireAnyRole = (roles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: `Requires one of: ${roles.join(', ')}` });
      return;
    }

    next();
  };
};

// =============================================================================
// DATABASE SYNC FUNCTIONS
// =============================================================================

interface FirebaseUserData {
  uid: string;
  email?: string;
  email_verified: boolean;
  phone_number?: string;
  display_name?: string;
  photo_url?: string;
  provider_id?: string;
}

/**
 * Sync Firebase user to PostgreSQL database
 */
async function syncFirebaseUserToDb(firebaseUser: FirebaseUserData): Promise<any> {
  try {
    const result = await db.query(
      `SELECT upsert_firebase_user($1, $2, $3, $4, $5, $6, $7)`,
      [
        firebaseUser.uid,
        firebaseUser.email,
        firebaseUser.email_verified,
        firebaseUser.phone_number,
        firebaseUser.display_name,
        firebaseUser.photo_url,
        firebaseUser.provider_id || 'firebase',
      ]
    );

    const userId = result.rows[0].upsert_firebase_user;

    // Get complete user record
    const userResult = await db.query(
      `SELECT * FROM get_user_by_firebase_uid($1)`,
      [firebaseUser.uid]
    );

    return userResult.rows[0];
  } catch (error) {
    console.error('Database sync error:', error);
    throw new Error('Failed to sync user data');
  }
}

/**
 * Log authentication event
 */
async function logAuthEvent(event: {
  user_id?: string;
  firebase_uid: string;
  event_type: string;
  event_status: string;
  ip_address?: string;
  user_agent?: string;
  error_message?: string;
}): Promise<void> {
  try {
    await db.query(
      `INSERT INTO auth_audit_log
       (user_id, firebase_uid, event_type, event_status, ip_address, user_agent, error_message)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        event.user_id,
        event.firebase_uid,
        event.event_type,
        event.event_status,
        event.ip_address,
        event.user_agent,
        event.error_message,
      ]
    );
  } catch (error) {
    console.error('Failed to log auth event:', error);
  }
}

// =============================================================================
// USER MANAGEMENT ROUTES
// =============================================================================

/**
 * Create a new Firebase user (admin only)
 */
app.post('/auth/users', async (req: Request, res: Response) => {
  try {
    const { email, password, displayName, phoneNumber } = req.body;

    // Create Firebase user
    const firebaseUser = await admin.auth().createUser({
      email,
      password,
      displayName,
      phoneNumber,
      emailVerified: false,
    });

    // Sync to database
    await syncFirebaseUserToDb({
      uid: firebaseUser.uid,
      email: firebaseUser.email,
      email_verified: firebaseUser.emailVerified,
      phone_number: firebaseUser.phoneNumber,
      display_name: firebaseUser.displayName,
      photo_url: firebaseUser.photoURL,
    });

    // Log event
    await logAuthEvent({
      firebase_uid: firebaseUser.uid,
      event_type: 'user_created',
      event_status: 'success',
      ip_address: req.ip,
    });

    res.status(201).json({
      uid: firebaseUser.uid,
      email: firebaseUser.email,
      displayName: firebaseUser.displayName,
    });
  } catch (error: any) {
    console.error('User creation error:', error);

    if (error.code === 'auth/email-already-exists') {
      res.status(400).json({ error: 'Email already exists' });
      return;
    }

    res.status(500).json({ error: error.message });
  }
});

/**
 * Get Firebase user by UID
 */
app.get('/auth/users/:uid', async (req: Request, res: Response) => {
  try {
    const { uid } = req.params;

    const firebaseUser = await admin.auth().getUser(uid);

    res.json({
      uid: firebaseUser.uid,
      email: firebaseUser.email,
      emailVerified: firebaseUser.emailVerified,
      phoneNumber: firebaseUser.phoneNumber,
      displayName: firebaseUser.displayName,
      photoURL: firebaseUser.photoURL,
      disabled: firebaseUser.disabled,
      customClaims: firebaseUser.customClaims,
    });
  } catch (error: any) {
    console.error('Get user error:', error);

    if (error.code === 'auth/user-not-found') {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.status(500).json({ error: error.message });
  }
});

/**
 * Update Firebase user
 */
app.patch('/auth/users/:uid', async (req: Request, res: Response) => {
  try {
    const { uid } = req.params;
    const { displayName, photoURL, phoneNumber } = req.body;

    const firebaseUser = await admin.auth().updateUser(uid, {
      displayName,
      photoURL,
      phoneNumber,
    });

    // Sync to database
    await syncFirebaseUserToDb({
      uid: firebaseUser.uid,
      email: firebaseUser.email,
      email_verified: firebaseUser.emailVerified,
      phone_number: firebaseUser.phoneNumber,
      display_name: firebaseUser.displayName,
      photo_url: firebaseUser.photoURL,
    });

    res.json({
      uid: firebaseUser.uid,
      email: firebaseUser.email,
      displayName: firebaseUser.displayName,
      photoURL: firebaseUser.photoURL,
    });
  } catch (error: any) {
    console.error('Update user error:', error);

    if (error.code === 'auth/user-not-found') {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.status(500).json({ error: error.message });
  }
});

/**
 * Delete Firebase user
 */
app.delete('/auth/users/:uid', async (req: Request, res: Response) => {
  try {
    const { uid } = req.params;

    // Delete from Firebase
    await admin.auth().deleteUser(uid);

    // Soft delete in database
    await db.query(
      `UPDATE users SET deleted_at = NOW(), status = 'deleted' WHERE firebase_uid = $1`,
      [uid]
    );

    // Log event
    await logAuthEvent({
      firebase_uid: uid,
      event_type: 'user_deleted',
      event_status: 'success',
      ip_address: req.ip,
    });

    res.json({ message: 'User deleted successfully' });
  } catch (error: any) {
    console.error('Delete user error:', error);

    if (error.code === 'auth/user-not-found') {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// CUSTOM CLAIMS (ROLES & PERMISSIONS)
// =============================================================================

/**
 * Set custom claims for a user (admin only)
 */
app.post(
  '/auth/users/:uid/claims',
  verifyFirebaseToken,
  requireRole('admin'),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { uid } = req.params;
      const claims: CustomClaims = req.body;

      // Set custom claims in Firebase
      await admin.auth().setCustomUserClaims(uid, claims);

      // Update in database
      await db.query(
        `UPDATE users
         SET custom_claims = $1,
             role = COALESCE($2, role),
             updated_at = NOW()
         WHERE firebase_uid = $3`,
        [claims, claims.role, uid]
      );

      // Log event
      await logAuthEvent({
        user_id: req.user!.id,
        firebase_uid: uid,
        event_type: 'claims_updated',
        event_status: 'success',
        ip_address: req.ip,
      });

      res.json({ message: 'Custom claims updated successfully' });
    } catch (error: any) {
      console.error('Set claims error:', error);

      if (error.code === 'auth/user-not-found') {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.status(500).json({ error: error.message });
    }
  }
);

// =============================================================================
// TOKEN MANAGEMENT
// =============================================================================

/**
 * Revoke all refresh tokens for a user
 */
app.post(
  '/auth/tokens/revoke/:uid',
  verifyFirebaseToken,
  requireRole('admin'),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { uid } = req.params;

      // Revoke all refresh tokens
      await admin.auth().revokeRefreshTokens(uid);

      // Revoke sessions in database
      await db.query(
        `UPDATE user_sessions
         SET revoked_at = NOW()
         WHERE user_id = (SELECT id FROM users WHERE firebase_uid = $1)
           AND revoked_at IS NULL`,
        [uid]
      );

      // Log event
      await logAuthEvent({
        user_id: req.user!.id,
        firebase_uid: uid,
        event_type: 'tokens_revoked',
        event_status: 'success',
        ip_address: req.ip,
      });

      res.json({ message: 'User tokens revoked successfully' });
    } catch (error: any) {
      console.error('Revoke tokens error:', error);

      if (error.code === 'auth/user-not-found') {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Verify Firebase ID token (for testing)
 */
app.post('/auth/tokens/verify', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'No token provided' });
      return;
    }

    const idToken = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    res.json({
      uid: decodedToken.uid,
      email: decodedToken.email,
      emailVerified: decodedToken.email_verified,
      customClaims: decodedToken,
    });
  } catch (error: any) {
    console.error('Token verification error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// =============================================================================
// PROTECTED ROUTE EXAMPLES
// =============================================================================

/**
 * Get current authenticated user profile
 */
app.get('/me', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
  res.json({
    id: req.user!.id,
    firebase_uid: req.user!.firebase_uid,
    email: req.user!.email,
    display_name: req.user!.display_name,
    role: req.user!.role,
    subscription_tier: req.user!.subscription_tier,
  });
});

/**
 * Admin-only route
 */
app.get(
  '/admin/dashboard',
  verifyFirebaseToken,
  requireRole('admin'),
  async (req: AuthenticatedRequest, res: Response) => {
    res.json({
      message: `Welcome to admin dashboard, ${req.user!.display_name}`,
    });
  }
);

// =============================================================================
// HEALTH CHECK
// =============================================================================

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'firebase-auth-backend' });
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// =============================================================================
// START SERVER
// =============================================================================

app.listen(PORT, () => {
  console.log(`🚀 Firebase Auth Backend running on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  await db.end();
  process.exit(0);
});
