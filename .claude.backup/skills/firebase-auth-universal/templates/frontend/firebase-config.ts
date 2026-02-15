/**
 * Firebase Configuration
 * Initialize Firebase Client SDK for web applications
 */

import { initializeApp, getApps, FirebaseApp } from 'firebase/app';
import {
  getAuth,
  Auth,
  connectAuthEmulator,
  browserLocalPersistence,
  browserSessionPersistence,
  inMemoryPersistence,
} from 'firebase/auth';

// =============================================================================
// FIREBASE CONFIG
// =============================================================================

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
  measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID, // Optional
};

// Validate configuration
const requiredKeys = ['apiKey', 'authDomain', 'projectId'];
const missingKeys = requiredKeys.filter(key => !firebaseConfig[key as keyof typeof firebaseConfig]);

if (missingKeys.length > 0) {
  throw new Error(
    `Missing required Firebase configuration: ${missingKeys.join(', ')}. ` +
    `Please check your environment variables (NEXT_PUBLIC_FIREBASE_*)`
  );
}

// =============================================================================
// INITIALIZE FIREBASE
// =============================================================================

let app: FirebaseApp;
let auth: Auth;

// Check if Firebase is already initialized (prevents multiple initializations)
if (!getApps().length) {
  app = initializeApp(firebaseConfig);
  auth = getAuth(app);

  // Set persistence based on environment
  if (typeof window !== 'undefined') {
    // Browser environment
    const persistence =
      process.env.NEXT_PUBLIC_AUTH_PERSISTENCE === 'session'
        ? browserSessionPersistence // Persist only for current tab
        : browserLocalPersistence; // Persist across browser sessions (default)

    auth.setPersistence(persistence).catch((error) => {
      console.error('Failed to set auth persistence:', error);
    });
  }

  // Connect to Firebase Auth Emulator in development
  if (
    process.env.NODE_ENV === 'development' &&
    process.env.NEXT_PUBLIC_FIREBASE_EMULATOR_HOST
  ) {
    const emulatorHost = process.env.NEXT_PUBLIC_FIREBASE_EMULATOR_HOST || 'localhost';
    const emulatorPort = parseInt(process.env.NEXT_PUBLIC_FIREBASE_EMULATOR_PORT || '9099');

    console.log(`🔧 Connecting to Firebase Auth Emulator at ${emulatorHost}:${emulatorPort}`);
    connectAuthEmulator(auth, `http://${emulatorHost}:${emulatorPort}`, {
      disableWarnings: true,
    });
  }
} else {
  app = getApps()[0];
  auth = getAuth(app);
}

export { app, auth };
export default auth;
