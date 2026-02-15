/**
 * useAuth Hook
 * React hook for Firebase Authentication
 * Provides auth state, user data, and authentication methods
 */

import { useState, useEffect, useCallback, createContext, useContext, ReactNode } from 'react';
import {
  User,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  OAuthProvider,
  FacebookAuthProvider,
  TwitterAuthProvider,
  GithubAuthProvider,
  RecaptchaVerifier,
  signInWithPhoneNumber,
  ConfirmationResult,
  updatePassword,
  reauthenticateWithCredential,
  EmailAuthProvider,
  linkWithPopup,
  unlink,
} from 'firebase/auth';
import auth from './firebase-config';

// =============================================================================
// TYPES
// =============================================================================

interface AuthContextType {
  // User state
  user: User | null;
  loading: boolean;
  idToken: string | null;

  // Auth methods
  signIn: (email: string, password: string) => Promise<User>;
  signUp: (email: string, password: string, displayName?: string) => Promise<User>;
  signInWithGoogle: (useRedirect?: boolean) => Promise<User | void>;
  signInWithApple: (useRedirect?: boolean) => Promise<User | void>;
  signInWithFacebook: (useRedirect?: boolean) => Promise<User | void>;
  signInWithTwitter: (useRedirect?: boolean) => Promise<User | void>;
  signInWithGithub: (useRedirect?: boolean) => Promise<User | void>;
  signInWithPhone: (phoneNumber: string, recaptchaContainerId: string) => Promise<ConfirmationResult>;
  logOut: () => Promise<void>;

  // User management
  resetPassword: (email: string) => Promise<void>;
  verifyEmail: () => Promise<void>;
  updateUserProfile: (displayName?: string, photoURL?: string) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;

  // Account linking
  linkGoogleAccount: () => Promise<void>;
  linkAppleAccount: () => Promise<void>;
  unlinkProvider: (providerId: string) => Promise<void>;

  // Token management
  getIdToken: (forceRefresh?: boolean) => Promise<string | null>;
  refreshToken: () => Promise<string | null>;
}

// =============================================================================
// CONTEXT
// =============================================================================

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// =============================================================================
// AUTH PROVIDER
// =============================================================================

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [idToken, setIdToken] = useState<string | null>(null);

  // =============================================================================
  // TOKEN MANAGEMENT
  // =============================================================================

  const getIdToken = useCallback(
    async (forceRefresh: boolean = false): Promise<string | null> => {
      if (!user) return null;

      try {
        const token = await user.getIdToken(forceRefresh);
        setIdToken(token);
        return token;
      } catch (error) {
        console.error('Failed to get ID token:', error);
        return null;
      }
    },
    [user]
  );

  const refreshToken = useCallback(async (): Promise<string | null> => {
    return getIdToken(true);
  }, [getIdToken]);

  // =============================================================================
  // AUTH STATE LISTENER
  // =============================================================================

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setUser(firebaseUser);

      if (firebaseUser) {
        // Get ID token
        const token = await firebaseUser.getIdToken();
        setIdToken(token);

        // Refresh token every 55 minutes (tokens expire in 1 hour)
        const tokenRefreshInterval = setInterval(async () => {
          const newToken = await firebaseUser.getIdToken(true);
          setIdToken(newToken);
        }, 55 * 60 * 1000);

        return () => clearInterval(tokenRefreshInterval);
      } else {
        setIdToken(null);
      }

      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  // =============================================================================
  // EMAIL/PASSWORD AUTH
  // =============================================================================

  const signIn = async (email: string, password: string): Promise<User> => {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    return userCredential.user;
  };

  const signUp = async (
    email: string,
    password: string,
    displayName?: string
  ): Promise<User> => {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);

    // Update profile with display name if provided
    if (displayName) {
      await updateProfile(userCredential.user, { displayName });
    }

    // Send email verification
    await sendEmailVerification(userCredential.user);

    return userCredential.user;
  };

  const logOut = async (): Promise<void> => {
    await signOut(auth);
    setIdToken(null);
  };

  const resetPassword = async (email: string): Promise<void> => {
    await sendPasswordResetEmail(auth, email);
  };

  const verifyEmail = async (): Promise<void> => {
    if (!user) throw new Error('No user logged in');
    await sendEmailVerification(user);
  };

  const updateUserProfile = async (
    displayName?: string,
    photoURL?: string
  ): Promise<void> => {
    if (!user) throw new Error('No user logged in');
    await updateProfile(user, {
      ...(displayName && { displayName }),
      ...(photoURL && { photoURL }),
    });
  };

  const changePassword = async (
    currentPassword: string,
    newPassword: string
  ): Promise<void> => {
    if (!user || !user.email) throw new Error('No user logged in');

    // Re-authenticate user before changing password
    const credential = EmailAuthProvider.credential(user.email, currentPassword);
    await reauthenticateWithCredential(user, credential);

    // Update password
    await updatePassword(user, newPassword);
  };

  // =============================================================================
  // SOCIAL AUTH (GOOGLE, APPLE, FACEBOOK, ETC.)
  // =============================================================================

  const signInWithGoogle = async (useRedirect: boolean = false): Promise<User | void> => {
    const provider = new GoogleAuthProvider();
    provider.addScope('email');
    provider.addScope('profile');

    if (useRedirect) {
      await signInWithRedirect(auth, provider);
      // User will be redirected, so no user object is returned immediately
    } else {
      const result = await signInWithPopup(auth, provider);
      return result.user;
    }
  };

  const signInWithApple = async (useRedirect: boolean = false): Promise<User | void> => {
    const provider = new OAuthProvider('apple.com');
    provider.addScope('email');
    provider.addScope('name');

    if (useRedirect) {
      await signInWithRedirect(auth, provider);
    } else {
      const result = await signInWithPopup(auth, provider);
      return result.user;
    }
  };

  const signInWithFacebook = async (useRedirect: boolean = false): Promise<User | void> => {
    const provider = new FacebookAuthProvider();
    provider.addScope('email');
    provider.addScope('public_profile');

    if (useRedirect) {
      await signInWithRedirect(auth, provider);
    } else {
      const result = await signInWithPopup(auth, provider);
      return result.user;
    }
  };

  const signInWithTwitter = async (useRedirect: boolean = false): Promise<User | void> => {
    const provider = new TwitterAuthProvider();

    if (useRedirect) {
      await signInWithRedirect(auth, provider);
    } else {
      const result = await signInWithPopup(auth, provider);
      return result.user;
    }
  };

  const signInWithGithub = async (useRedirect: boolean = false): Promise<User | void> => {
    const provider = new GithubAuthProvider();
    provider.addScope('user:email');

    if (useRedirect) {
      await signInWithRedirect(auth, provider);
    } else {
      const result = await signInWithPopup(auth, provider);
      return result.user;
    }
  };

  // =============================================================================
  // PHONE AUTH
  // =============================================================================

  const signInWithPhone = async (
    phoneNumber: string,
    recaptchaContainerId: string
  ): Promise<ConfirmationResult> => {
    // Create reCAPTCHA verifier
    const recaptchaVerifier = new RecaptchaVerifier(auth, recaptchaContainerId, {
      size: 'invisible',
      callback: () => {
        // reCAPTCHA solved
      },
    });

    // Send verification code
    const confirmationResult = await signInWithPhoneNumber(
      auth,
      phoneNumber,
      recaptchaVerifier
    );

    return confirmationResult;
  };

  // =============================================================================
  // ACCOUNT LINKING
  // =============================================================================

  const linkGoogleAccount = async (): Promise<void> => {
    if (!user) throw new Error('No user logged in');

    const provider = new GoogleAuthProvider();
    await linkWithPopup(user, provider);
  };

  const linkAppleAccount = async (): Promise<void> => {
    if (!user) throw new Error('No user logged in');

    const provider = new OAuthProvider('apple.com');
    await linkWithPopup(user, provider);
  };

  const unlinkProvider = async (providerId: string): Promise<void> => {
    if (!user) throw new Error('No user logged in');
    await unlink(user, providerId);
  };

  // =============================================================================
  // CONTEXT VALUE
  // =============================================================================

  const value: AuthContextType = {
    user,
    loading,
    idToken,
    signIn,
    signUp,
    signInWithGoogle,
    signInWithApple,
    signInWithFacebook,
    signInWithTwitter,
    signInWithGithub,
    signInWithPhone,
    logOut,
    resetPassword,
    verifyEmail,
    updateUserProfile,
    changePassword,
    linkGoogleAccount,
    linkAppleAccount,
    unlinkProvider,
    getIdToken,
    refreshToken,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
