/**
 * Universal Authentication Hook (React)
 * =====================================
 *
 * Production-ready React hook for authentication with:
 * - Email/password login
 * - MFA (TOTP and email codes)
 * - OAuth (Google, Apple)
 * - Session management
 *
 * Usage:
 *   const { user, loading, login, logout, setupMFA } = useAuth();
 */

import { useState, useEffect, createContext, useContext, ReactNode } from 'react';

// ==============================================================================
// TYPES
// ==============================================================================

interface User {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  mfaEnabled: boolean;
  mfaMethod?: 'totp' | 'email';
}

interface LoginCredentials {
  email: string;
  password: string;
  mfaCode?: string;
}

interface RegisterData {
  email: string;
  password: string;
  name: string;
}

interface MFASetupResponse {
  method: 'totp' | 'email';
  secret?: string;  // TOTP only
  qrCode?: string;  // TOTP only - base64 image
  backupCodes?: string[];  // TOTP only
  message?: string;  // Email MFA
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (credentials: LoginCredentials) => Promise<{ mfaRequired?: boolean; mfaMethod?: string }>;
  logout: () => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  setupMFA: (method: 'totp' | 'email') => Promise<MFASetupResponse>;
  verifyMFA: (code: string) => Promise<void>;
  disableMFA: (password: string, code: string) => Promise<void>;
}

// ==============================================================================
// CONFIGURATION
// ==============================================================================

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// ==============================================================================
// API CLIENT
// ==============================================================================

async function apiCall<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_URL}${endpoint}`;

  const config: RequestInit = {
    ...options,
    credentials: 'include',  // CRITICAL: Include cookies for session auth
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  };

  const response = await fetch(url, config);

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `HTTP ${response.status}`);
  }

  return response.json();
}

// ==============================================================================
// AUTH CONTEXT
// ==============================================================================

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

// ==============================================================================
// AUTH PROVIDER
// ==============================================================================

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Check authentication status on mount
  useEffect(() => {
    checkAuth();
  }, []);

  async function checkAuth() {
    try {
      const data = await apiCall<{ user: User }>('/api/auth/me');
      setUser(data.user);
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  async function register(data: RegisterData): Promise<void> {
    await apiCall('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    // User needs to verify email before logging in
  }

  async function login(credentials: LoginCredentials) {
    const response = await apiCall<any>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });

    // Check if MFA required
    if (response.mfaRequired) {
      return {
        mfaRequired: true,
        mfaMethod: response.mfaMethod,
      };
    }

    // Login successful
    setUser(response.user);
    return {};
  }

  async function logout(): Promise<void> {
    await apiCall('/api/auth/logout', {
      method: 'POST',
    });
    setUser(null);
  }

  async function setupMFA(method: 'totp' | 'email'): Promise<MFASetupResponse> {
    const response = await apiCall<MFASetupResponse>('/api/auth/mfa/setup', {
      method: 'POST',
      body: JSON.stringify({ method }),
    });
    return response;
  }

  async function verifyMFA(code: string): Promise<void> {
    await apiCall('/api/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });

    // Refresh user data
    await checkAuth();
  }

  async function disableMFA(password: string, code: string): Promise<void> {
    await apiCall('/api/auth/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ password, code }),
    });

    // Refresh user data
    await checkAuth();
  }

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    register,
    setupMFA,
    verifyMFA,
    disableMFA,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ==============================================================================
// EXAMPLE USAGE IN COMPONENTS
// ==============================================================================

/*
// 1. Wrap your app with AuthProvider
import { AuthProvider } from './hooks/useAuth';

function App() {
  return (
    <AuthProvider>
      <YourApp />
    </AuthProvider>
  );
}

// 2. Use in components
import { useAuth } from './hooks/useAuth';

function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaMethod, setMfaMethod] = useState<string>();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    try {
      const result = await login({ email, password, mfaCode });

      if (result.mfaRequired) {
        setMfaRequired(true);
        setMfaMethod(result.mfaMethod);
      } else {
        // Login successful, redirect to dashboard
        navigate('/dashboard');
      }
    } catch (error) {
      alert(error.message);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        required
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        required
      />

      {mfaRequired && (
        <div>
          <p>
            {mfaMethod === 'email'
              ? 'Check your email for verification code'
              : 'Enter code from authenticator app'}
          </p>
          <input
            type="text"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
            placeholder="6-digit code"
            maxLength={6}
            required
          />
        </div>
      )}

      <button type="submit">Login</button>
    </form>
  );
}

// 3. Protected route example
function Dashboard() {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" />;
  }

  return <div>Welcome, {user.name}!</div>;
}

// 4. MFA Setup component
function MFASetup() {
  const { setupMFA, verifyMFA } = useAuth();
  const [method, setMethod] = useState<'totp' | 'email'>('totp');
  const [qrCode, setQrCode] = useState<string>();
  const [backupCodes, setBackupCodes] = useState<string[]>();
  const [verificationCode, setVerificationCode] = useState('');

  async function handleSetup() {
    const response = await setupMFA(method);

    if (response.qrCode) {
      setQrCode(response.qrCode);
      setBackupCodes(response.backupCodes);
    }
  }

  async function handleVerify() {
    await verifyMFA(verificationCode);
    alert('MFA enabled successfully!');
  }

  return (
    <div>
      <select value={method} onChange={(e) => setMethod(e.target.value as any)}>
        <option value="totp">Authenticator App</option>
        <option value="email">Email Code</option>
      </select>

      <button onClick={handleSetup}>Setup MFA</button>

      {qrCode && (
        <div>
          <p>Scan this QR code with your authenticator app:</p>
          <img src={qrCode} alt="QR Code" />

          <p>Backup codes (save these!):</p>
          <ul>
            {backupCodes?.map((code) => (
              <li key={code}>{code}</li>
            ))}
          </ul>

          <input
            type="text"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value)}
            placeholder="Enter code to verify"
          />
          <button onClick={handleVerify}>Verify and Enable</button>
        </div>
      )}
    </div>
  );
}
*/
