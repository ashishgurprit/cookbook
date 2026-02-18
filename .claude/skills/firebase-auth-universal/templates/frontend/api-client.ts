/**
 * API Client with Firebase Authentication
 * Automatically injects Firebase ID token in requests
 */

import auth from './firebase-config';

// =============================================================================
// CONFIGURATION
// =============================================================================

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// =============================================================================
// API CLIENT
// =============================================================================

interface RequestOptions extends RequestInit {
  requiresAuth?: boolean;
}

/**
 * Get current Firebase ID token
 */
async function getIdToken(): Promise<string | null> {
  const user = auth.currentUser;
  if (!user) return null;

  try {
    const token = await user.getIdToken();
    return token;
  } catch (error) {
    console.error('Failed to get ID token:', error);
    return null;
  }
}

/**
 * Make authenticated API request
 */
export async function apiRequest<T = any>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const { requiresAuth = true, headers = {}, ...restOptions } = options;

  // Build request headers
  const requestHeaders: HeadersInit = {
    'Content-Type': 'application/json',
    ...headers,
  };

  // Add Firebase ID token if authentication is required
  if (requiresAuth) {
    const idToken = await getIdToken();

    if (!idToken) {
      throw new Error('Not authenticated');
    }

    requestHeaders['Authorization'] = `Bearer ${idToken}`;
  }

  // Make request
  const url = `${API_BASE_URL}${endpoint}`;

  try {
    const response = await fetch(url, {
      ...restOptions,
      headers: requestHeaders,
    });

    // Handle non-2xx responses
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const errorMessage = errorData.error || errorData.message || response.statusText;

      // Handle specific HTTP status codes
      if (response.status === 401) {
        // Token expired or invalid - try refreshing
        const user = auth.currentUser;
        if (user) {
          try {
            const newToken = await user.getIdToken(true); // Force refresh
            requestHeaders['Authorization'] = `Bearer ${newToken}`;

            // Retry request with new token
            const retryResponse = await fetch(url, {
              ...restOptions,
              headers: requestHeaders,
            });

            if (retryResponse.ok) {
              return retryResponse.json();
            }
          } catch (refreshError) {
            console.error('Token refresh failed:', refreshError);
          }
        }

        throw new Error('Authentication failed. Please sign in again.');
      }

      if (response.status === 403) {
        throw new Error('You do not have permission to perform this action');
      }

      if (response.status === 404) {
        throw new Error('Resource not found');
      }

      throw new Error(errorMessage);
    }

    // Parse and return response
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return response.json();
    }

    return response.text() as any;
  } catch (error: any) {
    console.error('API request failed:', error);

    // Re-throw the error
    if (error instanceof Error) {
      throw error;
    }

    throw new Error('Network request failed');
  }
}

// =============================================================================
// CONVENIENCE METHODS
// =============================================================================

export const api = {
  /**
   * GET request
   */
  get: async <T = any>(endpoint: string, options?: RequestOptions): Promise<T> => {
    return apiRequest<T>(endpoint, {
      ...options,
      method: 'GET',
    });
  },

  /**
   * POST request
   */
  post: async <T = any>(
    endpoint: string,
    data?: any,
    options?: RequestOptions
  ): Promise<T> => {
    return apiRequest<T>(endpoint, {
      ...options,
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  },

  /**
   * PATCH request
   */
  patch: async <T = any>(
    endpoint: string,
    data?: any,
    options?: RequestOptions
  ): Promise<T> => {
    return apiRequest<T>(endpoint, {
      ...options,
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    });
  },

  /**
   * PUT request
   */
  put: async <T = any>(
    endpoint: string,
    data?: any,
    options?: RequestOptions
  ): Promise<T> => {
    return apiRequest<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  },

  /**
   * DELETE request
   */
  delete: async <T = any>(endpoint: string, options?: RequestOptions): Promise<T> => {
    return apiRequest<T>(endpoint, {
      ...options,
      method: 'DELETE',
    });
  },

  /**
   * Upload file (multipart/form-data)
   */
  upload: async <T = any>(
    endpoint: string,
    formData: FormData,
    options?: Omit<RequestOptions, 'headers'>
  ): Promise<T> => {
    const { requiresAuth = true, ...restOptions } = options || {};

    const headers: HeadersInit = {};

    // Add Firebase ID token if authentication is required
    if (requiresAuth) {
      const idToken = await getIdToken();
      if (!idToken) {
        throw new Error('Not authenticated');
      }
      headers['Authorization'] = `Bearer ${idToken}`;
    }

    // Don't set Content-Type for FormData - browser will set it with boundary
    const url = `${API_BASE_URL}${endpoint}`;

    const response = await fetch(url, {
      ...restOptions,
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || errorData.message || 'Upload failed');
    }

    return response.json();
  },
};

// =============================================================================
// USAGE EXAMPLES
// =============================================================================

/*

// Example 1: Get current user profile
try {
  const profile = await api.get('/me');
  console.log('User profile:', profile);
} catch (error) {
  console.error('Failed to get profile:', error);
}

// Example 2: Update user profile
try {
  const updatedProfile = await api.patch('/me', {
    display_name: 'John Doe',
  });
  console.log('Profile updated:', updatedProfile);
} catch (error) {
  console.error('Failed to update profile:', error);
}

// Example 3: Public endpoint (no auth required)
try {
  const publicData = await api.get('/public/data', { requiresAuth: false });
  console.log('Public data:', publicData);
} catch (error) {
  console.error('Failed to fetch public data:', error);
}

// Example 4: Upload file
try {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('description', 'My file');

  const result = await api.upload('/upload', formData);
  console.log('Upload result:', result);
} catch (error) {
  console.error('Upload failed:', error);
}

// Example 5: Using in React component
function MyComponent() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchData() {
      try {
        const result = await api.get('/my-data');
        setData(result);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  return <div>{JSON.stringify(data)}</div>;
}

*/

export default api;
