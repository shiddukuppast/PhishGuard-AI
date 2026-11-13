/**
 * PhishGuard AI - Authentication Service Layer
 * Connects directly to the FastAPI + MongoDB Atlas authentication endpoints.
 * 
 * Security Architecture:
 * - Credentials and tokens are managed via secure HTTP-only cookies
 * - Zero storage of passwords, hashed passwords, or tokens in localStorage
 * - Session verification is validated against GET /api/v1/auth/me on mount
 */

import { User, LoginCredentials, SignupCredentials, AuthResponse } from '@/types';
import { authApi, setAuthToken, clearAuthTokens } from '@/lib/api';
import { clearAllClientStorage } from '@/lib/storage';

/**
 * Generate 2-letter uppercase initials from full name
 */
export function getInitials(name: string): string {
  if (!name) return 'PG';
  const parts = name.trim().split(/\s+/);
  if (parts.length === 1) return parts[0].substring(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/**
 * Maps a backend UserResponse to the frontend User interface
 */
export function mapBackendUserToFrontend(backendUser: {
  id: string;
  full_name: string;
  email: string;
  role?: string;
  organization?: string;
  created_at?: string;
}): User {
  return {
    id: backendUser.id,
    name: backendUser.full_name,
    email: backendUser.email,
    role: backendUser.role || 'Security Analyst',
    organization: backendUser.organization || 'Defense Operations',
    avatarInitials: getInitials(backendUser.full_name),
    apiKey: 'pg_live_' + (backendUser.id ? backendUser.id.substring(0, 12) : 'user_session'),
    createdAt: backendUser.created_at || new Date().toISOString(),
  };
}

export const authService = {
  /**
   * Authenticate user credentials against FastAPI POST /api/v1/auth/login
   */
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    // Purge previous session tokens and cached data to prevent cross-account leakage
    clearAuthTokens();
    clearAllClientStorage();

    try {
      const res = await authApi.login({
        email: credentials.email,
        password: credentials.password,
        remember_me: credentials.rememberMe,
      });

      if (res && res.success && res.user) {
        if (res.token) {
          setAuthToken(res.token);
        }
        const user = mapBackendUserToFrontend(res.user);
        return {
          success: true,
          message: res.message || 'Authentication successful.',
          session: {
            token: res.token,
            user,
            expiresAt: Date.now() + 86400000 * 7,
          },
        };
      }
      return {
        success: false,
        message: 'Invalid response from authentication service.',
      };
    } catch (err: any) {
      return {
        success: false,
        message: err.message || 'Authentication failed. Please verify your email and password.',
      };
    }
  },

  /**
   * Register a new user against FastAPI POST /api/v1/auth/signup
   */
  async register(credentials: SignupCredentials): Promise<AuthResponse> {
    if (!credentials.termsAccepted) {
      return {
        success: false,
        message: 'You must accept the terms of service to proceed.',
      };
    }

    // Purge previous session tokens and cached data to prevent cross-account leakage
    clearAuthTokens();
    clearAllClientStorage();

    try {
      const res = await authApi.signup({
        full_name: credentials.name,
        email: credentials.email,
        password: credentials.password,
      });

      if (res && res.success && res.user) {
        if (res.token) {
          setAuthToken(res.token);
        }
        const user = mapBackendUserToFrontend(res.user);
        return {
          success: true,
          message: res.message || 'Account created successfully.',
          session: {
            token: res.token,
            user,
            expiresAt: Date.now() + 86400000 * 7,
          },
        };
      }
      return {
        success: false,
        message: 'Invalid response received from registration service.',
      };
    } catch (err: any) {
      return {
        success: false,
        message: err.message || 'Registration failed. Please check your details and try again.',
      };
    }
  },

  /**
   * Fetch active authenticated user profile from GET /api/v1/auth/me
   */
  async getProfile(): Promise<User | null> {
    try {
      const userData = await authApi.me();
      if (userData && userData.id) {
        return mapBackendUserToFrontend(userData);
      }
      return null;
    } catch {
      return null;
    }
  },

  /**
   * End session via POST /api/v1/auth/logout with complete client-side cache and token eradication
   */
  async logout(): Promise<void> {
    clearAuthTokens();
    clearAllClientStorage();
    try {
      await authApi.logout();
    } catch {
      // Ignore network errors on logout
    } finally {
      clearAuthTokens();
      clearAllClientStorage();
    }
  },
};
