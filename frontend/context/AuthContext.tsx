'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { User, LoginCredentials, SignupCredentials, AuthResponse } from '@/types';
import { authService } from '@/lib/auth';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginCredentials) => Promise<AuthResponse>;
  register: (credentials: SignupCredentials) => Promise<AuthResponse>;
  logout: () => Promise<void>;
  updateUser: (updates: Partial<User>) => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Restore authenticated state on startup by verifying HTTP-only cookie with /api/v1/auth/me
  useEffect(() => {
    let isMounted = true;

    authService
      .getProfile()
      .then((activeUser) => {
        if (isMounted) {
          setUser(activeUser);
        }
      })
      .catch(() => {
        if (isMounted) {
          setUser(null);
        }
      })
      .finally(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const login = useCallback(async (credentials: LoginCredentials): Promise<AuthResponse> => {
    setIsLoading(true);
    try {
      const res = await authService.login(credentials);
      if (res.success && res.session) {
        setUser(res.session.user);
      }
      return res;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(async (credentials: SignupCredentials): Promise<AuthResponse> => {
    setIsLoading(true);
    try {
      const res = await authService.register(credentials);
      if (res.success && res.session) {
        setUser(res.session.user);
      }
      return res;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    await authService.logout();
    setUser(null);
  }, []);

  const updateUser = useCallback((updates: Partial<User>) => {
    setUser((prev) => (prev ? { ...prev, ...updates } : null));
  }, []);

  const refreshUser = useCallback(async () => {
    const freshUser = await authService.getProfile();
    setUser(freshUser);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        updateUser,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
