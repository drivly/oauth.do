"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { authClient } from "../auth-client";

type User = {
  id: string;
  name?: string;
  email?: string;
  image?: string;
};

type AuthContextType = {
  user: User | null;
  isLoading: boolean;
  signIn: (provider: string) => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType>({
  user: null,
  isLoading: true,
  signIn: async () => {},
  signOut: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = authClient.session.subscribe((session: any) => {
      if (session) {
        setUser({
          id: session.user.id,
          name: session.user.name,
          email: session.user.email,
          image: session.user.image,
        });
      } else {
        setUser(null);
      }
      setIsLoading(false);
    });

    authClient.session.init();

    return () => {
      unsubscribe();
    };
  }, []);

  const signIn = async (provider: string) => {
    try {
      await authClient.signIn.social({ provider });
    } catch (error) {
      console.error(`Failed to sign in with ${provider}:`, error);
    }
  };

  const signOut = async () => {
    try {
      await authClient.signOut();
    } catch (error) {
      console.error("Failed to sign out:", error);
    }
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}
