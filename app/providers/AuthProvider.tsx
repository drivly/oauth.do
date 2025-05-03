"use client";

import React, { createContext, useContext } from "react";
import { signIn, signOut, useSession } from "../auth-client";

type User = {
  id: string;
  name?: string;
  email?: string;
  image?: string | null;
};

type SocialProvider = "github" | "apple" | "discord" | "facebook" | "google" | "microsoft" | "spotify" | "twitch" | "twitter" | "dropbox" | "linkedin" | "gitlab" | "tiktok" | "reddit" | "roblox" | "vk" | "kick" | "zoom";

type AuthContextType = {
  user: User | null;
  isLoading: boolean;
  signIn: (provider: SocialProvider) => Promise<void>;
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
  const { data: session, isPending } = useSession();
  
  const user = session?.user ? {
    id: session.user.id,
    name: session.user.name,
    email: session.user.email,
    image: session.user.image,
  } : null;

  const handleSignIn = async (provider: SocialProvider) => {
    try {
      await signIn.social({ provider });
    } catch (error) {
      console.error(`Failed to sign in with ${provider}:`, error);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut();
    } catch (error) {
      console.error("Failed to sign out:", error);
    }
  };

  return (
    <AuthContext.Provider value={{ 
      user, 
      isLoading: isPending, 
      signIn: handleSignIn, 
      signOut: handleSignOut 
    }}>
      {children}
    </AuthContext.Provider>
  );
}
