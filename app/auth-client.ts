"use client";

import { createAuthClient } from "better-auth/react";

const client = createAuthClient({
  baseURL: typeof window !== 'undefined' 
    ? `${window.location.origin}/api/auth` 
    : 'http://localhost:3000/api/auth',
});

export const useSession = client.useSession;
export const signIn = client.signIn;
export const signOut = client.signOut;

export const authClient = client;
