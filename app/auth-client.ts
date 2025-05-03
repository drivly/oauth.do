"use client";

import { createAuthClient } from "better-auth/react";

const client = createAuthClient({
  baseURL: "http://localhost:3000/api/auth", // Default for local development
});

export const useSession = client.useSession;
export const signIn = client.signIn;
export const signOut = client.signOut;

export const authClient = client;
