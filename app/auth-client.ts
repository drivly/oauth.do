"use client";

import { createAuthClient } from "better-auth/react";

const client = createAuthClient({
  baseURL: "/api/auth", // The base URL for API requests
});

export const useSession = client.useSession;
export const signIn = client.signIn;
export const signOut = client.signOut;

export const authClient = client;
