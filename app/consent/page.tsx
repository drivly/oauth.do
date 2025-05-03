"use client";

import React, { Suspense, useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { authClient } from "../auth-client";

function ConsentLoading() {
  return <div className="flex justify-center p-8">Loading consent page...</div>;
}

function ConsentContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [clientInfo, setClientInfo] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const clientId = searchParams.get("client_id");
  const scope = searchParams.get("scope");

  useEffect(() => {
    if (!clientId) {
      setError("Missing client_id parameter");
      setIsLoading(false);
      return;
    }

    setClientInfo({
      name: clientId,
      scopes: scope?.split(" ") || [],
    });
    setIsLoading(false);
  }, [clientId, scope]);

  const handleConsent = async (accept: boolean) => {
    try {
      setIsLoading(true);
      const response = await fetch("/api/auth/oauth2/consent", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ accept }),
      });
      
      if (!response.ok) {
        throw new Error("Failed to process consent");
      }
      
    } catch (error) {
      console.error("Error during consent:", error);
      setError("An error occurred during consent");
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return <div className="flex justify-center p-8">Loading...</div>;
  }

  if (error) {
    return <div className="flex justify-center p-8 text-red-500">{error}</div>;
  }

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md mt-10">
      <h1 className="text-2xl font-bold mb-4">Authorization Request</h1>
      <p className="mb-4">
        <span className="font-semibold">{clientInfo?.name}</span> is requesting
        access to your account.
      </p>

      {clientInfo?.scopes.length > 0 && (
        <div className="mb-4">
          <p className="font-semibold mb-2">The application is requesting:</p>
          <ul className="list-disc pl-6">
            {clientInfo.scopes.includes("openid") && (
              <li>Verify your identity</li>
            )}
            {clientInfo.scopes.includes("profile") && (
              <li>Access your basic profile information</li>
            )}
            {clientInfo.scopes.includes("email") && (
              <li>Access your email address</li>
            )}
          </ul>
        </div>
      )}

      <div className="flex gap-4 justify-end mt-6">
        <button
          onClick={() => handleConsent(false)}
          className="px-4 py-2 border border-gray-300 rounded-md hover:bg-gray-100"
          disabled={isLoading}
        >
          Deny
        </button>
        <button
          onClick={() => handleConsent(true)}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          disabled={isLoading}
        >
          Allow
        </button>
      </div>
    </div>
  );
}

export default function ConsentPage() {
  return (
    <Suspense fallback={<ConsentLoading />}>
      <ConsentContent />
    </Suspense>
  );
}
