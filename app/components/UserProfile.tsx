"use client";

import React, { useEffect, useState } from "react";
import { useAuth } from "../providers/AuthProvider";

type StripeAccount = {
  id: string;
  email?: string;
  name?: string;
  subscriptions?: {
    data: Array<{
      id: string;
      status: string;
      plan?: {
        nickname?: string;
        amount?: number;
        currency?: string;
      };
    }>;
  };
};

export function UserProfile() {
  const { user, isLoading } = useAuth();
  const [stripeAccount, setStripeAccount] = useState<StripeAccount | null>(null);
  const [isLoadingStripe, setIsLoadingStripe] = useState(false);

  useEffect(() => {
    if (user && !isLoading) {
      fetchStripeAccount();
    }
  }, [user, isLoading]);

  const fetchStripeAccount = async () => {
    try {
      setIsLoadingStripe(true);
      const response = await fetch("/api/auth/stripe/account");
      if (response.ok) {
        const data = await response.json();
        setStripeAccount(data);
      } else {
        console.error("Failed to fetch Stripe account:", await response.text());
      }
    } catch (error) {
      console.error("Error fetching Stripe account:", error);
    } finally {
      setIsLoadingStripe(false);
    }
  };

  if (isLoading || !user) {
    return null; // Don't render anything if user is not logged in
  }

  return (
    <div className="w-full max-w-2xl mx-auto bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
      <h2 className="text-2xl font-bold mb-6">Your Profile</h2>
      
      {/* User Information */}
      <div className="mb-8">
        <h3 className="text-xl font-semibold mb-4">User Information</h3>
        <div className="flex items-center gap-4 mb-4">
          {user.image && (
            <img 
              src={user.image} 
              alt={user.name || "User"} 
              className="w-16 h-16 rounded-full"
            />
          )}
          <div>
            <p className="text-lg font-medium">{user.name || "Anonymous User"}</p>
            <p className="text-gray-600 dark:text-gray-400">{user.email || "No email provided"}</p>
          </div>
        </div>
      </div>
      
      {/* Stripe Account Information */}
      <div>
        <h3 className="text-xl font-semibold mb-4">Stripe Account</h3>
        
        {isLoadingStripe ? (
          <p className="text-gray-600 dark:text-gray-400">Loading Stripe account information...</p>
        ) : stripeAccount ? (
          <div>
            <p className="mb-2">
              <span className="font-medium">Account ID:</span> {stripeAccount.id}
            </p>
            {stripeAccount.email && (
              <p className="mb-2">
                <span className="font-medium">Email:</span> {stripeAccount.email}
              </p>
            )}
            
            {/* Subscriptions */}
            {stripeAccount.subscriptions && stripeAccount.subscriptions.data.length > 0 ? (
              <div className="mt-4">
                <h4 className="text-lg font-medium mb-2">Subscriptions</h4>
                <ul className="space-y-2">
                  {stripeAccount.subscriptions.data.map((subscription) => (
                    <li key={subscription.id} className="bg-gray-100 dark:bg-gray-700 p-3 rounded">
                      <p>
                        <span className="font-medium">Plan:</span> {subscription.plan?.nickname || "Unknown Plan"}
                      </p>
                      <p>
                        <span className="font-medium">Status:</span> {subscription.status}
                      </p>
                      {subscription.plan?.amount && (
                        <p>
                          <span className="font-medium">Price:</span> {(subscription.plan.amount / 100).toFixed(2)} {subscription.plan.currency?.toUpperCase() || "USD"}
                        </p>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-gray-600 dark:text-gray-400">No active subscriptions</p>
            )}
          </div>
        ) : (
          <div>
            <p className="text-gray-600 dark:text-gray-400 mb-4">No Stripe account connected</p>
            <button 
              onClick={() => window.location.href = "/api/auth/stripe/connect"}
              className="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors"
            >
              Connect Stripe Account
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
