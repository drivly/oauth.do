"use client";

import { AuthButton } from "./components/AuthButton";
import { UserProfile } from "./components/UserProfile";
import { useAuth } from "./providers/AuthProvider";

export default function Home() {
  const { user, isLoading } = useAuth();

  return (
    <div className="grid grid-rows-[auto_1fr_auto] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20 font-[family-name:var(--font-geist-sans)]">
      <header className="w-full flex justify-between items-center">
        <h1 className="text-2xl font-bold">OAuth.do</h1>
        <AuthButton />
      </header>
      
      <main className="flex flex-col gap-[32px] row-start-2 items-center text-center w-full">
        {isLoading ? (
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-gray-900 dark:border-white"></div>
          </div>
        ) : user ? (
          <UserProfile />
        ) : (
          <>
            <h2 className="text-3xl font-bold mb-4">Welcome to OAuth.do</h2>
            <p className="text-lg mb-8">
              Sign in to view your profile and Stripe account information.
            </p>
            
            <div className="bg-gray-100 dark:bg-gray-800 p-6 rounded-lg shadow-md max-w-2xl">
              <h3 className="text-xl font-semibold mb-4">Features</h3>
              <ul className="list-disc list-inside text-left space-y-2">
                <li>GitHub authentication with better-auth</li>
                <li>Stripe integration for payment and subscription management</li>
                <li>User profile management</li>
                <li>Secure authentication with OAuth</li>
              </ul>
            </div>
          </>
        )}
      </main>
      
      <footer className="row-start-3 flex gap-[24px] flex-wrap items-center justify-center">
        <p className="text-sm text-gray-500">
          Powered by better-auth and Next.js
        </p>
      </footer>
    </div>
  );
}
