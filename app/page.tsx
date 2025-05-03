import Image from "next/image";
import { AuthButton } from "./components/AuthButton";

export default function Home() {
  return (
    <div className="grid grid-rows-[auto_1fr_auto] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20 font-[family-name:var(--font-geist-sans)]">
      <header className="w-full flex justify-between items-center">
        <h1 className="text-2xl font-bold">OAuth.do</h1>
        <AuthButton />
      </header>
      
      <main className="flex flex-col gap-[32px] row-start-2 items-center text-center">
        <h2 className="text-3xl font-bold mb-4">GitHub Authentication Demo</h2>
        <p className="text-lg mb-8">
          This is a demonstration of GitHub OAuth authentication using better-auth.
        </p>
        
        <div className="bg-gray-100 dark:bg-gray-800 p-6 rounded-lg shadow-md max-w-2xl">
          <h3 className="text-xl font-semibold mb-4">How it works</h3>
          <ol className="list-decimal list-inside text-left space-y-2">
            <li>Click the "Sign in with GitHub" button</li>
            <li>You'll be redirected to GitHub to authorize the application</li>
            <li>After authorization, you'll be redirected back to this page</li>
            <li>Your GitHub profile information will be displayed</li>
          </ol>
        </div>
      </main>
      
      <footer className="row-start-3 flex gap-[24px] flex-wrap items-center justify-center">
        <p className="text-sm text-gray-500">
          Powered by better-auth and Next.js
        </p>
      </footer>
    </div>
  );
}
