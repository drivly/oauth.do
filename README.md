# OAuth.do - GitHub Authentication

This project demonstrates how to implement GitHub OAuth authentication in a Next.js application using the better-auth library.

## Features

- GitHub OAuth authentication
- User session management
- Responsive UI with sign-in/sign-out functionality

## Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env.local` file with your GitHub OAuth credentials:
   ```
   GITHUB_CLIENT_ID=your_github_client_id
   GITHUB_CLIENT_SECRET=your_github_client_secret
   ```

## Getting GitHub OAuth Credentials

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click on "New OAuth App"
3. Fill in the application details:
   - Application name: Your app name
   - Homepage URL: http://localhost:3000
   - Authorization callback URL: http://localhost:3000/api/auth/callback/github
4. Register the application
5. Copy the Client ID and generate a new Client Secret
6. Add these credentials to your `.env.local` file

## Running the Application

```bash
npm run dev
```

Visit http://localhost:3000 to see the application running.

## Implementation Details

The authentication is implemented using the following components:

1. **API Route**: `/app/api/auth/[...all]/route.ts` handles the authentication API endpoints
2. **Auth Configuration**: `/app/auth.ts` configures the better-auth instance with GitHub provider
3. **Auth Client**: `/app/auth-client.ts` creates the client-side auth client
4. **Auth Provider**: `/app/providers/AuthProvider.tsx` provides authentication context to the application
5. **Auth Button**: `/app/components/AuthButton.tsx` implements the sign-in/sign-out UI

## How It Works

1. User clicks the "Sign in with GitHub" button
2. They are redirected to GitHub to authorize the application
3. After authorization, they are redirected back to the application
4. The application receives the authorization code and exchanges it for an access token
5. The access token is used to fetch the user's profile information
6. The user is signed in and their profile information is displayed

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.
- [Better Auth Documentation](https://www.better-auth.com/docs) - learn about Better Auth features and API.
