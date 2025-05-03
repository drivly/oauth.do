
const fetch = require('node:fetch');

async function registerClient() {
  try {
    const response = await fetch('http://localhost:3000/api/clients/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'APIs.do',
        redirect_uris: ['https://apis.do/api/auth/callback/oauth-do'],
      }),
    });

    const data = await response.json();
    console.log('Client registered successfully:');
    console.log('Client ID:', data.clientId);
    console.log('Client Secret:', data.clientSecret);
    console.log('\nAdd these values to your .env file in the apis.do repository:');
    console.log(`OAUTH_DO_CLIENT_ID=${data.clientId}`);
    console.log(`OAUTH_DO_CLIENT_SECRET=${data.clientSecret}`);
  } catch (error) {
    console.error('Error registering client:', error);
  }
}

registerClient();
