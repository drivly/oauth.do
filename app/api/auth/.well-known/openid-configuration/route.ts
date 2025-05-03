import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({
    issuer: process.env.OAUTH_ISSUER || "https://oauth.do",
    authorization_endpoint: "https://oauth.do/api/auth/oauth2/authorize",
    token_endpoint: "https://oauth.do/api/auth/oauth2/token",
    userinfo_endpoint: "https://oauth.do/api/auth/oauth2/userinfo",
    jwks_uri: "https://oauth.do/api/auth/.well-known/jwks.json",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    claims_supported: ["sub", "iss", "name", "email", "picture"]
  });
}
