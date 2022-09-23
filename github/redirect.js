import * as queryString from "query-string";
import { ConfigError } from "./errors";

export default function redirect({ options }) {
  const { clientId, state } = options;
  if (!clientId) {
    throw new ConfigError({
      message: "No client id passed"
    });
  }
  const params = queryString.stringify({
    client_id: clientId,
    scope: ["read:user", "user:email"].join(" "),
    allow_signup: true,
    state
  });

  const githubLoginUrl = `https://github.com/login/oauth/authorize?${params}`;
  return githubLoginUrl;
}
