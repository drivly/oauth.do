# [oauth.do](https://oauth.do)

Cloudflare Worker with GitHub OAuth

Visit <https://oauth.do/login> to login

## Login Flow Sequence

```mermaid
sequenceDiagram
  participant C as ctx-do
  participant D as database.do
  participant O as database.do<br/>(oauth-do)
  participant J as jwt-do
  participant A as oauth.do
  D->>O: /login
  alt databases.do logged in
    O->>J: /verify
    J->>O: decrypt database.do JWT
  else databases.do logged out
    O->>A: /login?state=
    alt oauth.do logged in
      A->>J: /verify
      J->>A: decrypt oauth.do JWT
    else oauth.do logged out
      A-)github.com: /login/oauth/authorize?
      github.com-->>A: /callback
    end
    A->>O: /login/callback
    O->>J: /generate
    J->>O: database.do JWT token
  end
  O->>D: /api
  Note over O,D: set JWT cookie
  D->>C: /api
  C->>J: /verify
  J->>C: decrypt database.do JWT
  C--)D: return user object
```

- Domains using `oauth.do` have a `*/login*` route bound to the oauth-do worker.
- `https://database.do/login` hits the `/login` route in oauth-do, and is redirected to the shared login service at `https://oauth.do/login` if not previously logged in.
- If the user has not logged into oauth.do, they are redirected to the oauth provider:
- `https://github.com/login/oauth/authorize?`
- Once authorized, GitHub redirects the user back to:
- `https://oauth.do/callback` which hits the `/callback` route in oauth-do, and is redirected back to the original domain:
- `https://database.do/login/callback` which hits the `/login/callback` route in oauth-do, which then generates the JWT token, and redirects the user back to:
- `https://database.do/api` which hits the `/api` route in database-do, except now, there is a cookie in the request header, which is then passed to the CTX service bindings on [ctx-do](https://ctx.do), where the JWT token is verified and decrypted, and the user object is returned:

```json
{
  "user": {
    "name": "John Doe",
    "email": "john@example.com",
    "image": "https://avatars.github.com/12345.png",
    "claims": "database:edit"
}
```

## [🚀 We're hiring!](https://careers.do/apply)

[Driv.ly](https://driv.ly) is simple APIs to buy & sell cars online, funded by some of the [biggest names](https://twitter.com/TurnerNovak) in [automotive](https://fontinalis.com/team/#bill-ford) and [finance & insurance](https://www.detroit.vc)

We're building our entire infrastructure on Cloudflare Workers, Durable Objects, KV, R2, and PubSub. If you're as passionate about these transformational technologies as we are, we'd love for you to join our rapidly-growing team.
