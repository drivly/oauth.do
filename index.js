import { Router } from 'itty-router'
import { error, json, withCookies } from 'itty-router-extras'
import { jwtVerify, SignJWT } from 'jose'
import { nanoid } from 'nanoid'
import github from './github'

const router = Router()
const recentInteractions = {}
const authCookie = '__Session-worker.auth.providers-token'

const enrichRequest = req => {
  req.id = req.headers.get('CF-Ray') + '-' + req.cf.colo
  req.ip = req.headers.get('CF-Connecting-IP')
  recentInteractions[req.ip] = recentInteractions[req.ip] ? recentInteractions[req.ip] + 1 : 1
  req.recentInteractions = recentInteractions[req.ip]
  req.timestamp = new Date().toISOString()
  if (req.recentInteractions > 100) {
    return error(429, { error: 'Over Rate Limit - Try again later' })
  }
}

router.all('*', withCookies, enrichRequest)


router.get('/', (req, env) => json({ req }))


router.get('/me', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies[authCookie]
  try {
    return json({ req, token, jwt: await verify(hostname, token, env) })
  } catch {
    return loginRedirect(req, env)
  }
})

router.get('/me.jpg', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies[authCookie]
  try {
    const jwt = await verify(hostname, token, env)
    return fetch(jwt?.payload?.profile?.image || 'https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  } catch {
    return fetch('https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  }
})

/**
 * Double-bound login service endpoint
 */
router.get('/login', loginRedirect)

async function verify(hostname, token, env) {
  const domain = hostname.replace(/.*\.([^.]+.[^.]+)$/, '$1')
  return await jwtVerify(token, new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(env.JWT_SECRET + domain))), { issuer: domain })
}

async function loginRedirect(req, env) {
  let { hostname, headers, query } = await env.CTX.fetch(req).then(res => res.json())
  const location = query?.redirect_uri && new URL(query.redirect_uri).hostname === hostname ? query.redirect_uri :
    headers?.referer && new URL(headers.referer).hostname === hostname ? headers.referer : `https://${hostname}/api`
  const token = req.cookies[authCookie]
  if (token) {
    const jwt = await verify(hostname, token, env)
    if (jwt) return redirect(location, token, jwt.payload.exp, req)
  }
  const options = { clientId: env.GITHUB_CLIENT_ID, state: crypto.randomUUID() }
  const [loginUrl] = await Promise.all([github.redirect({ options }), env.REDIRECTS.put(options.state, location, { expirationTtl: 600 })])
  return Response.redirect(loginUrl, 302)
}

/**
 * Callback to oauth.do from external oauth provider
 */
router.get('/callback', async (req, env) => {
  let { query, url } = await env.CTX.fetch(req).then(res => res.json())
  if (query.error) {
    return new Response(query.error, {
      status: 401,
    })
  }
  const clientId = env.GITHUB_CLIENT_ID
  const clientSecret = env.GITHUB_CLIENT_SECRET

  let [users, location] = await Promise.all([github.users({ options: { clientSecret, clientId }, request: { url } }), env.REDIRECTS.get(query.state)])
  const user = users.user
  const profile = {
    id: user.id,
    user: user.login,
    name: user.name,
    image: user.avatar_url,
    email: user.email,
  }

  const subdomain = location && new URL(location).hostname || hostname
  const domain = subdomain.replace(/.*\.([^.]+.[^.]+)$/, '$1')
  let expires = new Date()
  expires.setFullYear(expires.getFullYear() + 1)
  expires = expires.valueOf()

  const [token] = await Promise.all([
    new SignJWT({ profile })
      .setProtectedHeader({ alg: 'HS256' })
      .setJti(nanoid())
      .setIssuedAt()
      .setIssuer(domain)
      .setExpirationTime(expires)
      .sign(new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(env.JWT_SECRET + domain)))),
    env.USERS.put(user.id.toString(), JSON.stringify({ profile, user }, null, 2))
  ])
  await env.REDIRECTS.put(query.state + '2', JSON.stringify({ location, token, expires }), { expirationTtl: 60 })
  return new Response(null, {
    status: 302,
    headers: {
      location: domain === 'oauth.do' ? '/thanks' : `https://${subdomain}/login/callback?state=${query.state}`,
      "Set-Cookie": `${authCookie}=${token}; expires=${expires}; path=/; domain=.${domain}`
    }
  })
})

/**
 * Bound service method to set the login cookie
 */
router.get('/login/callback', async (req, env) => redirect(...(await env.REDIRECTS.get(new URL(req.url).searchParams.get('state') + '2').then(JSON.parse)), req))


/**
 * Bound service method to clear the login cookie
 */
router.get('/logout', (req, env) => redirect('/', '', 499162920, req))


function redirect(location, token, expires, req) {
  return new Response(null, {
    status: 302,
    headers: {
      location,
      "Set-Cookie": `${authCookie}=${token}; expires=${expires}; path=/; domain=.${new URL(req.url).hostname.replace(/.*\.([^.]+.[^.]+)$/, '$1')}`,
    }
  })
}


router.get('*', req => fetch(req))

export default {
  fetch: router.handle
}

