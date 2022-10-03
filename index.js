import { Router } from 'itty-router'
import { error, json, withCookies } from 'itty-router-extras'
import { jwtVerify, SignJWT } from 'jose'
import { nanoid } from 'nanoid'
import github from './github'

const router = Router()
const recentInteractions = {}
const authCookie = '__Secure-worker.auth.providers-token'

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

async function verify(hostname, token, env) {
  const domain = hostname.replace(/.*\.([^.]+.[^.]+)$/, '$1')
  const hash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(env.JWT_SECRET + domain))
  try {
    return await jwtVerify(token, new Uint8Array(hash), { issuer: domain })
  } catch (error) {
    console.log({ error })
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
    return await loginRedirect(req, env)
  }
})


router.get('/me.jpg', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies[authCookie]
  try {
    const jwt = await verify(hostname, token, env)
    return await fetch(jwt?.payload?.profile?.image || 'https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  } catch {
    return await fetch('https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  }
})


/**
 * Bound login service (also bound on oauth.do)
 */
router.get('/login', loginRedirect)

async function loginRedirect(req, env) {
  const context = await env.CTX.fetch(req).then(res => res.json())
  const { hostname, headers, query } = context
  const redirect = query?.state && await env.REDIRECTS.get(query.state).then(JSON.parse)
  const sendCookie = redirect ? redirect.sendCookie :
    query?.redirect_uri && new URL(query.redirect_uri).hostname === hostname ||
    !query?.redirect_uri && headers?.referer && new URL(headers.referer).hostname === hostname
  const location = redirect?.location || query?.redirect_uri || headers?.referer || `https://${hostname}/api`
  const state = query?.state || crypto.randomUUID()
  if (!query?.state) await env.REDIRECTS.put(state, JSON.stringify({ location, sendCookie }), { expirationTtl: 600 })
  const token = req.cookies[authCookie]
  let jwt;
  if (token && (jwt = await verify(hostname, token, env)))
    return hostname === (location && new URL(location).hostname) ?
      cookieRedirect(hostname === 'oauth.do' ? '/thanks' : location, token, jwt.payload.exp, req, sendCookie) :
      await callback(req, env, context)
  const options = { clientId: env.GITHUB_CLIENT_ID, state }
  return Response.redirect(hostname === 'oauth.do' ?
    github.redirect({ options }) :
    `https://oauth.do/login?state=${state}`, 302)
}

function cookieRedirect(location, token, expires, req, sendCookie = true) {
  return new Response(null, {
    status: 302,
    headers: {
      location,
      "Set-Cookie": sendCookie ? `${authCookie}=${token}; expires=${new Date(expires)}; path=/; domain=.${new URL(req.url).hostname.replace(/.*\.([^.]+.[^.]+)$/, '$1')}; Secure; HttpOnly` : undefined,
    }
  })
}


/**
 * Callback to oauth.do from external oauth provider
 */
router.get('/callback', async (req, env) => await callback(req, env, await env.CTX.fetch(req).then(res => res.json())))

async function callback(req, env, context) {
  let { query, url, user: contextUser, hostname } = context
  if (query.error) {
    return new Response(query.error, {
      status: 401,
    })
  }
  const clientId = env.GITHUB_CLIENT_ID
  const clientSecret = env.GITHUB_CLIENT_SECRET

  let [users, redirect] = await Promise.all([!contextUser?.authenticated && github.users({ options: { clientSecret, clientId }, request: { url } }), env.REDIRECTS.get(query.state).then(JSON.parse)])
  const { location, sendCookie } = redirect
  const kvUser = contextUser.profile?.id && await env.USERS.get(contextUser.profile.id).then(JSON.parse).catch(() => '')
  const user = (kvUser || users).user
  const profile = kvUser?.profile || {
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

  const token = await new SignJWT({ profile })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(nanoid())
    .setIssuedAt()
    .setIssuer(domain)
    .setExpirationTime(expires)
    .sign(new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(env.JWT_SECRET + domain))))

  await Promise.all([
    !kvUser && env.USERS.put(user.id.toString(), JSON.stringify({ profile, user }, null, 2)),
    env.REDIRECTS.put(query.state + '2', JSON.stringify({ location, token, expires, sendCookie }), { expirationTtl: 60 }),
  ])
  return cookieRedirect(domain === 'oauth.do' ? '/thanks' : `https://${subdomain}/login/callback?state=${query.state}`, token, expires, req, sendCookie)
}


/**
 * Bound service method to set the login cookie
 */
router.get('/login/callback', async (req, env) => {
  let { location, token, expires, sendCookie } = await env.REDIRECTS.get(new URL(req.url).searchParams.get('state') + '2').then(JSON.parse)
  return cookieRedirect(location, token, expires, req, sendCookie)
})


/**
 * Bound service method to clear the login cookie
 */
router.get('/logout', (req, env) => cookieRedirect('/', '', 499162920, req))


router.get('*', req => fetch(req))

export default {
  fetch: router.handle
}

