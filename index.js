import { Router } from 'itty-router'
import { error, json, withCookies } from 'itty-router-extras'
import github from './providers/github'
import google from './providers/google'
import qs from 'qs'

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
  if (!token) return token
  const json = await env.JWT.fetch(new Request(new URL(`/verify?token=${token}`, 'https://' + hostname.replace(/.*\.([^.]+.[^.]+)$/, '$1')), {
    headers: { 'cookie': `${authCookie}=${token}` }
  })).then(res => res.json())
  return json.jwt
}

router.all('*', withCookies, enrichRequest)


router.get('/', (req) => json({ req }))


router.get('/me', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies?.[authCookie]
  const jwt = await verify(hostname, token, env)
  if (jwt) return json({ req, token, jwt })
  return await loginRedirect(new Request(req.url, { headers: { referer: req.url }, cf: req.cf }), env)
})


router.get('/me.jpg', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies?.[authCookie]
  const jwt = await verify(hostname, token, env)
  return await fetch(jwt?.payload?.profile?.image || 'https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
})


/**
 * Bound login service (also bound on oauth.do)
 */
router.get('/login', loginRedirect)


router.get('/login/:provider', loginRedirect)

async function loginRedirect(req, env) {
  const context = await env.CTX.fetch(req).then(res => res.json())
  const { hostname, headers, pathSegments, query, } = context
  const redirect = query?.state && await env.REDIRECTS.get(query.state).then(JSON.parse)
  const sendCookie = redirect ? redirect.sendCookie :
    query?.redirect_uri && new URL(decodeURIComponent(query.redirect_uri)).hostname === hostname ||
    !query?.redirect_uri && headers?.referer && new URL(headers.referer).hostname === hostname
  const location = redirect?.location ||
    query?.redirect_uri && decodeURIComponent(query.redirect_uri) ||
    headers?.referer !== 'https://oauth.do/' && headers?.referer ||
    hostname === 'oauth.do' && 'https://oauth.do/thanks' ||
    `https://${hostname}/api`
  const state = query?.state || crypto.randomUUID()
  if (!query?.state) await env.REDIRECTS.put(state, JSON.stringify({ location, sendCookie }), { expirationTtl: 600 })
  const token = req.cookies?.[authCookie]
  let jwt
  if (token && (jwt = await verify(hostname, token, env)))
    return hostname === (location && new URL(location).hostname) ?
      cookieRedirect(location, token, jwt.payload.exp, req, sendCookie) :
      await callback(req, env, context)
  let provider = pathSegments[pathSegments.length - 1]
  const options = { state }
  let providerInstance = null
  switch (provider) {
    case 'google':
      options.clientId = env.GOOGLE_CLIENT_ID
      options.redirectUrl = 'https://oauth.do/callback/google'
      providerInstance = google
      break;
    case 'github':
    default:
      options.clientId = env.GITHUB_CLIENT_ID
      providerInstance = github
      break;
  }
  return Response.redirect(hostname === 'oauth.do' ?
    providerInstance.redirect({ options }) :
    `https://oauth.do/login/${provider}?state=${state}`, 302)
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
router.get('/callback/:provider', async (req, env) => await callback(req, env, await env.CTX.fetch(req).then(res => res.json())))

async function callback(req, env, context) {
  let { hostname, pathSegments, query, url, user, } = context
  if (query.error) {
    return new Response(query.error, {
      status: 401,
    })
  }

  let provider = pathSegments[pathSegments.length - 1]
  const options = {}
  let providerInstance = null
  switch (provider) {
    case 'google':
      options.clientId = env.GOOGLE_CLIENT_ID
      options.clientSecret = env.GOOGLE_CLIENT_SECRET
      providerInstance = google
      break;
    case 'github':
    default:
      options.clientId = env.GITHUB_CLIENT_ID
      options.clientSecret = env.GITHUB_CLIENT_SECRET
      providerInstance = github
      break;
  }

  let [users, redirect] = await Promise.all([!user?.id && providerInstance.users({ options, request: { url } }), env.REDIRECTS.get(query.state).then(JSON.parse)])
  const { location, sendCookie } = redirect
  const profile = {
    id: user?.id || users?.user?.id,
    user: user?.user || users?.user?.login,
    name: user?.name || users?.user?.name,
    image: user?.image || users?.user?.avatar_url,
    email: user?.email || users?.user?.email,
  }

  const subdomain = location && new URL(location).hostname || hostname
  const domain = subdomain.replace(/.*\.([^.]+.[^.]+)$/, '$1')
  let expires = new Date()
  expires.setFullYear(expires.getFullYear() + 1)
  expires = expires.valueOf()

  const json = await env.JWT.fetch(new Request(
    new URL('/generate?' + qs.stringify({ issuer: domain, expirationTTL: expires, secret: env.JWT_SECRET + domain, profile }), 'https://' + domain)))
    .then(res => res.json())
  if (json.error) throw json.error

  await Promise.all([
    users && env.USERS.put(profile.id.toString(), JSON.stringify({ profile, user: users.user }, null, 2)),
    env.REDIRECTS.put(query.state + '2', JSON.stringify({ location, token: json.token, expires, sendCookie }), { expirationTtl: 60 }),
  ])
  return cookieRedirect(domain === 'oauth.do' ? location : `https://${subdomain}/login/callback?state=${query.state}`, json.token, expires, req, sendCookie)
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

