import { Router } from 'itty-router'
import { error, json, withCookies } from 'itty-router-extras'
import { jwtVerify, SignJWT } from 'jose'
import { nanoid } from 'nanoid'
import github from './github'
import sha1 from 'sha1'

const router = Router()
const recentInteractions = {}
const authCookie = '__Session-worker.auth.providers-token'
const future2038problem = 2147483647

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
    const jwt = await jwtVerify(token, new TextEncoder().encode(sha1(env.JWT_SECRET + hostname)))
    return json({ req, token, jwt })
  } catch {
    return loginRedirect(req, env)
  }
})

router.get('/me.jpg', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies[authCookie]
  try {
    const jwt = await jwtVerify(token, new TextEncoder().encode(sha1(env.JWT_SECRET + hostname)))
    return fetch(jwt?.payload?.profile?.image || 'https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  } catch {
    return fetch('https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  }
})


router.get('/login', loginRedirect)

async function loginRedirect(req, env) {
  let { hostname, referer } = await env.CTX.fetch(req).then(res => res.json())
  const options = { clientId: env.GITHUB_CLIENT_ID, state: crypto.randomUUID() }
  const location = new URL(referer).hostname === hostname ? referer : `https://${hostname}/api`
  const [loginUrl] = await Promise.all([github.redirect({ options }), env.REDIRECTS.put(options.state, { location }, { expirationTtl: 600 })])
  return Response.redirect(loginUrl, 302)
}


router.get('/callback', async (req, env) => {
  const { id, ip, url } = req
  const { hostname, searchParams } = new URL(url)
  const error = searchParams.get('error')
  if (error) {
    return new Response(error, {
      status: 401,
    })
  }
  const state = searchParams.get('state')
  const clientId = env.GITHUB_CLIENT_ID
  const clientSecret = env.GITHUB_CLIENT_SECRET
  console.log({ clientId })
  console.log({ req, id, ip, url })

  let [users, location] = await Promise.all([github.users({ options: { clientSecret, clientId }, request: { url } }), env.REDIRECTS.get(state)])
  const user = users.user
  location = location.location

  // TODO: import a module for allowlist
  const domain = location && new URL(location).hostname || hostname
  if (!domain.match(/\.(cf|do)$/i))
    return new Response("Domain not allowed.", {
      status: 403,
    })

  const profile = {
    id: user.id,
    name: user.name,
    image: user.avatar_url,
    email: user.email,
  }

  let expires = new Date()
  expires.setFullYear(expires.getFullYear() + 1)
  expires = expires.valueOf()

  const [token] = await Promise.all([
    new SignJWT({ profile })
      .setProtectedHeader({ alg: 'HS256' })
      .setJti(nanoid())
      .setIssuedAt()
      .setExpirationTime('360d')
      .sign(new TextEncoder().encode(sha1(env.JWT_SECRET + domain))),
    env.USERS.put(user.id.toString(), JSON.stringify({ profile, user }, null, 2)),
    env.REDIRECTS.put(options.state, { location, token, expires }, { expirationTtl: 42 })
  ])

  return new Response(null, {
    status: 302,
    headers: domain === 'oauth.do' ? {
      location: '/thanks',
      "Set-Cookie": `${authCookie}=${token}; expires=${expires}; path=/;`
    } : {
      location: new URL(`/login/callback?state=${state}`),
    }
  })
})


router.get('/login/callback', async (req, env) => {
  const state = new URL(req.url).searchParams.get('state')
  const { location, token, expires } = await env.REDIRECTS.get(state)
  return new Response(null, {
    status: 302,
    headers: {
      location,
      "Set-Cookie": `${authCookie}=${token}; expires=${expires}; path=/;`,
    }
  })
})


router.get('/logout', async (req, env) => {
  return new Response(null, {
    status: 302,
    headers: {
      location: '/',
      "Set-Cookie": `${authCookie}=; expires=499162920; path=/;`,
    }
  })
})


router.get('*', req => fetch(req))

export default {
  fetch: router.handle
}

