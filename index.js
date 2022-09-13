import { Router } from 'itty-router'
import { error, json, withCookies } from 'itty-router-extras'
import { jwtVerify, SignJWT } from 'jose'
import { nanoid } from 'nanoid'
import github from './github'

const router = Router()
const recentInteractions = {}

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
  const token = req.cookies['__Session-worker.auth.providers-token']
  try {
    const jwt = await jwtVerify(token, new TextEncoder().encode(computeKey(hostname)))
    return json({ req, token, jwt })
  } catch {
    return loginRedirect(req, env)
  }
})

router.get('/me.jpg', async (req, env) => {
  const { hostname } = new URL(req.url)
  const token = req.cookies['__Session-worker.auth.providers-token']
  try {
    const jwt = await jwtVerify(token, new TextEncoder().encode(computeKey(hostname)))
    return fetch(jwt?.payload?.profile?.image || 'https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  } catch {
    return fetch('https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  }
})


router.get('/login', loginRedirect)

async function loginRedirect(req, env) {
  const { searchParams } = new URL(req.url)
  const options = { clientId: env.GITHUB_CLIENT_ID, state: crypto.randomUUID() }
  const redirect_uri = searchParams.get('redirect_uri')
  const [loginUrl] = await Promise.all([github.redirect({ options }), env.REDIRECTS.put(options.state, redirect_uri, { expirationTtl: 300 })])
  return Response.redirect(loginUrl, 302)
}

function computeKey(env, hostname) {
  return crypto.createHash('md5').update(env.JWT_SECRET + hostname).digest('hex');
}


router.get('/logout', async (req, env) => {
  return new Response(null, {
    status: 302,
    headers: {
      location: '/',
      "Set-Cookie": `__Session-worker.auth.providers-token=; expires=499162920; path=/;`,
    }
  })
})


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
  location = location || '/thanks'
  console.log({ user })
  const profile = {
    id: user.id,
    name: user.name,
    image: user.avatar_url,
    email: user.email,
  }

  const [token] = await Promise.all([
    new SignJWT({ profile })
      .setProtectedHeader({ alg: 'HS256' })
      .setJti(nanoid())
      .setIssuedAt()
      .setExpirationTime('360d')
      .sign(new TextEncoder().encode(computeKey(hostname))),

    env.USERS.put(user.id.toString(), JSON.stringify({ profile, user }, null, 2))
  ])

  return new Response(null, {
    status: 302,
    headers: {
      location,
      "Set-Cookie": `__Session-worker.auth.providers-token=${token}; expires=2147483647; path=/;`,
    }
  })
})


router.get('*', req => fetch(req))

export default {
  fetch: router.handle
}

