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
  const token = req.cookies['__Session-worker.auth.providers-token']
  try {
    const jwt = await jwtVerify(token, new TextEncoder().encode(env.JWT_SECRET))
    return json({ req, token, jwt })
  } catch {
    const loginUrl = await github.redirect({ options: { clientId: env.GITHUB_CLIENT_ID } })
    return Response.redirect(loginUrl, 302)
  }
})

router.get('/me.jpg', async (req, env) => {
  const token = req.cookies['__Session-worker.auth.providers-token']
  try {
    const jwt = await jwtVerify(token, new TextEncoder().encode(env.JWT_SECRET))
    return fetch(jwt?.payload?.profile?.image || 'https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  } catch {
    return fetch('https://github.com/drivly/oauth.do/raw/main/GetStartedWithGithub.png')
  }
})


router.get('/login', async (req, env) => {
  const loginUrl = await github.redirect({ options: { clientId: env.GITHUB_CLIENT_ID } })
  return Response.redirect(loginUrl, 302)
})


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

  const clientId = env.GITHUB_CLIENT_ID
  const clientSecret = env.GITHUB_CLIENT_SECRET
  console.log({ clientId })
  console.log({ req, id, ip, url })
  const { user } = await github.users({ options: { clientSecret, clientId }, request: { url } })
  console.log({ user })

  const profile = {
    id: user.id,
    name: user.name,
    image: user.avatar_url,
    email: user.email,
  }

  await env.USERS.put(user.id, JSON.stringify({ profile, user }, null, 2))

  const token = await new SignJWT({ profile })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(nanoid())
    .setIssuedAt()
    .setExpirationTime('360d')
    .sign(new TextEncoder().encode(env.JWT_SECRET))

  return new Response(null, {
    status: 302,
    headers: {
      location: '/thanks',
      "Set-Cookie": `__Session-worker.auth.providers-token=${token}; expires=2147483647; path=/;`,
    }
  })
})


router.get('*', req => fetch(req))

export default {
  fetch: router.handle
}

