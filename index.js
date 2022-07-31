import { Router } from 'itty-router'
import { error, json, withContent, withParams } from 'itty-router-extras'
import { github, google } from 'worker-auth-providers'
import jwt from 'jsonwebtoken'

const router = Router()
const recentInteractions = {}

const enrichRequest = req => {
  req.id = req.headers.get('CF-Request-ID') + '-' + req.cf.colo
  req.ip = req.headers.get('CF-Connecting-IP')
  recentInteractions[req.ip] = recentInteractions[req.ip] ? recentInteractions[req.ip] + 1 : 1
  req.recentInteractions = recentInteractions[req.ip]
  req.timestamp = new Date().toISOString()
  if(req.recentInteractions > 100) {
    return error(429, { error: 'Over Rate Limit - Try again soon' })
  }
}

router.all('*', enrichRequest)


router.get('/', (req, env) => json({ req }))


router.get('/login', async (req, env) => {
  const loginUrl = await github.redirect({options:{clientId: env.GITHUB_CLIENT_ID}})
  return Response.redirect(loginUrl, 302)
})


router.get('/callback', async (req, env) => {
  
  const { user: providerUser } = await github.users({ options: { clientSecret: env.GITHUB_CLIENT_SECRET, clientId: env.GITHUB_CLIENT_ID }, request })
  
  const profile = {
    id: user.id,
    name: user.name,
    image: user.avatar_url,
    email: user.email,
  }
  
  await USERS.put(user.id, JSON.stringify(profile))
  
  const clientId = env.GITHUB_CLIENT_ID
  const clientSecret = env.GITHUB_CLIENT_SECRET
  const claims = { user_id: user?.id }
  const secret = env.JWT_SECRET
  const jwt = jwt.sign(claims, secret, { algorithm: "HS256", expiresIn: "365d" })
  
  return new Response(null, {
    status: 302,
    headers: {
      location: '/thanks',
      "Set-Cookie": `__Session-worker.auth.providers-token=${jwt}; expires=${now.toUTCString()}; path=/;`,
    }
  })
  
  
})

export default {
  fetch: router.handle
}

