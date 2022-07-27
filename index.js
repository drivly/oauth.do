import { Router } from 'itty-router'
import { error, json, withContent, withParams } from 'itty-router-extras'
import { github, google } from 'worker-auth-providers'

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
  const loginUrl = await github.redirect({options:{clientId: env.GITHUB_CLIENT_ID}})
  return Response.redirect(loginUrl, 302)
})

export default {
  fetch: router.handle
}

