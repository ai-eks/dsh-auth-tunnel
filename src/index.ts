/**
 * Password-authenticated public access for the Web GUI through Cloudflare
 * Tunnel. The plugin contributes one authenticator to the Host's global Web
 * access service, then points cloudflared directly at the existing WebServer.
 * The core guard covers every current and future HTTP/upgrade route while
 * preserving unauthenticated direct-loopback use.
 * @module @deepseek-ai/dsh-auth-tunnel
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { once } from 'node:events'
import type { IncomingMessage } from 'node:http'
import { spawn, type ChildProcess } from 'node:child_process'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
// Pulls the Context augmentation typing `ctx.webServer`; no runtime import.
import type {} from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-shell-env'
import type {} from '@deepseek-ai/dsh-system-prompt'

/** Which tunnel this composition runs. */
export type TunnelMode = 'quick' | 'token'

/** Plugin config: the access password, tunnel mode, named-tunnel facts, and process tuning. */
export interface Config {
  /** Credential reference resolving to the shared access password. */
  passwordRef: string
  /** Session-cookie lifetime in hours; a minted cookie is valid for this long regardless of activity. */
  sessionTtlHours: number
  /** `quick` creates an ephemeral URL; `token` runs the named tunnel belonging to a Tunnel Token. */
  mode: TunnelMode
  /** Credential reference resolving to the Tunnel Token (`token` mode only). */
  tokenRef?: string
  /** Public hostname bound to the named tunnel (`token` mode only). */
  publicHostname?: string
  /** cloudflared executable: a PATH name or an absolute path. */
  executable: string
  /** How long activation waits for the tunnel to come up before failing the load. */
  startupTimeoutMs: number
}

interface InternalConfig extends Config {}

interface WebAccessDecision {
  kind: 'grant' | 'respond'
  response?: Response
}

interface WebAccessAuthenticator {
  authorize(request: IncomingMessage): WebAccessDecision | Promise<WebAccessDecision>
}

interface WebAccessService {
  registerAuthenticator(authenticator: WebAccessAuthenticator): () => void
}

export const name = '@deepseek-ai/dsh-auth-tunnel'

/** The existing WebServer, its global access service, and credentials must all exist before activation. */
export const inject = ['webServer', 'webAccess', 'credentials']

export const Config: z<InternalConfig> = z.object({
  passwordRef: z.string().role('credential-ref').default('DSH_WEB_PASSWORD'),
  sessionTtlHours: z.number().min(0.01).default(720),
  mode: z.union(['quick', 'token']).default('quick'),
  tokenRef: z.string().role('credential-ref'),
  publicHostname: z.string(),
  executable: z.string().default('cloudflared'),
  startupTimeoutMs: z.number().step(1).min(1).default(15_000),
})

const AUTH_PREFIX = '/dsh-auth-tunnel'
const LOGIN_PATH = `${AUTH_PREFIX}/login`
const LOGOUT_PATH = `${AUTH_PREFIX}/logout`
const AUTH_COOKIE = 'dsh_auth_tunnel'
const MAX_LOGIN_BODY_BYTES = 16 * 1024
const OUTPUT_TAIL_CHARS = 8192
const KILL_GRACE_MS = 2000
const QUICK_URL_PATTERN = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/

/**
 * The model-facing prompt section text for one live public URL.
 * @param publicUrl - discovered quick-tunnel URL or configured hostname URL.
 * @returns the `app:public-access` section body.
 */
export function publicAccessPrompt(publicUrl: string): string {
  return `This instance is also reachable from the public internet at ${publicUrl} through a Cloudflare Tunnel, protected by the instance's shared access password. Share that URL — never the password — when the user asks to open this GUI from another device or network. All sessions, tools, and files still run on this host.`
}

/** Resolve the credential-backed HMAC key used by login and cookie verification. */
async function sessionKey(ctx: Context, ref: string): Promise<Buffer | undefined> {
  const hit = await ctx.credentials.resolve(credentialRef(ref))
  if (hit === undefined || hit.value === '') return undefined
  return createHash('sha256').update(hit.value).digest()
}

/** Mint the session cookie value: version, absolute expiry, and HMAC. */
function mintCookie(key: Buffer, ttlMs: number): string {
  const expiry = Date.now() + ttlMs
  const mac = createHmac('sha256', key).update(`dsh-auth-tunnel/v1/${String(expiry)}`).digest('base64url')
  return `v1.${String(expiry)}.${mac}`
}

/** Verify a minted cookie value against the current key and clock. */
function verifyCookie(key: Buffer, value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return false
  const expiry = Number(parts[1])
  if (!Number.isSafeInteger(expiry) || expiry <= Date.now()) return false
  const expected = createHmac('sha256', key).update(`dsh-auth-tunnel/v1/${String(expiry)}`).digest('base64url')
  /* v8 ignore next -- the three-part check above pins the MAC segment. */
  const presented = Buffer.from(parts.at(2) ?? '')
  const wanted = Buffer.from(expected)
  return presented.length === wanted.length && timingSafeEqual(presented, wanted)
}

/** Read one cookie value from a node:http Cookie header. */
function readCookie(header: string | string[] | undefined, name: string): string | undefined {
  if (header === undefined) return undefined
  /* v8 ignore next -- Node joins repeated Cookie headers; the array arm preserves the declared input union. */
  for (const line of Array.isArray(header) ? header : [header]) {
    for (const segment of line.split(';')) {
      const eq = segment.indexOf('=')
      if (eq !== -1 && segment.slice(0, eq).trim() === name) return segment.slice(eq + 1).trim()
    }
  }
  return undefined
}

/** Whether an unauthorized request is a browser navigation that wants the login page. */
function isNavigation(request: IncomingMessage): boolean {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false
  if (request.headers['sec-fetch-dest'] === 'document') return true
  return request.headers.accept?.includes('text/html') === true
}

/** Format a Set-Cookie line for one minted or cleared session. */
function setSessionCookie(secure: boolean, value: string, ttlMs: number): string {
  const base = `${AUTH_COOKIE}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${String(Math.floor(ttlMs / 1000))}`
  return secure ? `${base}; Secure` : base
}

/** Whether the tunnel-facing request arrived at Cloudflare over HTTPS. */
function isSecureRequest(request: IncomingMessage): boolean {
  const value = request.headers['x-forwarded-proto']
  return typeof value === 'string' && value.split(',', 1)[0]?.trim().toLowerCase() === 'https'
}

/** Self-contained login page; it needs no unauthenticated asset routes. */
function loginPage(error: boolean): string {
  const banner = error ? '<p class="error">密码错误,请重试</p>' : ''
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>登录 - DeepSeek Harness</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0d10;color:#e6e8eb;font-family:system-ui,-apple-system,sans-serif}
main{width:min(360px,90vw)}
h1{font-size:20px;font-weight:600;margin:0 0 16px}
label{display:block;font-size:13px;color:#9aa3ad;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #2a2f36;background:#14171b;color:#e6e8eb;font-size:15px}
button{margin-top:14px;width:100%;padding:10px;border:none;border-radius:8px;background:#4f7cff;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#5f88ff}
.error{margin-top:12px;color:#ff8a80;font-size:13px}
.hint{margin-top:16px;font-size:12px;color:#5f6770}
</style>
</head>
<body>
<main>
<h1>访问密码</h1>
<form method="post" action="${LOGIN_PATH}" data-error="${error ? '1' : '0'}">
<label for="password">请输入共享访问密码</label>
<input id="password" name="password" type="password" autocomplete="off" required autofocus>
<button type="submit">登录</button>
</form>
${banner}
<p class="hint">该页面由 dsh-auth-tunnel 提供。</p>
</main>
</body>
</html>`
}

type FormRead = { form: URLSearchParams } | { response: Response }

/** Read one bounded URL-encoded login body. */
async function readForm(request: IncomingMessage): Promise<FormRead> {
  const mediaType = request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase()
  if (mediaType !== 'application/x-www-form-urlencoded') {
    return { response: new Response(null, { status: 415 }) }
  }
  const declared = request.headers['content-length']
  if (declared !== undefined && Number(declared) > MAX_LOGIN_BODY_BYTES) {
    return { response: new Response(null, { status: 413, headers: { connection: 'close' } }) }
  }
  let received = 0
  const chunks: Buffer[] = []
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
    received += bytes.byteLength
    if (received > MAX_LOGIN_BODY_BYTES) {
      request.resume()
      return { response: new Response(null, { status: 413, headers: { connection: 'close' } }) }
    }
    chunks.push(bytes)
  }
  return { form: new URLSearchParams(Buffer.concat(chunks).toString('utf8')) }
}

/** Password provider for the core global Web access service. */
class PasswordAuthenticator implements WebAccessAuthenticator {
  private readonly ttlMs: number

  constructor(
    private readonly ctx: Context,
    private readonly passwordRef: string,
    sessionTtlHours: number,
  ) {
    this.ttlMs = sessionTtlHours * 3600 * 1000
  }

  /** Authenticate the request or answer the login/logout handshake. */
  async authorize(request: IncomingMessage): Promise<WebAccessDecision> {
    /* v8 ignore next -- node:http server requests always carry a URL. */
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    if (url.pathname === LOGIN_PATH || url.pathname === LOGOUT_PATH) {
      return { kind: 'respond', response: await this.handshake(url, request) }
    }
    const key = await sessionKey(this.ctx, this.passwordRef)
    const cookie = readCookie(request.headers.cookie, AUTH_COOKIE)
    if (key !== undefined && cookie !== undefined && verifyCookie(key, cookie)) return { kind: 'grant' }
    if (isNavigation(request)) {
      return {
        kind: 'respond',
        response: new Response(null, {
          status: 302,
          headers: { location: LOGIN_PATH, 'cache-control': 'no-store' },
        }),
      }
    }
    return {
      kind: 'respond',
      response: new Response('{"error":"authentication required"}', {
        status: 401,
        headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
      }),
    }
  }

  private async handshake(url: URL, request: IncomingMessage): Promise<Response> {
    if (url.pathname === LOGIN_PATH && request.method === 'GET') {
      return new Response(loginPage(url.searchParams.get('error') === '1'), {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
      })
    }
    if (url.pathname === LOGIN_PATH && request.method === 'POST') {
      const read = await readForm(request)
      if ('response' in read) return read.response
      const key = await sessionKey(this.ctx, this.passwordRef)
      if (key === undefined) {
        this.ctx.logger.error('auth-tunnel: the access-password credential is no longer configured')
        return new Response(null, { status: 503 })
      }
      const presented = createHash('sha256').update(read.form.get('password') ?? '').digest()
      if (!timingSafeEqual(presented, key)) {
        return new Response(null, {
          status: 303,
          headers: { location: `${LOGIN_PATH}?error=1`, 'cache-control': 'no-store' },
        })
      }
      return new Response(null, {
        status: 303,
        headers: {
          location: '/',
          'cache-control': 'no-store',
          'set-cookie': setSessionCookie(isSecureRequest(request), mintCookie(key, this.ttlMs), this.ttlMs),
        },
      })
    }
    if (url.pathname === LOGOUT_PATH && (request.method === 'GET' || request.method === 'POST')) {
      return new Response(null, {
        status: 303,
        headers: {
          location: LOGIN_PATH,
          'cache-control': 'no-store',
          'set-cookie': setSessionCookie(isSecureRequest(request), '', 0),
        },
      })
    }
    return new Response(null, { status: 404 })
  }
}

/** Spawn cloudflared and resolve once the public tunnel is ready. */
async function spawnTunnel(ctx: Context, config: InternalConfig, target: string): Promise<{ child: ChildProcess; publicUrl: string }> {
  let args: string[]
  let publicUrlHint: string | undefined
  const env: NodeJS.ProcessEnv = {}
  /* v8 ignore start -- present in real processes; conditionals support scrubbed tests. */
  if (process.env.PATH !== undefined) env.PATH = process.env.PATH
  if (process.env.HOME !== undefined) env.HOME = process.env.HOME
  if (process.env.TMPDIR !== undefined) env.TMPDIR = process.env.TMPDIR
  /* v8 ignore stop */
  if (config.mode === 'quick') {
    if (config.tokenRef !== undefined || config.publicHostname !== undefined) {
      throw new Error('auth-tunnel: tokenRef and publicHostname belong to token mode, not quick')
    }
    args = ['tunnel', '--url', target, '--no-autoupdate']
  } else {
    const tokenRef = required(config, 'tokenRef', 'token mode requires tokenRef naming the Tunnel Token credential reference')
    publicUrlHint = `https://${required(config, 'publicHostname', 'token mode requires publicHostname, the hostname bound to the named tunnel in the Cloudflare dashboard')}`
    const hit = await ctx.credentials.resolve(credentialRef(tokenRef))
    if (hit === undefined || hit.value === '') {
      throw new Error(`auth-tunnel: credential reference "${tokenRef}" is not configured`)
    }
    env.TUNNEL_TOKEN = hit.value
    args = ['tunnel', 'run', '--no-autoupdate']
  }

  const child = spawn(config.executable, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
  let tail = ''
  const onData = (chunk: Buffer): void => {
    const text = chunk.toString('utf8')
    tail = (tail + text).slice(Math.max(tail.length + text.length - OUTPUT_TAIL_CHARS, 0))
  }
  child.stderr.on('data', onData)
  child.stdout.on('data', onData)

  try {
    const ready = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`auth-tunnel: cloudflared produced no public URL within ${String(config.startupTimeoutMs)}ms`))
      }, config.startupTimeoutMs)
      const finish = (action: () => void): void => {
        clearTimeout(timeout)
        action()
      }
      child.once('error', (error) => {
        finish(() => { reject(new Error(`auth-tunnel: failed to spawn ${config.executable}: ${error.message}`)) })
      })
      child.once('exit', (code, signal) => {
        finish(() => {
          reject(new Error(
            `auth-tunnel: cloudflared exited before the tunnel came up (code ${String(code)}, signal ${String(signal)})\n${tail}`,
          ))
        })
      })
      const scan = (chunk: Buffer): void => {
        if (config.mode === 'quick') {
          const hit = QUICK_URL_PATTERN.exec(chunk.toString('utf8'))
          if (hit !== null) finish(() => { resolve(hit[0]) })
        } else if (publicUrlHint !== undefined && chunk.toString('utf8').includes('Registered tunnel connection')) {
          finish(() => { resolve(publicUrlHint) })
        }
      }
      child.stderr.on('data', scan)
      child.stdout.on('data', scan)
    })
    return { child, publicUrl: await ready }
  } catch (error) {
    await killTree(child)
    throw error
  }
}

/** Terminate cloudflared and await its exit: SIGTERM, then SIGKILL after the grace. */
async function killTree(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  const closed = once(child, 'close')
  child.kill('SIGTERM')
  const escalation = setTimeout(() => { child.kill('SIGKILL') }, KILL_GRACE_MS)
  await closed
  clearTimeout(escalation)
}

/** Read one mode-required key or throw a load-time misconfiguration. */
function required<TKey extends 'tokenRef' | 'publicHostname'>(
  config: InternalConfig,
  key: TKey,
  message: string,
): NonNullable<InternalConfig[TKey]> {
  const value = config[key]
  if (value === undefined) throw new Error(`auth-tunnel: ${message}`)
  return value
}

/** Resolve the injected service without coupling this external package to an unreleased type package. */
function accessService(ctx: Context): WebAccessService {
  const service = ctx.get('webAccess') as WebAccessService | undefined
  if (service === undefined) throw new Error('auth-tunnel: webAccess service is required')
  return service
}

/**
 * Register password authentication, start cloudflared against the existing
 * WebServer, and publish the public URL to optional shell and prompt services.
 * @param ctx - plugin context.
 * @param config - validated plugin config.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const key = await sessionKey(ctx, config.passwordRef)
  if (key === undefined) {
    throw new Error(`auth-tunnel: credential reference "${config.passwordRef}" is not configured`)
  }

  const authenticator = new PasswordAuthenticator(ctx, config.passwordRef, config.sessionTtlHours)
  const disposeAuthenticator = ctx.effect(
    () => accessService(ctx).registerAuthenticator(authenticator),
    'auth-tunnel: Web authenticator',
  )
  let spawned: { child: ChildProcess; publicUrl: string }
  try {
    spawned = await spawnTunnel(ctx, config, `http://127.0.0.1:${String(ctx.webServer.port)}`)
  } catch (error) {
    await disposeAuthenticator()
    throw error
  }

  const { child, publicUrl } = spawned
  let disposed = false
  child.once('exit', (code, signal) => {
    if (disposed) return
    ctx.logger.error(`auth-tunnel: cloudflared exited (code ${String(code)}, signal ${String(signal)}); the public URL ${publicUrl} is now dead. Restart dsh to bring the tunnel back.`)
  })
  ctx.effect(() => async () => {
    disposed = true
    await killTree(child)
  }, 'auth-tunnel: cloudflared')

  console.log(`cloudflare tunnel: ${publicUrl}`)
  ctx.inject(['shellEnv'], (injected) => {
    injected.shellEnv.register({
      name: 'auth-tunnel',
      variables: { DSH_PUBLIC_URL: { description: 'Public URL of this instance, when the Cloudflare Tunnel is mounted' } },
      resolve: () => ({ DSH_PUBLIC_URL: publicUrl }),
    })
  })
  ctx.inject(['systemPrompt'], (injected) => {
    injected.systemPrompt.section({
      name: 'app:public-access',
      order: -97,
      text: () => publicAccessPrompt(publicUrl),
    })
  })
}
