/**
 * Self-contained public access for the Web GUI: a loopback password gate in
 * front of the webserver, published through a Cloudflare Tunnel. The gate is
 * a plain `node:http` proxy the plugin owns outright, so no web-facing
 * package changes shape: cloudflared dials the gate on loopback, the gate
 * enforces the shared-access-password handshake, and accepted requests reach
 * the loopback webserver with their Host and matching browser Origin rewritten
 * to the loopback authority (which keeps the upstream trust fence satisfied).
 * Only the public path is password-protected; direct loopback use of the Web
 * GUI stays open.
 * @module @deepseek-ai/dsh-auth-tunnel
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { once } from 'node:events'
import { createServer, request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { connect as netConnect } from 'node:net'
import { type Duplex } from 'node:stream'
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

/** Plugin config: the access password, tunnel mode, the named-tunnel facts, and process tuning. */
export interface Config {
  /**
   * Credential reference resolving to the shared access password, resolved
   * through the composition's credentials service. Configuration carries the
   * reference, never the password.
   */
  passwordRef: string
  /** Session-cookie lifetime in hours; a minted cookie is valid for this long regardless of activity. */
  sessionTtlHours: number
  /** `quick` dials an ephemeral `*.trycloudflare.com` tunnel; `token` runs the named tunnel a Tunnel Token belongs to. */
  mode: TunnelMode
  /** Credential reference resolving to the Tunnel Token (`token` mode only); configuration carries the reference, never the token. */
  tokenRef?: string
  /**
   * Public hostname bound to the named tunnel in the Cloudflare dashboard
   * (`token` mode only), used for the URL line and the model-facing values.
   */
  publicHostname?: string
  /**
   * Loopback port the password gate listens on; 0 assigns one from the OS.
   * `token` mode requires an explicit value: the named tunnel's dashboard
   * ingress must point at this port, and a random one could not be known there.
   */
  gatePort: number
  /** cloudflared executable: a PATH name or an absolute path. */
  executable: string
  /** How long activation waits for the tunnel to come up before failing the load. */
  startupTimeoutMs: number
}

interface InternalConfig {
  passwordRef: string
  sessionTtlHours: number
  mode: TunnelMode
  tokenRef?: string
  publicHostname?: string
  gatePort: number
  executable: string
  startupTimeoutMs: number
}

export const name = '@deepseek-ai/dsh-auth-tunnel'

// The gate proxies onto the loopback webserver and resolves credential
// references, so activation waits for both services.
export const inject = ['webServer', 'credentials']

export const Config: z<InternalConfig> = z.object({
  passwordRef: z.string().role('credential-ref').default('DSH_WEB_PASSWORD'),
  sessionTtlHours: z.number().min(0.01).default(720),
  mode: z.union(['quick', 'token']).default('quick'),
  tokenRef: z.string().role('credential-ref'),
  publicHostname: z.string(),
  gatePort: z.number().step(1).min(0).max(65535).default(0),
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

/** The model-facing prompt section text for one live public URL.
 * @param publicUrl - the discovered quick-tunnel URL or the configured hostname URL.
 * @returns the `app:public-access` section body.
 */
export function publicAccessPrompt(publicUrl: string): string {
  return `This instance is also reachable from the public internet at ${publicUrl} through a Cloudflare Tunnel, protected by the instance's shared access password. Share that URL — never the password — when the user asks to open this GUI from another device or network. All sessions, tools, and files still run on this host.`
}

/** Fetch one credential-backed HMAC key the login handshake and the cookie verifier are compared against. */
async function sessionKey(ctx: Context, ref: string): Promise<Buffer | undefined> {
  const hit = await ctx.credentials.resolve(credentialRef(ref))
  /* The load-time check keeps boot honest: unconfigured never opens a public
     gate; the runtime re-check only guards a credential deleted mid-flight */
  if (hit === undefined || hit.value === '') return undefined
  return createHash('sha256').update(hit.value).digest()
}

/** Mint the session cookie value: version, absolute expiry, and the HMAC over both. */
function mintCookie(key: Buffer, ttlMs: number): string {
  const expiry = Date.now() + ttlMs
  const mac = createHmac('sha256', key).update(`dsh-auth-tunnel/v1/${String(expiry)}`).digest('base64url')
  return `v1.${String(expiry)}.${mac}`
}

/** Verify a minted cookie value against the current session key and the clock. */
function verifyCookie(key: Buffer, value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return false
  const expiry = Number(parts[1])
  if (!Number.isSafeInteger(expiry) || expiry <= Date.now()) return false
  const expected = createHmac('sha256', key).update(`dsh-auth-tunnel/v1/${String(expiry)}`).digest('base64url')
  /* v8 ignore next -- the 3-part shape above pins the mac segment */
  const presented = Buffer.from(parts.at(2) ?? '')
  const wanted = Buffer.from(expected)
  return presented.length === wanted.length && timingSafeEqual(presented, wanted)
}

/** Read one cookie value out of a node:http cookie header. */
function readCookie(header: string | string[] | undefined, name: string): string | undefined {
  if (header === undefined) return undefined
  /* v8 ignore next -- node:http joins repeated cookie headers into one string;
  the array arm covers callers passing the raw union */
  for (const line of Array.isArray(header) ? header : [header]) {
    for (const segment of line.split(';')) {
      const eq = segment.indexOf('=')
      if (segment.slice(0, eq).trim() === name) return segment.slice(eq + 1).trim()
    }
  }
  return undefined
}

/** Whether the unauthorized request is a browser navigation that wants the login page. */
function isNavigation(req: IncomingMessage): boolean {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false
  if (req.headers['sec-fetch-dest'] === 'document') return true
  return req.headers.accept?.includes('text/html') === true
}

/** Whether an HTTP(S) Origin names the incoming request authority. */
function originMatchesHost(origin: string, host: string): boolean {
  try {
    const parsed = new URL(origin)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
    return new URL(`${parsed.protocol}//${host}`).host === parsed.host
  } catch {
    return false
  }
}

/**
 * Copy request headers onto the loopback trust surface. A browser Origin is
 * rewritten only when it names the incoming Host; foreign and opaque origins
 * stay unchanged so the upstream same-origin fence can reject them.
 */
function upstreamHeaders(req: IncomingMessage, upstreamPort: number): IncomingHttpHeaders {
  const authority = `127.0.0.1:${String(upstreamPort)}`
  const headers: IncomingHttpHeaders = { ...req.headers, host: authority }
  const origin = req.headers.origin
  const host = req.headers.host
  if (origin !== undefined && host !== undefined && originMatchesHost(origin, host)) {
    headers.origin = `http://${authority}`
  }
  return headers
}

/** Format a Set-Cookie attribute line for one minted (or cleared) session cookie. */
function setSessionCookie(secure: boolean, value: string, ttlMs: number): string {
  const base = `${AUTH_COOKIE}=${encodeURIComponent(value)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${String(Math.floor(ttlMs / 1000))}`
  // A Cloudflare edge always terminates TLS, so requests arriving through the
  // tunnel mark themselves; loopback never takes the public path.
  return secure ? `${base}; Secure` : base
}

/** The login page: fully self-contained (inline styles, no scripts, no external assets) because the whole GUI sits behind the gate. */
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
<form method="post" action="${LOGIN_PATH}" data-error="${error ? '1' : ''}">
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

/** Read and parse the form body of a login post, answering oversized or wrong-type requests in place. */
async function readForm(req: IncomingMessage, res: ServerResponse): Promise<URLSearchParams | undefined> {
  const mediaType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase()
  if (mediaType !== 'application/x-www-form-urlencoded') {
    res.writeHead(415)
    res.end()
    return undefined
  }
  const declared = req.headers['content-length']
  if (declared !== undefined && Number(declared) > MAX_LOGIN_BODY_BYTES) {
    res.writeHead(413, { connection: 'close' })
    res.end()
    req.destroy()
    return undefined
  }
  let received = 0
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    received += (chunk as Buffer).byteLength
    if (received > MAX_LOGIN_BODY_BYTES) {
      res.writeHead(413, { connection: 'close' })
      res.end()
      req.destroy()
      return undefined
    }
    chunks.push(chunk as Buffer)
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
}

/**
 * The loopback gate: everything under {@link AUTH_PREFIX} is the login
 * handshake, everything else passes the cookie check before it is proxied to
 * the upstream webserver. This server speaks plain HTTP on loopback only —
 * the public client is always cloudflared, never a browser.
 */
class PasswordGate {
  private readonly ref: string
  private readonly ttlMs: number
  private readonly upstreamPort: number

  constructor(
    private readonly ctx: Context,
    config: { passwordRef: string; sessionTtlHours: number },
    upstreamPort: number,
  ) {
    this.ref = config.passwordRef
    this.ttlMs = config.sessionTtlHours * 3600 * 1000
    this.upstreamPort = upstreamPort
  }

  /** Bind the gate on the configured loopback port (0 asks the OS for one).
   * @param gatePort - the configured port.
   * @returns the listening server and its port.
   */
  async start(gatePort: number): Promise<{ server: Server; port: number }> {
    const server = createServer((req, res) => {
      void this.handle(req, res).catch((error: unknown) => {
        /* v8 ignore next -- services throw Errors; String() guards an exotic fault */
        this.ctx.logger.warn(`auth-tunnel: gate request failed: ${error instanceof Error ? error.message : String(error)}`)
        /* v8 ignore next -- handle() rejects only before it answered, so headers are never sent */
        if (!res.headersSent) res.writeHead(500)
        res.end()
      })
    })
    server.on('upgrade', (req, socket, head) => {
      void this.handleUpgrade(req, socket, head).catch(() => {
        socket.destroy()
      })
    })
    server.listen(gatePort, '127.0.0.1')
    await once(server, 'listening')
    const address = server.address()
    /* v8 ignore next -- a listening TCP server always reports an AddressInfo */
    if (address === null || typeof address === 'string') throw new Error('auth-tunnel: gate bound to an unexpected address')
    return { server, port: address.port }
  }

  /** One accepted identity check: minted cookie against the current key. */
  private async authenticated(req: IncomingMessage): Promise<boolean> {
    const key = await sessionKey(this.ctx, this.ref)
    if (key === undefined) return false
    const presented = readCookie(req.headers.cookie, AUTH_COOKIE)
    return presented !== undefined && verifyCookie(key, presented)
  }

  /** Answer one unauthorized request: login page for navigations, terse 401 otherwise. */
  private async challenge(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (isNavigation(req)) {
      res.writeHead(302, { location: LOGIN_PATH, 'cache-control': 'no-store' })
      await new Promise<void>((resolve) => { res.end(resolve) })
      return
    }
    res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    await new Promise<void>((resolve) => { res.end('{"error":"authentication required"}', resolve) })
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    /* v8 ignore next -- node:http always sets url on server requests */
    const url = new URL(req.url ?? '/', 'http://x')
    if (url.pathname === LOGIN_PATH || url.pathname === LOGOUT_PATH) {
      await this.handleHandshake(url, req, res)
      return
    }
    if (!await this.authenticated(req)) {
      await this.challenge(req, res)
      return
    }
    this.proxy(req, res)
  }

  private async handleHandshake(url: URL, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (url.pathname === LOGIN_PATH && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(loginPage(url.searchParams.get('error') === '1'))
      return
    }
    if (url.pathname === LOGIN_PATH && req.method === 'POST') {
      const form = await readForm(req, res)
      if (form === undefined) return // response already answered (413/415)
      const key = await sessionKey(this.ctx, this.ref)
      if (key === undefined) {
        this.ctx.logger.error('auth-tunnel: the access-password credential is no longer configured')
        res.writeHead(503)
        res.end()
        return
      }
      const presented = createHash('sha256').update(form.get('password') ?? '').digest()
      if (!timingSafeEqual(presented, key)) {
        res.writeHead(303, { location: `${LOGIN_PATH}?error=1`, 'cache-control': 'no-store' })
        res.end()
        return
      }
      const secure = req.headers['x-forwarded-proto'] === 'https'
      res.writeHead(303, {
        location: '/',
        'cache-control': 'no-store',
        'set-cookie': setSessionCookie(secure, mintCookie(key, this.ttlMs), this.ttlMs),
      })
      res.end()
      return
    }
    if (url.pathname === LOGOUT_PATH && (req.method === 'GET' || req.method === 'POST')) {
      const secure = req.headers['x-forwarded-proto'] === 'https'
      res.writeHead(303, {
        location: LOGIN_PATH,
        'cache-control': 'no-store',
        'set-cookie': setSessionCookie(secure, '', 0),
      })
      res.end()
      return
    }
    res.writeHead(404)
    res.end()
  }

  /** Forward one accepted HTTP request to the loopback webserver with the Host rewritten. */
  private proxy(req: IncomingMessage, res: ServerResponse): void {
    const headers = upstreamHeaders(req, this.upstreamPort)
    delete headers.connection
    delete headers['keep-alive']
    delete headers.upgrade
    /* v8 ignore next -- node:http always sets url on server requests */
    const outgoing = httpRequest({
      host: '127.0.0.1',
      port: this.upstreamPort,
      method: req.method,
      path: req.url ?? '/',
      headers,
    }, (upstream) => {
      /* v8 ignore next -- node:http client always sets a status line */
      res.writeHead(upstream.statusCode ?? 502, upstream.headers)
      upstream.pipe(res)
    })
    outgoing.on('error', (error: Error) => {
      this.ctx.logger.warn(`auth-tunnel: upstream HTTP error: ${error.message}`)
      /* v8 ignore start -- the accepted flow only forwards request bodies, so
      an upstream error always lands before upstream response headers; the
      destroy arm exists for defense against a mid-transfer anomaly */
      if (res.headersSent) {
        res.destroy()
        return
      }
      /* v8 ignore stop */
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end('{"error":"upstream unreachable"}')
    })
    req.pipe(outgoing)
  }

  /** Forward one accepted upgrade handshake by piping the raw connection to the upstream. */
  private async handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
    if (!await this.authenticated(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n')
      socket.destroy()
      return
    }
    const upstream = netConnect(this.upstreamPort, '127.0.0.1')
    await once(upstream, 'connect')
    const headers = upstreamHeaders(req, this.upstreamPort)
    /* v8 ignore next 2 -- IncomingMessage surface entries carry no undefined values; node joins repeats */
    const lines = Object.entries(headers).flatMap(([entry, value]) =>
      value === undefined ? [] : [`${entry}: ${Array.isArray(value) ? value.join(', ') : value}`])
    /* v8 ignore next -- node:http always sets method and url on upgrade requests */
    upstream.write(`${req.method ?? 'GET'} ${req.url ?? '/'} HTTP/${req.httpVersion}\r\n${lines.join('\r\n')}\r\n\r\n`)
    if (head.length > 0) upstream.write(head)
    upstream.pipe(socket)
    socket.pipe(upstream)
    // Either half finishing tears the other down right away: waiting for
    // 'close' on both sides would deadlock (each side's FIN waits on the
    // other's).
    const drop = (): void => {
      upstream.destroy()
      socket.destroy()
    }
    upstream.once('end', drop)
    socket.once('end', drop)
    upstream.once('error', drop)
    socket.once('error', drop)
  }
}

/** Spawn one cloudflared and resolve once the tunnel is up; any failure kills the child. */
async function spawnTunnel(ctx: Context, config: InternalConfig, target: string): Promise<{ child: ChildProcess; publicUrl: string }> {
  let args: string[]
  let publicUrlHint: string | undefined
  /* The child gets a minimal environment on purpose: deployment variables that
     could steer the process (proxy settings) stay out; only what cloudflared
     needs is passed. */
  const env: NodeJS.ProcessEnv = {}
  /* v8 ignore start -- PATH/HOME/TMPDIR are present in every real process;
  the conditionals keep tests with scrubbed environments honest */
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
    if (config.gatePort === 0) {
      throw new Error('auth-tunnel: token mode requires gatePort: the named tunnel\'s dashboard ingress points at this loopback port, so it must be fixed')
    }
    const hit = await ctx.credentials.resolve(credentialRef(tokenRef))
    if (hit === undefined || hit.value === '') {
      throw new Error(`auth-tunnel: credential reference "${tokenRef}" is not configured`)
    }
    // The token travels over the environment, never argv: a process listing
    // must not expose it.
    env.TUNNEL_TOKEN = hit.value
    args = ['tunnel', 'run', '--no-autoupdate']
  }

  const child = spawn(config.executable, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
  // A bounded rolling tail of cloudflared output for diagnostics; the
  // console gets only the one URL line, not the child's chatter.
  let tail = ''
  const onData = (chunk: Buffer): void => {
    const text = chunk.toString('utf8')
    // Never accumulate beyond the line budget the failure message prints.
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
          const publicUrl = publicUrlHint
          finish(() => { resolve(publicUrl) })
        }
      }
      child.stderr.on('data', scan)
      child.stdout.on('data', scan)
    })
    const publicUrl = await ready
    return { child, publicUrl }
  } catch (error) {
    await killTree(child)
    throw error
  }
}

/** Terminate one cloudflared and await its exit: SIGTERM, with SIGKILL after the grace. */
async function killTree(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  const closed = once(child, 'close')
  child.kill('SIGTERM')
  const escalation = setTimeout(() => { child.kill('SIGKILL') }, KILL_GRACE_MS)
  await closed
  clearTimeout(escalation)
}

/** Read one mode-required key or throw a load-time misconfiguration. */
function required<TKey extends 'tokenRef' | 'publicHostname'>(config: InternalConfig, key: TKey, message: string): NonNullable<InternalConfig[TKey]> {
  const value = config[key]
  if (value === undefined) throw new Error(`auth-tunnel: ${message}`)
  return value
}

/**
 * Start the loopback password gate against the webserver, spawn cloudflared
 * against the gate, and publish the public URL to the shell and the model.
 * Activation completes only once the tunnel is up.
 * @param ctx - plugin context.
 * @param config - validated {@link Config}.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  // Activation checks the password reference before the gate opens: an
  // unconfigured credential never fronts a public URL.
  const key = await sessionKey(ctx, config.passwordRef)
  if (key === undefined) {
    throw new Error(`auth-tunnel: credential reference "${config.passwordRef}" is not configured`)
  }
  const gate = new PasswordGate(ctx, config, ctx.webServer.port)
  const { server, port } = await gate.start(config.gatePort)
  let spawned: { child: ChildProcess; publicUrl: string }
  try {
    spawned = await spawnTunnel(ctx, config, `http://127.0.0.1:${String(port)}`)
  } catch (error) {
    // A failed boot must not leave the gate listening behind no tunnel. A
    // close failure only delays teardown; the boot error stays the outcome.
    server.close()
    server.closeAllConnections()
    throw error
  }
  const { child, publicUrl } = spawned
  let disposed = false
  child.once('exit', (code, signal) => {
    // Our own teardown kill is no crash; anything else strands the URL.
    if (disposed) return
    ctx.logger.error(`auth-tunnel: cloudflared exited (code ${String(code)}, signal ${String(signal)}); the public URL ${publicUrl} is now dead. Restart dsh to bring the tunnel back.`)
  })
  ctx.effect(() => async () => {
    await new Promise<void>((resolve) => {
      server.close(() => { resolve() })
      server.closeAllConnections()
    })
  }, 'auth-tunnel: gate')
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
