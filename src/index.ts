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
 * @module dsh-auth-tunnel
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
import {
  settingsNamespace, type SettingsDescriptor, type SettingsPathOp,
} from '@deepseek-ai/dsh-settings'
// Pulls the Context augmentation typing `ctx.webServer`; no runtime import.
import type {} from '@deepseek-ai/dsh-host-webserver'
import type { ShellEnvRegistry } from '@deepseek-ai/dsh-shell-env'
import type { SystemPrompt } from '@deepseek-ai/dsh-system-prompt'

/** Which tunnel this composition runs. */
export type TunnelMode = 'quick' | 'token'

/** Plugin config: the access password, tunnel mode, the named-tunnel facts, and process tuning. */
export interface Config {
  /** Keep the settings surface loaded while deciding whether the public tunnel itself runs. */
  enabled: boolean
  /** Allow authenticated public pages to edit this plugin and persist their language choice. */
  allowRemoteSettings: boolean
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
  enabled: boolean
  allowRemoteSettings: boolean
  passwordRef: string
  sessionTtlHours: number
  mode: TunnelMode
  tokenRef?: string
  publicHostname?: string
  gatePort: number
  executable: string
  startupTimeoutMs: number
}

export const name = 'dsh-auth-tunnel'

/** Host/browser pairing key for the plugin settings card. */
export const AUTH_TUNNEL_SETTINGS_NAMESPACE = settingsNamespace('auth-tunnel')

// Public access cannot open until the persisted settings snapshot and both
// runtime dependencies are available.
export const inject = ['webServer', 'credentials', 'settings']

const PUBLIC_HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
const SESSION_TTL_MS_PER_HOUR = 3_600_000
const MAX_SESSION_TTL_HOURS = Math.floor((Number.MAX_SAFE_INTEGER - Date.now()) / SESSION_TTL_MS_PER_HOUR)
const MAX_TIMER_DELAY_MS = 2_147_483_647

export const Config: z<InternalConfig> = z.object({
  enabled: z.boolean().default(true),
  allowRemoteSettings: z.boolean().default(false),
  passwordRef: z.string().min(1).role('credential-ref').default('DSH_WEB_PASSWORD'),
  sessionTtlHours: z.number().min(0.01).max(MAX_SESSION_TTL_HOURS).default(720),
  mode: z.union(['quick', 'token']).default('quick'),
  tokenRef: z.string().min(1).role('credential-ref'),
  publicHostname: z.string().min(1).pattern(PUBLIC_HOSTNAME_PATTERN),
  gatePort: z.number().step(1).min(0).max(65535).default(0),
  executable: z.string().min(1).default('cloudflared'),
  startupTimeoutMs: z.number().step(1).min(1).max(MAX_TIMER_DELAY_MS).default(15_000),
})

/** Reject mode combinations that the field-level schema cannot express. */
export function validateConfig(config: Config): void {
  const sessionExpiry = Math.floor(Date.now() + config.sessionTtlHours * SESSION_TTL_MS_PER_HOUR)
  if (!Number.isSafeInteger(sessionExpiry)) {
    throw new Error('auth-tunnel: sessionTtlHours exceeds the verifiable expiration range')
  }
  if (!config.enabled) return
  if (config.mode !== 'token') return
  if (config.tokenRef === undefined) {
    throw new Error('auth-tunnel: token mode requires tokenRef')
  }
  if (config.publicHostname === undefined) {
    throw new Error('auth-tunnel: token mode requires publicHostname')
  }
  if (config.gatePort === 0) {
    throw new Error('auth-tunnel: token mode requires a fixed non-zero gatePort')
  }
}

/** Register the rc7 settings section and forward every live value. */
function settingsConfig(
  ctx: Context,
  entry: Config,
  onChange: (next: InternalConfig) => void,
): InternalConfig {
  const scope = ctx.settings.register(AUTH_TUNNEL_SETTINGS_NAMESPACE, Config, {
    base: entry,
    applies: 'live',
    validate: validateConfig,
  })
  ctx.effect(() => scope.watch(next => { onChange(next) }), 'auth-tunnel: settings watcher')
  return scope.get()
}

const AUTH_PREFIX = '/dsh-auth-tunnel'
const LOGIN_PATH = `${AUTH_PREFIX}/login`
const LOGOUT_PATH = `${AUTH_PREFIX}/logout`
export const AUTH_TUNNEL_STATUS_PATH = `${AUTH_PREFIX}/status`
export const AUTH_TUNNEL_REMOTE_SETTINGS_PATH = `${AUTH_PREFIX}/settings`
export const AUTH_TUNNEL_REMOTE_LOCALE_PATH = `${AUTH_PREFIX}/locale`
const PUBLIC_MANIFEST_PATH = '/manifest.webmanifest'
const AUTH_COOKIE = 'dsh_auth_tunnel'
const MAX_LOGIN_BODY_BYTES = 16 * 1024
const MAX_REMOTE_SETTINGS_BODY_BYTES = 64 * 1024
const OUTPUT_TAIL_CHARS = 8192
const KILL_GRACE_MS = 2000
const TUNNEL_ADOPTION_CHECK_MS = 25
const TUNNEL_HANDOFF_MS = 3500
const QUICK_URL_PATTERN = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])
const BLOCKED_REMOTE_CONFIGURATION_METHODS = new Set([
  'settings.openDocument',
  'settings.update',
  'settings.replace',
  'settings.mutate',
  'credentials.describe',
  'credentials.set',
  'credentials.unset',
  'llm.discoverModels',
])

/** Configuration-plane method named by one browser API request, when any. */
function remoteConfigurationMethod(url: URL): string | undefined {
  if (!url.pathname.startsWith('/api/')) return undefined
  return url.pathname.slice('/api/'.length)
}

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
  const expiry = Math.floor(Date.now() + ttlMs)
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

/** Whether this read is browser metadata whose fetch mode omits credentials. */
function isPublicManifestRequest(url: URL, req: IncomingMessage): boolean {
  return url.pathname === PUBLIC_MANIFEST_PATH && (req.method === 'GET' || req.method === 'HEAD')
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

/** Remove transport-local fields, including extension fields named by Connection. */
function withoutHopByHopHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const result = { ...headers }
  const connection = Array.isArray(headers.connection) ? headers.connection.join(',') : headers.connection
  const blocked = new Set(HOP_BY_HOP_HEADERS)
  for (const token of connection?.split(',') ?? []) {
    const name = token.trim().toLowerCase()
    if (name !== '') blocked.add(name)
  }
  for (const name of Object.keys(result)) {
    if (blocked.has(name.toLowerCase())) delete result[name]
  }
  return result
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

/** Read one bounded request body, answering oversized or wrong-type requests in place. */
async function readBody(
  req: IncomingMessage,
  res: ServerResponse,
  expectedMediaType: string,
  maxBytes: number,
): Promise<Buffer | undefined> {
  const mediaType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase()
  if (mediaType !== expectedMediaType) {
    res.writeHead(415)
    res.end()
    return undefined
  }
  const declared = req.headers['content-length']
  if (declared !== undefined && Number(declared) > maxBytes) {
    res.writeHead(413, { connection: 'close' })
    res.end()
    req.destroy()
    return undefined
  }
  let received = 0
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    received += (chunk as Buffer).byteLength
    if (received > maxBytes) {
      res.writeHead(413, { connection: 'close' })
      res.end()
      req.destroy()
      return undefined
    }
    chunks.push(chunk as Buffer)
  }
  return Buffer.concat(chunks)
}

/** Read and parse the form body of a login post. */
async function readForm(req: IncomingMessage, res: ServerResponse): Promise<URLSearchParams | undefined> {
  const body = await readBody(req, res, 'application/x-www-form-urlencoded', MAX_LOGIN_BODY_BYTES)
  return body === undefined ? undefined : new URLSearchParams(body.toString('utf8'))
}

/** Read and parse one plugin-owned JSON request. */
async function readJson(req: IncomingMessage, res: ServerResponse): Promise<unknown | undefined> {
  const body = await readBody(req, res, 'application/json', MAX_REMOTE_SETTINGS_BODY_BYTES)
  if (body === undefined) return undefined
  try {
    return JSON.parse(body.toString('utf8')) as unknown
  } catch {
    res.writeHead(400, { 'content-type': 'application/json', 'cache-control': 'no-store' })
    res.end('{"error":"invalid json"}')
    return undefined
  }
}

type RemoteSettingsField = keyof InternalConfig
type RemoteSettingsWrite =
  | { field: RemoteSettingsField; op: 'set'; value: unknown }
  | { field: RemoteSettingsField; op: 'unset' }

interface RemoteSettingsWriteRequest {
  expectedRevision: number
  writes: RemoteSettingsWrite[]
  password: string
}

const REMOTE_SETTINGS_FIELDS = new Set<string>([
  'enabled', 'allowRemoteSettings', 'passwordRef', 'sessionTtlHours', 'mode', 'tokenRef', 'publicHostname',
  'gatePort', 'executable', 'startupTimeoutMs',
])
const LOCALE_SETTINGS_NAMESPACE = settingsNamespace('locale')

function objectRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('expected an object')
  }
  return value as Record<string, unknown>
}

function parseRemoteSettingsWriteRequest(value: unknown): RemoteSettingsWriteRequest {
  const request = objectRecord(value)
  if (!Array.isArray(request.writes)) throw new TypeError('writes must be an array')
  const fields = new Set<RemoteSettingsField>()
  const writes = request.writes.map((entry): RemoteSettingsWrite => {
    const write = objectRecord(entry)
    if (typeof write.field !== 'string' || !REMOTE_SETTINGS_FIELDS.has(write.field)) {
      throw new TypeError('unknown settings field')
    }
    const field = write.field as RemoteSettingsField
    if (fields.has(field)) throw new TypeError('duplicate settings field')
    fields.add(field)
    if (write.op === 'unset') return { field, op: 'unset' }
    if (write.op === 'set' && Object.hasOwn(write, 'value')) return { field, op: 'set', value: write.value }
    throw new TypeError('invalid settings write')
  })
  const expectedRevision = request.expectedRevision
  if (typeof expectedRevision !== 'number' || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new TypeError('invalid settings revision')
  }
  if (request.password !== undefined && typeof request.password !== 'string') {
    throw new TypeError('password must be a string')
  }
  return {
    expectedRevision,
    writes,
    password: typeof request.password === 'string' ? request.password : '',
  }
}

function descriptorFor(ctx: Context, namespace: string): { descriptor: SettingsDescriptor; writable: boolean } {
  const settings = ctx.get('settings')
  if (settings === undefined) throw new Error('settings service is unavailable')
  const descriptor = settings.describe({ redactSecrets: true }).find(entry => entry.ns === namespace)
  if (descriptor === undefined) throw new Error(`settings namespace "${namespace}" is unavailable`)
  return { descriptor, writable: settings.writable }
}

function remoteSettingsDocument(ctx: Context): Record<string, unknown> {
  const { descriptor, writable } = descriptorFor(ctx, AUTH_TUNNEL_SETTINGS_NAMESPACE)
  const locale = ctx.get('settings')?.describe({ redactSecrets: true })
    .find(entry => entry.ns === LOCALE_SETTINGS_NAMESPACE)?.value
  const preference = typeof locale === 'object' && locale !== null && !Array.isArray(locale)
    ? (locale as Record<string, unknown>).preference
    : undefined
  return {
    settings: {
      value: descriptor.value,
      ...(descriptor.base === undefined ? {} : { base: descriptor.base }),
      ...(descriptor.user === undefined ? {} : { user: descriptor.user }),
      revision: descriptor.revision,
      writable,
    },
    ...(preference === 'zh' || preference === 'en' ? { locale: preference } : {}),
  }
}

function settingsNamespaceView(descriptor: SettingsDescriptor): Record<string, unknown> {
  return {
    ns: String(descriptor.ns),
    schema: descriptor.schema,
    value: descriptor.value,
    ...(descriptor.base === undefined ? {} : { base: descriptor.base }),
    ...(descriptor.user === undefined ? {} : { user: descriptor.user }),
    applies: descriptor.applies,
    secrets: (descriptor.secrets ?? []).map(secret => ({ path: [...secret.path], set: secret.set })),
    revision: descriptor.revision,
  }
}

function targetConfig(descriptor: SettingsDescriptor, writes: readonly RemoteSettingsWrite[]): InternalConfig {
  const target = { ...objectRecord(descriptor.value) }
  const base = descriptor.base === undefined ? {} : objectRecord(descriptor.base)
  for (const write of writes) {
    if (write.op === 'set') {
      target[write.field] = write.value
    } else if (Object.hasOwn(base, write.field)) {
      target[write.field] = base[write.field]
    } else {
      delete target[write.field]
    }
  }
  const parsed = Config(target as unknown as InternalConfig)
  validateConfig(parsed)
  return parsed
}

function settingsWriteSatisfied(descriptor: SettingsDescriptor, write: RemoteSettingsWrite): boolean {
  const user = descriptor.user === undefined ? {} : objectRecord(descriptor.user)
  if (write.op === 'unset') return !Object.hasOwn(user, write.field)
  return Object.hasOwn(user, write.field) && Object.is(user[write.field], write.value)
}

function changesTunnelRoute(current: InternalConfig, target: InternalConfig): boolean {
  return current.mode !== target.mode
    || current.gatePort !== target.gatePort
    || current.executable !== target.executable
    || current.tokenRef !== target.tokenRef
    || current.publicHostname !== target.publicHostname
}

function writeJson(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(value))
}

/** Resolve only after Node has finished handing the response to the socket. */
function writeJsonComplete(res: ServerResponse, status: number, value: unknown): Promise<void> {
  if (res.destroyed || res.writableEnded || res.writableFinished) return Promise.resolve()
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  return new Promise<void>((resolve) => {
    const done = (): void => {
      res.off('finish', done)
      res.off('close', done)
      resolve()
    }
    res.once('finish', done)
    res.once('close', done)
    res.end(JSON.stringify(value))
  })
}

/**
 * The loopback gate: everything under {@link AUTH_PREFIX} is the login
 * handshake, the Web App Manifest is public metadata, and everything else
 * passes the cookie check before it is proxied to the upstream webserver. This
 * server speaks plain HTTP on loopback only — the public client is always
 * cloudflared, never a browser.
 */
interface RemoteMutationFence {
  tail: Promise<void>
}

class PasswordGate {
  private auth: { passwordRef: string; ttlMs: number; allowRemoteSettings: boolean }
  private authGeneration = 0
  private readonly upgradeDrops = new Set<() => void>()

  constructor(
    private readonly ctx: Context,
    config: { passwordRef: string; sessionTtlHours: number; allowRemoteSettings: boolean },
    private readonly upstreamPort: number,
    private readonly remoteMutations: RemoteMutationFence,
  ) {
    this.auth = {
      passwordRef: config.passwordRef,
      ttlMs: config.sessionTtlHours * 3600 * 1000,
      allowRemoteSettings: config.allowRemoteSettings,
    }
    this.upstreamPort = upstreamPort
  }

  /** Atomically replace the authentication policy used by subsequent requests. */
  updateAuth(config: { passwordRef: string; sessionTtlHours: number; allowRemoteSettings: boolean }): void {
    if (config.passwordRef !== this.auth.passwordRef) this.revokeAuthenticatedUpgrades()
    this.auth = {
      passwordRef: config.passwordRef,
      ttlMs: config.sessionTtlHours * 3600 * 1000,
      allowRemoteSettings: config.allowRemoteSettings,
    }
  }

  /** Drop upgraded connections authenticated with the previous credential value. */
  revokeAuthenticatedUpgrades(): void {
    this.authGeneration += 1
    for (const drop of [...this.upgradeDrops]) drop()
  }

  /** Revoke the settings surface immediately without disturbing ordinary sessions. */
  revokeRemoteSettings(): void {
    this.auth = { ...this.auth, allowRemoteSettings: false }
  }

  /** Fence every gate that currently authenticates with a rotated credential. */
  credentialUpdated(ref: string): void {
    if (this.auth.passwordRef === ref) this.revokeAuthenticatedUpgrades()
  }

  /** Keep authenticated remote writes ordered across concurrent browser tabs. */
  private serializeRemoteMutation<T>(mutation: () => Promise<T>): Promise<T> {
    const queued = this.remoteMutations.tail.then(mutation)
    this.remoteMutations.tail = queued.then(() => undefined, () => undefined)
    return queued
  }

  /** Revalidate the current credential generation and live permission. */
  private async remoteSettingsAuthorized(req: IncomingMessage): Promise<boolean> {
    const passwordRef = this.auth.passwordRef
    const authGeneration = this.authGeneration
    const authenticated = this.auth.allowRemoteSettings
      && await this.authenticated(req)
      && this.auth.allowRemoteSettings
      && this.auth.passwordRef === passwordRef
      && this.authGeneration === authGeneration
    if (!authenticated) return false
    try {
      const { descriptor } = descriptorFor(this.ctx, AUTH_TUNNEL_SETTINGS_NAMESPACE)
      return Config(objectRecord(descriptor.value) as unknown as InternalConfig).passwordRef === passwordRef
    } catch {
      return false
    }
  }

  /** Revalidate authorization after reading a remote mutation body. */
  private async requireRemoteMutationAuthorization(req: IncomingMessage): Promise<void> {
    if (!await this.remoteSettingsAuthorized(req)) throw new Error('remote settings authorization changed')
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
    const listening = once(server, 'listening')
    try {
      server.listen(gatePort, '127.0.0.1')
      await listening
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`auth-tunnel: gate failed to bind 127.0.0.1:${String(gatePort)}: ${detail}`, { cause: error })
    }
    const address = server.address()
    /* v8 ignore next -- a listening TCP server always reports an AddressInfo */
    if (address === null || typeof address === 'string') throw new Error('auth-tunnel: gate bound to an unexpected address')
    return { server, port: address.port }
  }

  /** One accepted identity check: minted cookie against the current key. */
  private async authenticated(req: IncomingMessage): Promise<boolean> {
    const { passwordRef } = this.auth
    const key = await sessionKey(this.ctx, passwordRef)
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
    if (isPublicManifestRequest(url, req)) {
      this.proxy(req, res)
      return
    }
    if (!await this.authenticated(req)) {
      await this.challenge(req, res)
      return
    }
    if (url.pathname === AUTH_TUNNEL_REMOTE_SETTINGS_PATH || url.pathname === AUTH_TUNNEL_REMOTE_LOCALE_PATH) {
      if (!this.auth.allowRemoteSettings) {
        writeJson(res, 403, { error: 'remote settings disabled' })
        return
      }
      if (url.pathname === AUTH_TUNNEL_REMOTE_SETTINGS_PATH) await this.handleRemoteSettings(req, res)
      else await this.handleRemoteLocale(req, res)
      return
    }
    const configurationMethod = remoteConfigurationMethod(url)
    if (configurationMethod === 'settings.describe' || (configurationMethod !== undefined && BLOCKED_REMOTE_CONFIGURATION_METHODS.has(configurationMethod))) {
      if (!this.auth.allowRemoteSettings) {
        writeJson(res, 403, { error: 'remote settings disabled' })
        return
      }
      if (configurationMethod === 'settings.describe') {
        await this.handleSettingsDescribe(req, res)
        return
      }
      writeJson(res, 403, { error: 'remote configuration method unavailable' })
      return
    }
    this.proxy(req, res)
  }

  /** Serve the core plugin-directory read with only this plugin's namespace. */
  private async handleSettingsDescribe(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST', 'cache-control': 'no-store' })
      res.end()
      return
    }
    const body = await readJson(req, res)
    if (body === undefined) return
    try {
      const message = objectRecord(body)
      objectRecord(message.payload)
      if (message.type !== 'client-request' || message.method !== 'settings.describe' || typeof message.rpcId !== 'string') {
        throw new TypeError('invalid settings describe envelope')
      }
      if (!await this.remoteSettingsAuthorized(req)) {
        writeJson(res, 403, { error: 'remote settings authorization changed' })
        return
      }
      const settings = this.ctx.get('settings')
      if (settings === undefined) {
        writeJson(res, 200, {
          type: 'server-response',
          rpcId: message.rpcId,
          result: { ok: false, error: { code: 'internal', message: 'settings service unavailable', details: {} } },
        })
        return
      }
      const namespaces = settings.describe({ redactSecrets: true })
        .filter(entry => entry.ns === AUTH_TUNNEL_SETTINGS_NAMESPACE)
        .map(settingsNamespaceView)
      writeJson(res, 200, {
        type: 'server-response',
        rpcId: message.rpcId,
        result: {
          ok: true,
          value: {
            writable: settings.writable,
            hasDocument: settings.documentPath !== undefined,
            namespaces,
          },
        },
      })
    } catch {
      writeJson(res, 400, { error: 'invalid settings describe request' })
    }
  }

  /** Read or commit the authenticated plugin settings card. */
  private async handleRemoteSettings(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === 'GET') {
      if (!await this.remoteSettingsAuthorized(req)) {
        writeJson(res, 403, { error: 'remote settings authorization changed' })
        return
      }
      try {
        writeJson(res, 200, remoteSettingsDocument(this.ctx))
      } catch {
        writeJson(res, 503, { error: 'plugin settings unavailable' })
      }
      return
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'GET, POST', 'cache-control': 'no-store' })
      res.end()
      return
    }
    const body = await readJson(req, res)
    if (body === undefined) return
    try {
      const request = parseRemoteSettingsWriteRequest(body)
      await this.serializeRemoteMutation(async () => {
        try {
          const openedSettings = descriptorFor(this.ctx, AUTH_TUNNEL_SETTINGS_NAMESPACE)
          if (!openedSettings.writable) throw new Error('settings provider is read-only')
          const opened = openedSettings.descriptor
          if (request.expectedRevision !== opened.revision) {
            throw new Error('settings revision changed')
          }
          const current = Config(objectRecord(opened.value) as unknown as InternalConfig)
          const target = targetConfig(opened, request.writes)
          const password = request.password
          if (password !== '' && current.enabled && changesTunnelRoute(current, target)) {
            throw new Error('rotate the access password separately from tunnel route changes')
          }
          if (target.passwordRef === current.tokenRef || target.passwordRef === target.tokenRef) {
            throw new Error('access password credential conflicts with the tunnel token credential')
          }
          if (target.passwordRef !== current.passwordRef) {
            const targetCredential = await this.ctx.credentials.resolve(credentialRef(target.passwordRef))
            if (password === '' && targetCredential === undefined) {
              throw new Error('access password credential is not configured')
            }
            if (password !== '' && targetCredential !== undefined) {
              throw new Error('access password credential already exists')
            }
          }
          if (!current.allowRemoteSettings) throw new Error('remote settings disabled')
          await this.requireRemoteMutationAuthorization(req)
          if (request.writes.length !== 0) {
            const settings = this.ctx.get('settings')
            if (settings === undefined) throw new Error('settings service is unavailable')
            const ops: SettingsPathOp[] = request.writes.map(write => write.op === 'set'
              ? { op: 'set', path: [write.field], value: write.value }
              : { op: 'unset', path: [write.field] })
            await settings.mutate(
              AUTH_TUNNEL_SETTINGS_NAMESPACE,
              ops,
              request.expectedRevision,
            )
            const committed = descriptorFor(this.ctx, AUTH_TUNNEL_SETTINGS_NAMESPACE).descriptor
            if (request.writes.some(write => !settingsWriteSatisfied(committed, write))) {
              throw new Error('settings write was not committed')
            }
          }
          if (password !== '') {
            await this.ctx.credentials.set(credentialRef(target.passwordRef), password)
          }
          await writeJsonComplete(res, 200, remoteSettingsDocument(this.ctx))
        } catch (error) {
          this.ctx.logger.warn(`auth-tunnel: remote settings write rejected: ${error instanceof Error ? error.message : String(error)}`)
          await writeJsonComplete(res, 409, { error: 'plugin settings were not saved' })
        }
      })
    } catch (error) {
      this.ctx.logger.warn(`auth-tunnel: remote settings write rejected: ${error instanceof Error ? error.message : String(error)}`)
      writeJson(res, 409, { error: 'plugin settings were not saved' })
    }
  }

  /** Persist the public page's language through the Host locale namespace. */
  private async handleRemoteLocale(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST', 'cache-control': 'no-store' })
      res.end()
      return
    }
    const body = await readJson(req, res)
    if (body === undefined) return
    try {
      const locale = objectRecord(body).locale
      if (locale !== 'zh' && locale !== 'en') throw new TypeError('unsupported locale')
      await this.serializeRemoteMutation(async () => {
        await this.requireRemoteMutationAuthorization(req)
        const settings = this.ctx.get('settings')
        if (settings === undefined) throw new Error('settings service is unavailable')
        await settings.update(LOCALE_SETTINGS_NAMESPACE, { preference: locale })
      })
      writeJson(res, 200, { locale })
    } catch (error) {
      this.ctx.logger.warn(`auth-tunnel: remote locale write rejected: ${error instanceof Error ? error.message : String(error)}`)
      writeJson(res, 409, { error: 'language was not saved' })
    }
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
      const { passwordRef, ttlMs } = this.auth
      const key = await sessionKey(this.ctx, passwordRef)
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
        'set-cookie': setSessionCookie(secure, mintCookie(key, ttlMs), ttlMs),
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
    const headers = withoutHopByHopHeaders(upstreamHeaders(req, this.upstreamPort))
    /* v8 ignore next -- node:http always sets url on server requests */
    const outgoing = httpRequest({
      host: '127.0.0.1',
      port: this.upstreamPort,
      method: req.method,
      path: req.url ?? '/',
      headers,
    }, (upstream) => {
      /* v8 ignore next -- node:http client always sets a status line */
      res.writeHead(upstream.statusCode ?? 502, withoutHopByHopHeaders(upstream.headers))
      upstream.pipe(res)
    })
    const cancelUpstream = (): void => {
      if (!res.writableFinished) outgoing.destroy()
    }
    res.once('close', cancelUpstream)
    outgoing.once('close', () => { res.off('close', cancelUpstream) })
    outgoing.on('error', (error: Error) => {
      if (res.destroyed) return
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
    const authGeneration = this.authGeneration
    if (!await this.authenticated(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n')
      socket.destroy()
      return
    }
    if (authGeneration !== this.authGeneration) {
      socket.destroy()
      return
    }
    const upstream = netConnect(this.upstreamPort, '127.0.0.1')
    let dropped = false
    const drop = (): void => {
      if (dropped) return
      dropped = true
      this.upgradeDrops.delete(drop)
      upstream.destroy()
      socket.destroy()
    }
    this.upgradeDrops.add(drop)
    upstream.once('end', drop)
    socket.once('end', drop)
    upstream.once('close', drop)
    socket.once('close', drop)
    upstream.once('error', drop)
    socket.once('error', drop)
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
  }
}

/** Spawn one cloudflared and resolve once the tunnel is up; any failure kills the child. */
async function spawnTunnel(
  ctx: Context,
  config: InternalConfig,
  target: string,
  signal?: AbortSignal,
): Promise<{ child: ChildProcess; publicUrl: string }> {
  const cancelled = (): boolean => signal?.aborted === true
  if (cancelled()) throw new Error('auth-tunnel: tunnel startup cancelled')
  let args: string[]
  let publicUrlHint: string | undefined
  let tokenValue: string | undefined
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
    tokenValue = hit.value
    env.TUNNEL_TOKEN = tokenValue
    args = ['tunnel', '--no-autoupdate', 'run']
  }

  if (cancelled()) throw new Error('auth-tunnel: tunnel startup cancelled')
  const child = spawn(config.executable, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
  const cancel = (): void => { void killTree(child) }
  signal?.addEventListener('abort', cancel, { once: true })
  if (cancelled()) cancel()
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
          const diagnosticTail = tokenValue === undefined ? tail : tail.replaceAll(tokenValue, '[REDACTED]')
          reject(new Error(
            `auth-tunnel: cloudflared exited before the tunnel came up (code ${String(code)}, signal ${String(signal)})\n${diagnosticTail}`,
          ))
        })
      })
      const scan = (previous: string, chunk: Buffer): string => {
        const output = (previous + chunk.toString('utf8')).slice(-OUTPUT_TAIL_CHARS)
        if (config.mode === 'quick') {
          const hit = QUICK_URL_PATTERN.exec(output)
          if (hit !== null) finish(() => { resolve(hit[0]) })
        } else if (publicUrlHint !== undefined && output.includes('Registered tunnel connection')) {
          const publicUrl = publicUrlHint
          finish(() => { resolve(publicUrl) })
        }
        return output
      }
      let stderrReadinessTail = ''
      let stdoutReadinessTail = ''
      child.stderr.on('data', (chunk: Buffer) => { stderrReadinessTail = scan(stderrReadinessTail, chunk) })
      child.stdout.on('data', (chunk: Buffer) => { stdoutReadinessTail = scan(stdoutReadinessTail, chunk) })
    })
    const publicUrl = await ready
    // Let an immediate post-readiness process exit reach ChildProcess before
    // the runtime adopts and publishes the candidate.
    await new Promise<void>(resolve => { setTimeout(resolve, TUNNEL_ADOPTION_CHECK_MS) })
    if (cancelled()) throw new Error('auth-tunnel: tunnel startup cancelled')
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(
        `auth-tunnel: cloudflared exited before adoption (code ${String(child.exitCode)}, signal ${String(child.signalCode)})`,
      )
    }
    return { child, publicUrl }
  } catch (error) {
    await killTree(child)
    throw error
  } finally {
    signal?.removeEventListener('abort', cancel)
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

export type AuthTunnelRuntimePhase = 'stopped' | 'applying' | 'running' | 'error'

/** Browser-safe runtime state served by {@link AUTH_TUNNEL_STATUS_PATH}. */
export interface AuthTunnelRuntimeStatus {
  phase: AuthTunnelRuntimePhase
  running: boolean
  revision: number
  publicUrl?: string
  message?: string
}

interface ActiveTunnel {
  config: InternalConfig
  gate: PasswordGate
  server: Server
  port: number
  child: ChildProcess
  publicUrl: string
  alive: boolean
}

/** Close one gate and every accepted connection without leaving a listener behind. */
async function closeGate(server: Server): Promise<void> {
  if (!server.listening) {
    server.closeAllConnections()
    return
  }
  await new Promise<void>((resolve) => {
    server.close(() => { resolve() })
    server.closeAllConnections()
  })
}

function errorMessage(error: unknown): string {
  /* v8 ignore next -- service and process failures are Errors; String guards exotic rejections */
  return error instanceof Error ? error.message : String(error)
}

/** Own the one live gate/tunnel pair and reconcile settings changes serially. */
class AuthTunnelRuntime {
  private active: ActiveTunnel | undefined
  private desired: InternalConfig | undefined
  private debounce: ReturnType<typeof setTimeout> | undefined
  private drainTask: Promise<void> | undefined
  private disposed = false
  private readonly shutdown = new AbortController()
  private stagedStartup: AbortController | undefined
  private finishHandoff: (() => void) | undefined
  private readonly remoteMutations: RemoteMutationFence = { tail: Promise.resolve() }
  private readonly liveGates = new Set<PasswordGate>()
  private readonly tokenCredentialGenerations = new Map<string, number>()
  private appliedTokenCredentialGeneration = 0
  private configured: InternalConfig | undefined
  private revision = 0
  private status: AuthTunnelRuntimeStatus = { phase: 'stopped', running: false, revision: 0 }
  private readonly intentionalExits = new WeakSet<ChildProcess>()
  private publishedUrl: string | undefined
  private shellEnv: ShellEnvRegistry | undefined
  private shellRegistration: (() => void) | undefined
  private systemPrompt: SystemPrompt | undefined
  private promptRegistration: (() => void) | undefined

  constructor(private readonly ctx: Context) {}

  getStatus(): AuthTunnelRuntimeStatus {
    return this.status
  }

  /** Attach an optional shell registry while it is present in the composition. */
  attachShellEnv(service: ShellEnvRegistry): () => void {
    this.shellEnv = service
    this.syncShellEnv()
    return () => {
      if (this.shellEnv !== service) return
      this.shellRegistration?.()
      this.shellRegistration = undefined
      this.shellEnv = undefined
    }
  }

  /** Attach an optional prompt registry while it is present in the composition. */
  attachSystemPrompt(service: SystemPrompt): () => void {
    this.systemPrompt = service
    this.syncSystemPrompt()
    return () => {
      if (this.systemPrompt !== service) return
      this.promptRegistration?.()
      this.promptRegistration = undefined
      this.systemPrompt = undefined
    }
  }

  /** Apply the boot snapshot synchronously so startup still reports hard failures. */
  async start(config: InternalConfig): Promise<void> {
    this.configured = config
    this.drainTask = this.startInitial(config).finally(() => { this.finishDrain() })
    await this.drainTask
  }

  private async startInitial(config: InternalConfig): Promise<void> {
    if (!config.enabled) {
      this.setStatus('stopped', false)
      return
    }
    this.setStatus('applying', false)
    const tokenGeneration = this.tokenGeneration(config)
    try {
      const candidate = await this.startFull(config)
      if (this.disposed) {
        await this.stop(candidate)
        return
      }
      if (!this.adopt(candidate)) {
        await this.stop(candidate)
        throw this.exitedBeforeAdoption(candidate)
      }
      this.setStatus('running', true, candidate.publicUrl)
      this.appliedTokenCredentialGeneration = tokenGeneration
    } catch (error) {
      if (this.disposed) return
      if (this.desired !== undefined) return
      this.setStatus('error', false, undefined, errorMessage(error))
      throw error
    }
  }

  /** Coalesce scalar settings writes, then reconcile only the latest snapshot. */
  request(config: InternalConfig): void {
    if (this.disposed) return
    if (!config.enabled) {
      this.stagedStartup?.abort()
      const handoff = this.finishHandoff
      if (handoff !== undefined) {
        const finish = (): void => {
          if (this.finishHandoff === handoff) handoff()
        }
        void this.remoteMutations.tail.then(finish, finish)
      }
    }
    if (!config.allowRemoteSettings) {
      for (const gate of this.liveGates) gate.revokeRemoteSettings()
      if (this.active?.config.allowRemoteSettings === true) {
        this.active.config = { ...this.active.config, allowRemoteSettings: false }
      }
    }
    this.configured = config
    this.desired = config
    const running = this.active?.alive === true
    this.setStatus('applying', running, running ? this.active?.publicUrl : undefined)
    if (this.debounce !== undefined) clearTimeout(this.debounce)
    this.debounce = setTimeout(() => { this.beginDrain() }, 120)
  }

  /** Retry the latest desired settings after its access credential is repaired. */
  credentialUpdated(ref: string): void {
    const config = this.configured
    const configuredTokenUpdated = config?.mode === 'token' && config.tokenRef === ref
    const activeTokenUpdated = this.active?.config.mode === 'token' && this.active.config.tokenRef === ref
    const tokenUpdated = configuredTokenUpdated || activeTokenUpdated
    if (tokenUpdated) this.tokenCredentialGenerations.set(ref, (this.tokenCredentialGenerations.get(ref) ?? 0) + 1)
    for (const gate of this.liveGates) gate.credentialUpdated(ref)
    if (config !== undefined && (config.passwordRef === ref || tokenUpdated)) {
      this.request(config)
    }
  }

  /** Stop queued work and tear down the currently adopted runtime. */
  async dispose(): Promise<void> {
    if (this.disposed) return
    this.disposed = true
    this.desired = undefined
    if (this.debounce !== undefined) {
      clearTimeout(this.debounce)
      this.debounce = undefined
    }
    const active = this.active
    this.active = undefined
    this.publish(undefined)
    this.shutdown.abort()
    this.stagedStartup?.abort()
    await Promise.all([
      this.drainTask,
      active === undefined ? Promise.resolve() : this.stop(active),
    ])
  }

  private setStatus(
    phase: AuthTunnelRuntimePhase,
    running: boolean,
    publicUrl?: string,
    message?: string,
  ): void {
    this.revision += 1
    this.status = {
      phase,
      running,
      revision: this.revision,
      ...(publicUrl === undefined ? {} : { publicUrl }),
      ...(message === undefined ? {} : { message }),
    }
  }

  private beginDrain(): void {
    this.debounce = undefined
    if (this.disposed || this.drainTask !== undefined) return
    this.drainTask = this.drain().finally(() => { this.finishDrain() })
  }

  private finishDrain(): void {
    this.drainTask = undefined
    if (this.desired === undefined || this.disposed) return
    if (this.debounce !== undefined) clearTimeout(this.debounce)
    this.debounce = setTimeout(() => { this.beginDrain() }, 0)
  }

  private async drain(): Promise<void> {
    while (this.desired !== undefined && !this.disposed) {
      const next = this.desired
      this.desired = undefined
      try {
        await this.reconcile(next)
      } catch (error) {
        if (this.disposed) return
        const message = errorMessage(error)
        const running = this.active?.alive === true
        this.setStatus('error', running, running ? this.active?.publicUrl : undefined, message)
        this.ctx.logger.error(`auth-tunnel: could not apply live settings: ${message}`)
      }
    }
  }

  private async reconcile(next: InternalConfig): Promise<void> {
    validateConfig(next)
    if (!next.enabled) {
      await this.remoteMutations.tail
      const previous = this.active
      this.active = undefined
      this.publish(undefined)
      if (previous !== undefined) await this.stop(previous)
      this.setStatus('stopped', false)
      return
    }

    const tokenGeneration = this.tokenGeneration(next)
    let current = this.active
    if (current === undefined) {
      const candidate = await this.startFull(next)
      if (this.disposed) {
        await this.stop(candidate)
        return
      }
      if (!this.adopt(candidate)) {
        await this.stop(candidate)
        throw this.exitedBeforeAdoption(candidate)
      }
      this.setStatus('running', true, candidate.publicUrl)
      this.appliedTokenCredentialGeneration = tokenGeneration
      return
    }

    const activeTokenGeneration = this.tokenGeneration(current.config)
    if (current.config.mode === 'token'
      && this.appliedTokenCredentialGeneration !== activeTokenGeneration
      && (next.mode !== 'token' || next.tokenRef !== current.config.tokenRef)) {
      const refreshed = await this.refreshRetainedTokenTunnel(current, activeTokenGeneration)
      if (refreshed === undefined) return
      current = refreshed
    }

    await this.requirePassword(next.passwordRef)
    const replaceGate = current.config.gatePort !== next.gatePort
    if (replaceGate) {
      const candidate = await this.startFull(next)
      if (this.disposed) {
        await this.stop(candidate)
        return
      }
      const previous = this.active
      if (!this.adopt(candidate)) {
        await this.stop(candidate)
        throw this.exitedBeforeAdoption(candidate)
      }
      if (previous !== undefined) previous.gate.updateAuth(candidate.config)
      this.setStatus('running', true, candidate.publicUrl)
      // Keep the old public path alive long enough for its page to observe the
      // new runtime URL before the browser's current tunnel is retired.
      if (previous !== undefined) {
        await this.waitForHandoff()
        if (this.disposed) {
          await this.stop(previous)
          return
        }
        if (this.desired?.enabled === false) {
          this.active = undefined
          this.publish(undefined)
          await Promise.all([this.stop(candidate), this.stop(previous)])
          return
        }
        if (!candidate.alive) {
          const restored = this.restorePreviousAfterFailedHandoff(candidate, previous)
          await this.stop(candidate)
          if (!restored) {
            this.active = undefined
            this.publish(undefined)
            await this.stop(previous)
          }
          return
        }
        await this.stop(previous)
      }
      this.appliedTokenCredentialGeneration = tokenGeneration
      return
    }

    const replaceTunnel = !current.alive
      || current.config.mode !== next.mode
      || current.config.executable !== next.executable
      || (next.mode === 'token' && current.config.tokenRef !== next.tokenRef)
      || this.appliedTokenCredentialGeneration !== tokenGeneration
    if (replaceTunnel) {
      const spawned = await this.spawnStaged(next, `http://127.0.0.1:${String(current.port)}`)
      if (this.disposed) {
        this.intentionalExits.add(spawned.child)
        await killTree(spawned.child)
        return
      }
      const previous = this.active
      const candidate: ActiveTunnel = {
        config: next,
        gate: current.gate,
        server: current.server,
        port: current.port,
        child: spawned.child,
        publicUrl: spawned.publicUrl,
        alive: true,
      }
      if (!this.adopt(candidate)) {
        await this.stopChild(candidate)
        throw this.exitedBeforeAdoption(candidate)
      }
      candidate.gate.updateAuth(candidate.config)
      this.setStatus('running', true, candidate.publicUrl)
      if (previous !== undefined) {
        await this.waitForHandoff()
        if (this.disposed) {
          await this.stopChild(previous)
          return
        }
        if (this.desired?.enabled === false) {
          this.active = undefined
          this.publish(undefined)
          await Promise.all([this.stop(candidate), this.stopChild(previous)])
          return
        }
        if (!candidate.alive) {
          this.restorePreviousAfterFailedHandoff(candidate, previous)
          return
        }
        await this.stopChild(previous)
      }
      this.appliedTokenCredentialGeneration = tokenGeneration
      return
    }

    current.gate.updateAuth(next)
    const previousUrl = current.publicUrl
    current.config = next
    if (next.mode === 'token') {
      current.publicUrl = `https://${required(next, 'publicHostname', 'token mode requires publicHostname')}`
    }
    if (current.publicUrl !== previousUrl) console.log(`cloudflare tunnel: ${current.publicUrl}`)
    this.publish(current.publicUrl)
    this.setStatus('running', true, current.publicUrl)
  }

  private async requirePassword(ref: string): Promise<void> {
    if (await sessionKey(this.ctx, ref) === undefined) {
      throw new Error(`auth-tunnel: credential reference "${ref}" is not configured`)
    }
  }

  private tokenGeneration(config: InternalConfig): number {
    if (config.mode !== 'token' || config.tokenRef === undefined) return 0
    return this.tokenCredentialGenerations.get(config.tokenRef) ?? 0
  }

  /** Refresh the actually retained token child before retrying a different failed target. */
  private async refreshRetainedTokenTunnel(
    current: ActiveTunnel,
    tokenGeneration: number,
  ): Promise<ActiveTunnel | undefined> {
    const spawned = await this.spawnStaged(current.config, `http://127.0.0.1:${String(current.port)}`)
    if (this.disposed) {
      this.intentionalExits.add(spawned.child)
      await killTree(spawned.child)
      return undefined
    }
    const candidate: ActiveTunnel = {
      config: current.config,
      gate: current.gate,
      server: current.server,
      port: current.port,
      child: spawned.child,
      publicUrl: spawned.publicUrl,
      alive: true,
    }
    if (!this.adopt(candidate)) {
      await this.stopChild(candidate)
      throw this.exitedBeforeAdoption(candidate)
    }
    await this.waitForHandoff()
    if (this.disposed) {
      await this.stopChild(current)
      return undefined
    }
    if (this.desired?.enabled === false) {
      this.active = undefined
      this.publish(undefined)
      await Promise.all([this.stop(candidate), this.stopChild(current)])
      return undefined
    }
    if (!candidate.alive) {
      this.restorePreviousAfterFailedHandoff(candidate, current)
      await this.stopChild(candidate)
      return current
    }
    await this.stopChild(current)
    this.appliedTokenCredentialGeneration = tokenGeneration
    return candidate
  }

  private async startFull(config: InternalConfig): Promise<ActiveTunnel> {
    if (this.startupCancelled()) throw new Error('auth-tunnel: tunnel startup cancelled')
    await this.requirePassword(config.passwordRef)
    if (this.startupCancelled()) throw new Error('auth-tunnel: tunnel startup cancelled')
    const gate = new PasswordGate(this.ctx, config, this.ctx.webServer.port, this.remoteMutations)
    const { server, port } = await gate.start(config.gatePort)
    this.liveGates.add(gate)
    try {
      const spawned = await this.spawnStaged(config, `http://127.0.0.1:${String(port)}`)
      return {
        config,
        gate,
        server,
        port,
        child: spawned.child,
        publicUrl: spawned.publicUrl,
        alive: true,
      }
    } catch (error) {
      this.liveGates.delete(gate)
      await closeGate(server)
      throw error
    }
  }

  private adopt(candidate: ActiveTunnel): boolean {
    let observed = false
    const exited = (code: number | null, signal: NodeJS.Signals | null): void => {
      if (observed) return
      observed = true
      candidate.alive = false
      if (this.disposed || this.intentionalExits.has(candidate.child) || this.active !== candidate) return
      this.publish(undefined)
      const message = `auth-tunnel: cloudflared exited (code ${String(code)}, signal ${String(signal)}); the public URL ${candidate.publicUrl} is now dead. Toggle the tunnel off and on to start it again.`
      this.ctx.logger.error(message)
      this.setStatus('error', false, undefined, message)
    }
    candidate.child.once('exit', exited)
    if (candidate.child.exitCode !== null || candidate.child.signalCode !== null) {
      candidate.alive = false
    }
    if (!candidate.alive) return false
    const allowRemoteSettings = this.configured?.allowRemoteSettings ?? candidate.config.allowRemoteSettings
    if (candidate.config.allowRemoteSettings !== allowRemoteSettings) {
      candidate.config = { ...candidate.config, allowRemoteSettings }
    }
    candidate.gate.updateAuth(candidate.config)
    this.active = candidate
    console.log(`cloudflare tunnel: ${candidate.publicUrl}`)
    this.publish(candidate.publicUrl)
    return true
  }

  private exitedBeforeAdoption(candidate: ActiveTunnel): Error {
    return new Error(
      `auth-tunnel: cloudflared exited before adoption (code ${String(candidate.child.exitCode)}, signal ${String(candidate.child.signalCode)})`,
    )
  }

  private async spawnStaged(
    config: InternalConfig,
    target: string,
  ): Promise<{ child: ChildProcess; publicUrl: string }> {
    const startup = new AbortController()
    this.stagedStartup = startup
    if (this.startupCancelled()) startup.abort()
    try {
      return await spawnTunnel(this.ctx, config, target, startup.signal)
    } finally {
      if (this.stagedStartup === startup) this.stagedStartup = undefined
    }
  }

  private startupCancelled(): boolean {
    return this.disposed || this.shutdown.signal.aborted || this.desired?.enabled === false
  }

  private waitForHandoff(): Promise<void> {
    const signal = this.shutdown.signal
    if (signal.aborted) return Promise.resolve()
    return new Promise<void>((resolve) => {
      let settled = false
      const finish = (): void => {
        if (settled) return
        settled = true
        clearTimeout(timeout)
        signal.removeEventListener('abort', finish)
        if (this.finishHandoff === finish) this.finishHandoff = undefined
        resolve()
      }
      this.finishHandoff = finish
      const timeout = setTimeout(finish, TUNNEL_HANDOFF_MS)
      signal.addEventListener('abort', finish, { once: true })
      if (signal.aborted) finish()
    })
  }

  private restorePreviousAfterFailedHandoff(candidate: ActiveTunnel, previous: ActiveTunnel): boolean {
    if (candidate.alive || !previous.alive || this.disposed) return false
    const failure = this.status.message ?? 'auth-tunnel: replacement cloudflared exited during handoff.'
    previous.config = {
      ...previous.config,
      passwordRef: candidate.config.passwordRef,
      sessionTtlHours: candidate.config.sessionTtlHours,
      allowRemoteSettings: candidate.config.allowRemoteSettings,
    }
    this.active = previous
    previous.gate.updateAuth(previous.config)
    this.publish(previous.publicUrl)
    this.setStatus('error', true, previous.publicUrl, `${failure} The plugin kept the previous public URL.`)
    return true
  }

  private async stopChild(active: ActiveTunnel): Promise<void> {
    this.intentionalExits.add(active.child)
    await killTree(active.child)
  }

  private async stop(active: ActiveTunnel): Promise<void> {
    this.liveGates.delete(active.gate)
    await Promise.all([this.stopChild(active), closeGate(active.server)])
  }

  private publish(publicUrl: string | undefined): void {
    if (this.publishedUrl === publicUrl) return
    this.publishedUrl = publicUrl
    this.syncShellEnv()
    this.syncSystemPrompt()
  }

  private syncShellEnv(): void {
    this.shellRegistration?.()
    this.shellRegistration = undefined
    if (this.shellEnv === undefined || this.publishedUrl === undefined) return
    const publicUrl = this.publishedUrl
    this.shellRegistration = this.shellEnv.register({
      name: 'auth-tunnel',
      variables: { DSH_PUBLIC_URL: { description: 'Public URL of this instance, when the Cloudflare Tunnel is mounted' } },
      resolve: () => ({ DSH_PUBLIC_URL: publicUrl }),
    })
  }

  private syncSystemPrompt(): void {
    this.promptRegistration?.()
    this.promptRegistration = undefined
    if (this.systemPrompt === undefined || this.publishedUrl === undefined) return
    const publicUrl = this.publishedUrl
    this.promptRegistration = this.systemPrompt.section({
      name: 'app:public-access',
      order: -97,
      text: () => publicAccessPrompt(publicUrl),
    })
  }
}

/**
 * Install the runtime controller, settings watcher, status route, and optional
 * model-facing publications. Boot still waits for an initially enabled tunnel.
 * @param ctx - plugin context.
 * @param config - validated {@link Config}.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const runtime = new AuthTunnelRuntime(ctx)
  ctx.effect(() => async () => { await runtime.dispose() }, 'auth-tunnel: runtime')
  ctx.webServer.register({
    kind: 'exact',
    path: AUTH_TUNNEL_STATUS_PATH,
    handler: (req, res) => {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { allow: 'GET, HEAD', 'cache-control': 'no-store' })
        res.end()
        return
      }
      const body = JSON.stringify(runtime.getStatus())
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      res.end(req.method === 'HEAD' ? undefined : body)
    },
  })
  ctx.inject(['shellEnv'], (injected) => {
    injected.effect(() => runtime.attachShellEnv(injected.shellEnv), 'auth-tunnel: shell publication')
  })
  ctx.inject(['systemPrompt'], (injected) => {
    injected.effect(() => runtime.attachSystemPrompt(injected.systemPrompt), 'auth-tunnel: prompt publication')
  })
  ctx.on('credentials/updated', ref => { runtime.credentialUpdated(ref) })
  const active = settingsConfig(ctx, config, next => { runtime.request(next) })
  await runtime.start(active)
}
