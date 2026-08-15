/**
 * REAL-composition coverage: a test-only cordis.yml booted through the
 * vendored Loader mounts the webserver row and the auth-tunnel row over
 * executable cloudflared fakes, and every assertion observes a user-visible
 * surface: the gate's login handshake and cookie flow, the proxied Host
 * rewrite, upgrade pass-through with and without the cookie, the console URL
 * line, DSH_PUBLIC_URL, the model-facing prompt section, boot-failure
 * diagnostics, and cloudflared/gate teardown.
 */

import { chmod, mkdtemp, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises'
import { once } from 'node:events'
import { connect, connect as netConnect, createServer as createNetServer, type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Context, Service } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'

/** Minimal in-memory credentials service for the composition (rotate via set). */
class StubCredentials extends Service {
  constructor(ctx: Context) {
    super(ctx, 'credentials')
  }

  resolve(request: string): Promise<{ value: string; source: string } | undefined> {
    if (this.fault) return Promise.reject(new Error('credential store exploded'))
    const hit = this.values.get(request)
    return Promise.resolve(hit === undefined ? undefined : { value: hit, source: 'test' })
  }

  /** Test knob: make every resolve throw (per-request error containment). */
  fault = false

  /** Test knob: set or delete one credential. */
  set(ref: string, value: string | undefined): void {
    if (value === undefined) {
      this.values.delete(ref)
    } else {
      this.values.set(ref, value)
    }
  }

  private readonly values = new Map<string, string>()
}

/** Minimal shell-env service capturing every contributor for later assertions. */
class StubShellEnv extends Service {
  constructor(ctx: Context) {
    super(ctx, 'shellEnv')
  }

  contributors: { name: string; resolve(): Record<string, string> }[] = []

  register(contributor: { name: string; resolve(): Record<string, string> }): () => void {
    this.contributors.push(contributor)
    return () => {
      this.contributors = this.contributors.filter(entry => entry !== contributor)
    }
  }
}

/** Minimal system-prompt service capturing every section for later assertions. */
class StubSystemPrompt extends Service {
  constructor(ctx: Context) {
    super(ctx, 'systemPrompt')
  }

  sections: { name: string; text(): string }[] = []

  section(section: { name: string; text(): string }): () => void {
    this.sections.push(section)
    return () => {
      this.sections = this.sections.filter(entry => entry !== section)
    }
  }
}

interface StubbedContext {
  loaded: Context
  credentials: () => StubCredentials
  shellEnv: () => StubShellEnv
  systemPrompt: () => StubSystemPrompt
  gateBase: () => Promise<string>
}

const FIXTURES = fileURLToPath(new URL('fixtures/', import.meta.url))
const QUICK_URL = 'https://alpha-bravo-charlie.trycloudflare.com'
const FAKE_PREFIX = 'fake-cloudflared-'

let root: string | undefined
let context: Context | undefined

/** Sweep any fakes' pid/url files from earlier tests or runs. */
async function cleanFixtureMarkers(): Promise<void> {
  for (const entry of await readdir(tmpdir())) {
    if (entry.startsWith(FAKE_PREFIX)) await unlink(join(tmpdir(), entry)).catch(() => undefined)
  }
}

beforeEach(async () => {
  await cleanFixtureMarkers()
  root = await mkdtemp(join(tmpdir(), 'dsh-tunnel-loader-'))
})

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
  await cleanFixtureMarkers()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

/** Materialize one executable fake cloudflared from a fixture into the temp root. */
async function fixtureExecutable(fixture: string): Promise<string> {
  const target = join(root!, fixture)
  await writeFile(target, await readFile(join(FIXTURES, fixture)))
  await chmod(target, 0o755)
  return target
}

/** Pids of live fakes (markers name the pid; alive check keeps killed pids out). */
async function liveFixturePids(): Promise<string[]> {
  const pids: string[] = []
  for (const entry of await readdir(tmpdir())) {
    const hit = new RegExp(`^${FAKE_PREFIX}(\\d+)\\.pid$`).exec(entry)
    if (hit === null) continue
    try {
      process.kill(Number(hit[1]), 0)
      pids.push(hit[1]!)
    } catch {
      // Dead pid: the process already exited.
    }
  }
  return pids
}

/** Write a cordis.yml with webserver + stubs + the tunnel row and create the Loader child.
 * Does not await the load unless asked.
 */
interface CompositionOptions {
  /** Register no credentials stub row at all. */
  withCredentials?: boolean
  /** Make the credentials row activate after the webserver-dependent tunnel row. */
  credentialsAfterWebServer?: boolean
  /** Register no shell-env/system-prompt stub rows. */
  withShell?: boolean
  /** Seed no DSH_WEB_PASSWORD. */
  withPassword?: boolean
  /** Extra seeded credentials. */
  seeds?: Record<string, string>
  /** Skip the loader resolution wait (boot-failure tests). */
  wait?: boolean
}

async function loadComposition(tunnelConfig: Record<string, unknown>, options?: CompositionOptions): Promise<StubbedContext> {
  const configPath = join(root!, 'cordis.yml')
  const seeds: Record<string, string> = {
    ...(options?.withPassword === false ? {} : { DSH_WEB_PASSWORD: 's3kret-passw0rd' }),
    ...options?.seeds,
  }
  const credentialRows = options?.withCredentials === false ? [] : [
    "- name: '@deepseek-ai/dsh-credentials'",
    '  config:',
    `    seeds: ${JSON.stringify(seeds)}`,
  ]
  const tunnelRows = [
    "- name: '@deepseek-ai/dsh-auth-tunnel'",
    '  config:',
    ...Object.entries(tunnelConfig).map(([key, value]) => `    ${key}: ${JSON.stringify(value)}`),
  ]
  const rows: string[] = [
    "- name: '@deepseek-ai/dsh-host-webserver'",
    '  config:',
    "    host: '127.0.0.1'",
    '    port: 0',
    ...(options?.credentialsAfterWebServer === true ? [] : credentialRows),
    ...(options?.withShell === false ? [] : [
      "- name: '@deepseek-ai/dsh-shell-env'",
      "- name: '@deepseek-ai/dsh-system-prompt'",
    ]),
    ...tunnelRows,
    ...(options?.credentialsAfterWebServer === true ? credentialRows : []),
    '',
  ]
  await writeFile(configPath, rows.join('\n'))

  context = new Context()
  context.baseUrl = pathToFileURL(root!).href + '/'
  await context.plugin(Loader)
  context.loader.builtins.include = Include
  const shellEnvPlugin = (ctx2: Context): void => { void ctx2.plugin(StubShellEnv) }
  const systemPromptPlugin = (ctx2: Context): void => { void ctx2.plugin(StubSystemPrompt) }
  // Seeds must land in the service BEFORE the tunnel row evaluates its row:
  // activation reads the password reference at load, never afterwards.
  const credentialsPlugin = (ctx2: Context, config?: { seeds?: Record<string, string> }): void => {
    const service = new StubCredentials(ctx2)
    for (const [ref, value] of Object.entries(config?.seeds ?? {})) service.set(ref, value)
  }
  credentialsPlugin.inject = options?.credentialsAfterWebServer === true ? ['webServer'] : []
  const webserver = (await import('@deepseek-ai/dsh-host-webserver')).default
  const tunnel = await import('../src/index.ts')
  const modules = new Map<string, unknown>([
    ['@deepseek-ai/dsh-host-webserver', webserver],
    ['@deepseek-ai/dsh-credentials', credentialsPlugin],
    ['@deepseek-ai/dsh-shell-env', shellEnvPlugin],
    ['@deepseek-ai/dsh-system-prompt', systemPromptPlugin],
    ['@deepseek-ai/dsh-auth-tunnel', tunnel],
  ])
  context.loader.internal = {
    version: 'v2',
    async import(specifier: string) {
      if (!modules.has(specifier)) throw new Error(`unexpected Loader import: ${specifier}`)
      return modules.get(specifier)
    },
  } as unknown as NonNullable<typeof context.loader.internal>
  await context.loader.create({
    name: 'cordis:include',
    config: { path: pathToFileURL(configPath).href },
  })
  if (options?.wait !== false) await context.loader.await()
  const loaded = context
  return {
    loaded,
    credentials: () => loaded.get('credentials')! as unknown as StubCredentials,
    shellEnv: () => loaded.get('shellEnv')! as unknown as StubShellEnv,
    systemPrompt: () => loaded.get('systemPrompt')! as unknown as StubSystemPrompt,
    async gateBase(): Promise<string> {
      for (const entry of await readdir(tmpdir())) {
        const hit = new RegExp(`^${FAKE_PREFIX}\\d+\\.url$`).exec(entry)
        if (hit !== null) return (await readFile(join(tmpdir(), entry), 'utf8')).trim()
      }
      throw new Error('no fake recorded its gate target')
    },
  }
}

/** Boot one quick-mode composition with the password seeded. */
async function bootQuick(
  overrides?: Record<string, unknown>,
  options?: CompositionOptions,
): Promise<StubbedContext> {
  return loadComposition({
    sessionTtlHours: 720,
    mode: 'quick',
    executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
    startupTimeoutMs: 15_000,
    ...overrides,
  }, options)
}

/** Log in over the gate and return the minted Cookie header value. */
async function login(base: string, extraHeaders?: Record<string, string>, password = 's3kret-passw0rd'): Promise<Headers> {
  const response = await fetch(`${base}/dsh-auth-tunnel/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...extraHeaders },
    body: `password=${encodeURIComponent(password)}`,
  })
  expect(response.status).toBe(303)
  expect(response.headers.get('set-cookie')).toContain('dsh_auth_tunnel=v1.')
  return response.headers
}

/** One raw HTTP request over a socket; returns the raw response head. */
async function rawRequest(port: number, request: string[]): Promise<string> {
  const socket = connect(port, '127.0.0.1')
  await once(socket, 'connect')
  socket.write(request.join('\r\n'))
  const [data] = await once(socket, 'data') as [Buffer]
  socket.end()
  return String(data)
}

/** Wait one bounded interval in real time. */
async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms)
  })
}

describe('password gate over the loopback webserver', () => {
  it('serves the public Web App Manifest without opening other unauthenticated paths', { timeout: 60_000 }, async () => {
    const { loaded, gateBase } = await bootQuick()
    loaded.webServer.register({
      kind: 'exact', path: '/manifest.webmanifest', handler: (_req, res) => {
        res.writeHead(200, { 'content-type': 'application/manifest+json' })
        res.end('{"name":"DeepSeek Harness"}')
      },
    })
    const base = await gateBase()

    const manifest = await fetch(`${base}/manifest.webmanifest`)
    expect(manifest.status).toBe(200)
    expect(await manifest.json()).toEqual({ name: 'DeepSeek Harness' })
    expect((await fetch(`${base}/manifest.webmanifest`, { method: 'POST' })).status).toBe(401)
    expect((await fetch(`${base}/favicon.svg`)).status).toBe(401)
  })

  it('challenges navigations and APIs, serves the login dance, and proxies accepted requests', { timeout: 60_000 }, async () => {
    const { loaded, gateBase } = await bootQuick()
    let observedHost = ''
    let observedOrigin = ''
    loaded.webServer.register({
      kind: 'prefix', path: '/api', handler: (req, res) => {
        observedHost = String(req.headers.host)
        observedOrigin = String(req.headers.origin)
        res.writeHead(200, { 'content-type': 'application/json', 'x-mark': 'gate' })
        res.end('{"ok":true}')
      },
    })
    const base = await gateBase()

    // No cookie: navigations redirect to the login page; API calls get a terse 401.
    const nav = await fetch(`${base}/anything`, { redirect: 'manual', headers: { accept: 'text/html' } })
    expect(nav.status).toBe(302)
    expect(nav.headers.get('location')).toBe('/dsh-auth-tunnel/login')
    const api = await fetch(`${base}/api/probe`)
    expect(api.status).toBe(401)
    expect(await api.text()).toBe('{"error":"authentication required"}')
    const apiPost = await fetch(`${base}/api/probe`, { method: 'POST' })
    expect(apiPost.status).toBe(401)

    // GET login serves the self-contained page; a wrong password bounces with the error flag.
    const page = await fetch(`${base}/dsh-auth-tunnel/login`)
    expect(page.status).toBe(200)
    expect((await page.text()).length).toBeGreaterThan(500)
    const wrong = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=nope',
    })
    expect(wrong.status).toBe(303)
    expect(wrong.headers.get('location')).toBe('/dsh-auth-tunnel/login?error=1')

    // A correct password behind the TLS edge mints a Secure HttpOnly cookie.
    const good = await login(base, { 'x-forwarded-proto': 'https' })
    expect(good.get('location')).toBe('/')
    const cookie = good.get('set-cookie')!.split(';', 1)[0]!
    expect(good.get('set-cookie')).toContain('Secure')

    // The accepted cookie reaches the upstream, which saw the loopback
    // authority rather than the public hostname (the DNS-rebinding fence
    // keeps reading the loopback webserver's own trust surface).
    const proxied = await fetch(`${base}/api/probe`, { headers: { cookie } })
    expect(proxied.status).toBe(200)
    expect(proxied.headers.get('x-mark')).toBe('gate')
    expect(await proxied.text()).toBe('{"ok":true}')
    expect(observedHost).toMatch(/^127\.0\.0\.1:\d+$/)

    const port = Number(new URL(base).port)
    const browserApi = await rawRequest(port, [
      'GET /api/probe HTTP/1.1',
      'Host: public.example',
      'Origin: https://public.example',
      `Cookie: ${cookie}`,
      'Connection: close',
      '',
      '',
    ])
    expect(browserApi).toContain('200 OK')
    expect(observedOrigin).toBe(`http://${observedHost}`)

    // Authentication does not launder a cross-origin request: an Origin that
    // does not name the incoming Host stays foreign for the upstream fence.
    await rawRequest(port, [
      'GET /api/probe HTTP/1.1',
      'Host: public.example',
      'Origin: https://foreign.example',
      `Cookie: ${cookie}`,
      'Connection: close',
      '',
      '',
    ])
    expect(observedOrigin).toBe('https://foreign.example')

    // Foreign cookies are not trusted: wrong signature, wrong shape, wrong
    // version, and an unrelated cookie that names nothing.
    for (const bad of [
      'dsh_auth_tunnel=v1.99999999999999.AAAA',
      'dsh_auth_tunnel=v1.123',
      'dsh_auth_tunnel=v9.99999999999999.AAAA',
      'dsh_auth_tunnel=v1.abc.AAAA',
      'unrelated=1; another=2',
    ]) {
      expect((await fetch(`${base}/api/probe`, { headers: { cookie: bad } })).status).toBe(401)
    }

    // A navigation spelled with Fetch Metadata (no Accept header) still lands
    // on the login page; a form without the password field bounces with the
    // error flag, and any other login-verb is a literal 404.
    const fetchMeta = await fetch(`${base}/anything`, { redirect: 'manual', headers: { 'sec-fetch-dest': 'document' } })
    expect(fetchMeta.status).toBe(302)
    const acceptOnly = await fetch(`${base}/anything`, { redirect: 'manual', headers: { accept: 'text/html,application/xhtml+xml' } })
    expect(acceptOnly.status).toBe(302)
    const missingField = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'whatever=1',
    })
    expect(missingField.status).toBe(303)
    expect(missingField.headers.get('location')).toBe('/dsh-auth-tunnel/login?error=1')
    const wrongVerb = await fetch(`${base}/dsh-auth-tunnel/login`, { method: 'DELETE' })
    expect(wrongVerb.status).toBe(404)

    // The error banner is rendered when the dance bounces.
    const errorPage = await fetch(`${base}/dsh-auth-tunnel/login?error=1`)
    expect(await errorPage.text()).toContain('密码错误')

    // Logout clears the cookie with Max-Age=0, marks Secure behind the TLS
    // edge, and lands back on the login page; the POST verb does the same.
    const loggedOut = await fetch(`${base}/dsh-auth-tunnel/logout`, {
      redirect: 'manual',
      headers: { cookie, 'x-forwarded-proto': 'https' },
    })
    expect(loggedOut.status).toBe(303)
    expect(loggedOut.headers.get('location')).toBe('/dsh-auth-tunnel/login')
    expect(loggedOut.headers.get('set-cookie')).toContain('Max-Age=0')
    expect(loggedOut.headers.get('set-cookie')).toContain('Secure')
    const loggedOutPost = await fetch(`${base}/dsh-auth-tunnel/logout`, { method: 'POST', redirect: 'manual' })
    expect(loggedOutPost.status).toBe(303)
  })

  it('rejects cookies minted before a password rotation and accepts cookies minted after it', { timeout: 60_000 }, async () => {
    const { credentials, gateBase } = await bootQuick()
    const base = await gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    expect((await fetch(`${base}/`, { redirect: 'manual', headers: { cookie } })).status).not.toBe(302)

    credentials().set('DSH_WEB_PASSWORD', 'rotated-passw0rd')
    expect((await fetch(`${base}/`, { redirect: 'manual', headers: { cookie } })).status).toBe(401)
    const fresh = (await login(base, undefined, 'rotated-passw0rd')).get('set-cookie')!.split(';', 1)[0]!
    expect((await fetch(`${base}/`, { redirect: 'manual', headers: { cookie: fresh } })).status).not.toBe(302)
  })

  it('regenerates hop-by-hop headers on both HTTP proxy legs', { timeout: 60_000 }, async () => {
    const { loaded, gateBase } = await bootQuick()
    let observedHeaders: Record<string, string | string[] | undefined> = {}
    loaded.webServer.register({
      kind: 'exact', path: '/api/hop-by-hop', handler: (req, res) => {
        observedHeaders = { ...req.headers }
        res.writeHead(200, {
          connection: 'x-upstream-hop, keep-alive',
          'x-upstream-hop': 'private',
          'keep-alive': 'timeout=99',
          'proxy-authenticate': 'Basic realm="upstream"',
          trailer: 'x-upstream-trailer',
          'x-end-to-end': 'kept',
        })
        res.end('OK')
      },
    })
    const base = await gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const response = await rawRequest(port, [
      'GET /api/hop-by-hop HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      `Cookie: ${cookie}`,
      'Connection: x-client-hop, close',
      'X-Client-Hop: private',
      'Keep-Alive: timeout=99',
      'Proxy-Authorization: Basic private',
      'TE: trailers',
      'Trailer: x-client-trailer',
      'X-End-To-End: kept',
      '',
      '',
    ])

    expect(observedHeaders['x-client-hop']).toBeUndefined()
    expect(observedHeaders['keep-alive']).toBeUndefined()
    expect(observedHeaders['proxy-authorization']).toBeUndefined()
    expect(observedHeaders.te).toBeUndefined()
    expect(observedHeaders.trailer).toBeUndefined()
    expect(observedHeaders['x-end-to-end']).toBe('kept')
    expect(response.toLowerCase()).not.toContain('x-upstream-hop')
    expect(response.toLowerCase()).not.toContain('keep-alive: timeout=99')
    expect(response.toLowerCase()).not.toContain('proxy-authenticate')
    expect(response.toLowerCase()).not.toContain('trailer: x-upstream-trailer')
    expect(response.toLowerCase()).toContain('x-end-to-end: kept')
  })

  it('rejects expired cookies regardless of the signature', { timeout: 60_000 }, async () => {
    const { gateBase } = await bootQuick()
    const base = await gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 31 * 24 * 3600 * 1000)
    expect((await fetch(`${base}/`, { redirect: 'manual', headers: { cookie } })).status).toBe(401)
  })

  it('answers wrong content types, oversized bodies, and deleted credentials inside the login handshake', { timeout: 60_000 }, async () => {
    const { credentials, gateBase } = await bootQuick()
    const base = await gateBase()
    const port = Number(new URL(base).port)

    // 415 for a non-form login post.
    const wrongType = await fetch(`${base}/dsh-auth-tunnel/login`, { method: 'POST', body: 'x' })
    expect(wrongType.status).toBe(415)

    // 413 when the declared content-length already exceeds the budget.
    const declared = await rawRequest(port, [
      'POST /dsh-auth-tunnel/login HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Content-Type: application/x-www-form-urlencoded',
      'Content-Length: 70000',
      '',
      '',
    ])
    expect(declared.startsWith('HTTP/1.1 413')).toBe(true)

    // 413 when a streamed (chunked) body overruns the budget mid-flight.
    const socket = netConnect(port, '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'POST /dsh-auth-tunnel/login HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Content-Type: application/x-www-form-urlencoded',
      'Transfer-Encoding: chunked',
      '',
      '4100',
      'x'.repeat(0x4100),
      '0',
      '',
      '',
    ].join('\r\n'))
    const [streamedHead] = await once(socket, 'data') as [Buffer]
    socket.end()
    expect(String(streamedHead).startsWith('HTTP/1.1 413')).toBe(true)

    // A deleted password credential fails the login loudly, not silently.
    credentials().set('DSH_WEB_PASSWORD', undefined)
    const deleted = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=s3kret-passw0rd',
    })
    expect(deleted.status).toBe(503)

    // A minted cookie minted before the deletion also fails closed.
    const stale = await fetch(`${base}/api/probe`, { headers: { cookie: 'dsh_auth_tunnel=v1.99999999999999.AAAA' } })
    expect(stale.status).toBe(401)
  })
})

describe('upgrade pass-through', () => {
  it('proxies authenticated upgrades and closes both directions on client disconnect', { timeout: 60_000 }, async () => {
    const { loaded, gateBase } = await bootQuick()
    let observedHost = ''
    let observedOrigin = ''
    loaded.webServer.registerUpgrade({
      path: '/events',
      handler: (req, socket, head) => {
        observedHost = String(req.headers.host)
        observedOrigin = String(req.headers.origin)
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\n\r\n')
        if (head.length > 0) socket.write(head)
        socket.on('data', (chunk: Buffer) => { socket.write(chunk) })
      },
    })
    const base = await gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!

    const socket = connect(port, '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /events HTTP/1.1',
      'Host: public.example:443',
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      'Origin: https://public.example',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n'))
    const [head] = await once(socket, 'data') as [Buffer]
    expect(String(head)).toContain('101 Switching Protocols')
    expect(observedHost).toMatch(/^127\.0\.0\.1:\d+$/)
    expect(observedOrigin).toBe(`http://${observedHost}`)

    socket.write('hello-tunnel')
    const [echo] = await once(socket, 'data') as [Buffer]
    expect(String(echo)).toBe('hello-tunnel')
    socket.end()
    const closed = once(socket, 'close')
    await closed
  })

  it('rejects unauthenticated upgrades with a terse 401', { timeout: 60_000 }, async () => {
    const { gateBase } = await bootQuick()
    const base = await gateBase()
    const port = Number(new URL(base).port)
    const response = await rawRequest(port, [
      'GET /events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      '',
      '',
    ])
    expect(response).toContain('401 Unauthorized')
  })
})

describe('fetch-metadata navigation', () => {
  it('spells the login redirect for a bare Sec-Fetch-Dest navigation', { timeout: 60_000 }, async () => {
    const { gateBase } = await bootQuick()
    const port = Number(new URL(await gateBase()).port)
    const head = await rawRequest(port, [
      'GET /lecture HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Sec-Fetch-Dest: document',
      'Connection: close',
      '',
      '',
    ])
    expect(head).toContain('302')
    expect(head.toLowerCase()).toContain('location: /dsh-auth-tunnel/login')
  })
})

describe('containment against broken peers', () => {
  it('cancels the upstream HTTP request when the public client disconnects', { timeout: 60_000 }, async () => {
    const { loaded, gateBase } = await bootQuick()
    let markStarted!: () => void
    let markCancelled!: () => void
    const started = new Promise<void>((resolve) => { markStarted = resolve })
    const cancelled = new Promise<void>((resolve) => { markCancelled = resolve })
    loaded.webServer.register({
      kind: 'exact', path: '/api/slow', handler: (_req, res) => {
        markStarted()
        res.once('close', () => {
          if (!res.writableFinished) markCancelled()
        })
      },
    })
    const base = await gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => { /* Destroying this fixture is the tested client disconnect. */ })
    await once(socket, 'connect')
    socket.write([
      'GET /api/slow HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      `Cookie: ${cookie}`,
      'Connection: keep-alive',
      '',
      '',
    ].join('\r\n'))
    await started
    socket.destroy()
    await Promise.race([
      cancelled,
      sleep(1000).then(() => { throw new Error('upstream request survived the client disconnect') }),
    ])
  })

  it('answers 502 when the upstream refuses, keeps serving, and passes buffered head bytes through upgrades', { timeout: 60_000 }, async () => {
    const { loaded, gateBase } = await bootQuick()
    loaded.webServer.register({
      kind: 'exact', path: '/api/broken', handler: (req) => { req.socket.destroy() },
    })
    loaded.webServer.register({
      kind: 'exact', path: '/probe', handler: (_req, res) => { res.writeHead(200); res.end('ALIVE') },
    })
    let upgradeSawHead = 0
    loaded.webServer.registerUpgrade({
      path: '/events',
      handler: (_req, socket, head) => {
        upgradeSawHead = head.length
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\n\r\n')
      },
    })
    const base = await gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!

    // The aborted upstream answers the gate error surface, and the gate keeps
    // serving accepted cookies afterwards.
    const broken = await fetch(`${base}/api/broken`, { headers: { cookie } })
    expect(broken.status).toBe(502)
    expect(await broken.json()).toEqual({ error: 'upstream unreachable' })
    expect((await fetch(`${base}/probe`, { headers: { cookie } })).status).toBe(200)

    // Any bytes the client flushed together with the handshake (Buffer head)
    // are forwarded, not dropped.
    const socket = connect(port, '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /events HTTP/1.1',
      'Host: public.example:443',
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n') + 'HEADBYTES')
    const [head] = await once(socket, 'data') as [Buffer]
    expect(String(head)).toContain('101 Switching Protocols')
    socket.end()
    await once(socket, 'close')
    // Upstream saw the flushed head bytes (asserted after the pipes settled).
    await sleep(50)
    expect(upgradeSawHead).toBe('HEADBYTES'.length)
  })

  it('contains a credential-store failure inside single requests', { timeout: 60_000 }, async () => {
    const { credentials, gateBase } = await bootQuick()
    const base = await gateBase()
    const port = Number(new URL(base).port)

    // An HTTP request while the store throws: 500 for that request, gate alive.
    credentials().fault = true
    const failed = await fetch(`${base}/`)
    expect(failed.status).toBe(500)

    // An upgrade while the store throws: the socket is destroyed, gate alive.
    const socket = netConnect(port, '127.0.0.1')
    socket.on('error', () => { /* The destroyed socket is the fixture outcome. */ })
    await once(socket, 'connect')
    const closed = once(socket, 'close')
    socket.write([
      'GET /events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      '',
      '',
    ].join('\r\n'))
    await closed
    credentials().fault = false
    expect((await fetch(`${base}/dsh-auth-tunnel/login`)).status).toBe(200)
  })
})

describe('tunnel lifecycle', () => {
  it('waits for credentials that activate after the webserver', { timeout: 60_000 }, async () => {
    const { gateBase } = await bootQuick(undefined, { credentialsAfterWebServer: true })
    expect((await fetch(`${await gateBase()}/dsh-auth-tunnel/login`)).status).toBe(200)
  })

  it('prints the public URL, publishes DSH_PUBLIC_URL, and section-strings the model', { timeout: 60_000 }, async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const { shellEnv, systemPrompt } = await bootQuick()
    expect(consoleSpy.mock.calls.flat().join('\n')).toContain(`cloudflare tunnel: ${QUICK_URL}`)
    expect(shellEnv().contributors.find(entry => entry.name === 'auth-tunnel')?.resolve().DSH_PUBLIC_URL).toBe(QUICK_URL)
    const section = systemPrompt().sections.find(entry => entry.name === 'app:public-access')
    expect(section?.text()).toContain(QUICK_URL)
    expect(section?.text()).toContain('shared access password')

  })

  it('teardown kills the cloudflared child and closes the gate', { timeout: 60_000 }, async () => {
    const { gateBase } = await bootQuick()
    const base = await gateBase()
    const pidsBefore = await liveFixturePids()
    expect(pidsBefore.length).toBe(1)
    expect((await fetch(`${base}/dsh-auth-tunnel/login`)).status).toBe(200)

    await context!.fiber.dispose()
    context = undefined
    await sleep(100)
    expect(await liveFixturePids()).toEqual([])
    await expect(fetch(`${base}/dsh-auth-tunnel/login`)).rejects.toThrow()
  })

  it('escalates a stubborn cloudflared to SIGKILL after the grace', { timeout: 60_000 }, async () => {
    await bootQuick({ executable: await fixtureExecutable('fake-cloudflared-stubborn.sh') })
    expect((await liveFixturePids()).length).toBe(1)
    await context!.fiber.dispose()
    context = undefined
    await sleep(2600)
    expect(await liveFixturePids()).toEqual([])
  })

  it('logs a loud error when cloudflared dies after the tunnel came up', { timeout: 60_000 }, async () => {
    const { loaded } = await bootQuick()
    const pids = await liveFixturePids()
    expect(pids.length).toBe(1)
    const logged: string[] = []
    loaded.logger.exporter({ export(message) { logged.push(String(message.args[0])) } })
    process.kill(Number(pids[0]!), 'SIGTERM')
    // The fixture's TERM trap runs only after its current `sleep 1` returns.
    await sleep(1500)
    expect(logged.some(line => line.includes('the public URL') && line.includes(QUICK_URL))).toBe(true)
  })
})

describe('activation dependencies and boot failures', () => {
  type BootFailureOptions = { withPassword?: boolean; seeds?: Record<string, string> }
  const expectBootFailure = async (config: Record<string, unknown>, pattern: RegExp, options?: BootFailureOptions): Promise<void> => {
    const composition = await loadComposition(config, { wait: false, ...options })
    const pending = composition.loaded.loader.await() as Promise<unknown>
    await expect(pending).rejects.toThrow(pattern)
    await sleep(100)
  }

  it('stays pending when the composition offers no credentials service', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
      startupTimeoutMs: 15_000,
    }, { withCredentials: false })
    const tunnel = [...composition.loaded.loader.entries()]
      .find(entry => entry.options.name === '@deepseek-ai/dsh-auth-tunnel')
    expect(tunnel).toBeDefined()
    expect(tunnel?.fiber?.state).toBe(0)
    expect(await liveFixturePids()).toEqual([])
  })

  it('refuses to gate a public URL when the access password is unconfigured', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
      startupTimeoutMs: 15_000,
    }, /credential reference "DSH_WEB_PASSWORD" is not configured/, { withPassword: false })
    expect(await liveFixturePids()).toEqual([]) // the child never spawned
  })

  it('rejects a quick-mode row that names token-mode keys', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'quick',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
      startupTimeoutMs: 15_000,
    }, /tokenRef and publicHostname belong to token mode/)
    expect(await liveFixturePids()).toEqual([])
  })

  it('fails when the executable cannot spawn', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'quick',
      executable: '/nonexistent/cloudflared',
      startupTimeoutMs: 15_000,
    }, /failed to spawn/)
  })

  it('fails when cloudflared exits before the tunnel comes up, with tail-bounded diagnostics', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-crash.sh'),
      startupTimeoutMs: 15_000,
    }, { wait: false })
    const pending = composition.loaded.loader.await() as Promise<unknown>
    await expect(pending).rejects.toSatisfy((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error)
      return message.includes('exited before the tunnel came up')
        && message.includes('fixture fatal: cannot dial the edge')
        // 200 ERR lines of ~66 chars would be ~13k; the rolling tail keeps
        // the failure message inside one line budget plus the prefix.
        && message.length < 9_200
    })
  })

  it('fails on the startup timeout and kills the silent child', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-silent.sh'),
      startupTimeoutMs: 50,
    }, /produced no public URL/)
    await sleep(300)
    expect(await liveFixturePids()).toEqual([])
  })

  it('reports an occupied fixed gate port as a handled boot failure', { timeout: 60_000 }, async () => {
    const blocker = createNetServer()
    blocker.listen(0, '127.0.0.1')
    await once(blocker, 'listening')
    const address = blocker.address()
    if (address === null || typeof address === 'string') throw new Error('test blocker bound to an unexpected address')
    try {
      await expectBootFailure({
        mode: 'quick',
        gatePort: address.port,
        executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
        startupTimeoutMs: 15_000,
      }, new RegExp(`gate failed to bind 127\\.0\\.0\\.1:${String(address.port)}:.*EADDRINUSE`))
      expect(await liveFixturePids()).toEqual([])
    } finally {
      const closed = once(blocker, 'close')
      blocker.close()
      await closed
    }
  })

  it('rejects a scheme-prefixed public hostname before opening the gate', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'https://gui.example.com',
      gatePort: 32_313,
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, /expect string to match regexp/, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })
    expect(await liveFixturePids()).toEqual([])
  })

  it('token mode: runs the named tunnel over the env-var token against the fixed gate port', { timeout: 60_000 }, async () => {
    // Reserve one free loopback port for the gate; the dashboard ingress
    // would point at exactly this address.
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })
    expect(consoleSpy.mock.calls.flat().join('\n')).toContain('cloudflare tunnel: https://gui.example.com')
    const section = composition.systemPrompt().sections.find(entry => entry.name === 'app:public-access')
    expect(section?.text()).toContain('https://gui.example.com')
    // The gate really listens on exactly the configured fixed port.
    expect((await fetch(`http://127.0.0.1:${String(gatePort)}/dsh-auth-tunnel/login`)).status).toBe(200)
  })

  it('token mode names its missing row facts: hostname, gate port, and token', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      gatePort: 32_313,
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, /token mode requires publicHostname/, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })

    await expectBootFailure({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, /token mode requires gatePort/, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })

    await expectBootFailure({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort: 32_309,
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, /credential reference \"DSH_TUNNEL_TOKEN\" is not configured/)
  })
})

describe('bundle patch', () => {
  it('inserts the auth-tunnel row into a stock Web profile', async () => {
    const patch = await readFile(fileURLToPath(new URL('../cordis.patch.yml', import.meta.url)), 'utf8')
    expect(patch).toContain([
      '- insert:',
      '    - id: directory-picker-browse',
      "      name: '@deepseek-ai/dsh-host-directory-picker-browse'",
      '    - id: ui-directory-picker-browse',
      "      name: '@deepseek-ai/dsh-client-ui-directory-picker-browse'",
      '    - id: auth-tunnel',
      "      name: '@deepseek-ai/dsh-auth-tunnel'",
    ].join('\n'))
    expect(patch).not.toMatch(/^- id: auth-tunnel$/m)
  })
})
