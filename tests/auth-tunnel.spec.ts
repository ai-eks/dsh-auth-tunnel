/** Real Loader composition over a minimal global Web-access host. */

import { chmod, mkdtemp, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises'
import { once } from 'node:events'
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Context, Service } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'

interface AccessDecision {
  kind: 'grant' | 'respond'
  response?: Response
}

interface Authenticator {
  authorize(request: IncomingMessage): AccessDecision | Promise<AccessDecision>
}

/** Minimal credentials service with rotation and a per-request failure knob. */
class StubCredentials extends Service {
  private readonly values = new Map<string, string>()
  fault = false

  constructor(ctx: Context) {
    super(ctx, 'credentials')
  }

  resolve(request: string): Promise<{ value: string; source: string } | undefined> {
    if (this.fault) return Promise.reject(new Error('credential store exploded'))
    const hit = this.values.get(request)
    return Promise.resolve(hit === undefined ? undefined : { value: hit, source: 'test' })
  }

  set(ref: string, value: string | undefined): void {
    if (value === undefined) this.values.delete(ref)
    else this.values.set(ref, value)
  }
}

/** One-seat access service matching the core provider surface. */
class StubWebAccess extends Service {
  private authenticator: Authenticator | undefined

  constructor(ctx: Context) {
    super(ctx, 'webAccess')
  }

  registerAuthenticator(authenticator: Authenticator): () => void {
    if (this.authenticator !== undefined) throw new Error('web-access: authenticator already registered')
    this.authenticator = authenticator
    return () => {
      if (this.authenticator === authenticator) this.authenticator = undefined
    }
  }

  async authorize(request: IncomingMessage): Promise<AccessDecision | undefined> {
    return this.authenticator?.authorize(request)
  }
}

/** Serialize a Fetch Response onto node:http. */
async function sendResponse(request: IncomingMessage, response: Response, res: ServerResponse): Promise<void> {
  res.writeHead(response.status, Object.fromEntries(response.headers.entries()))
  if (request.method !== 'HEAD' && response.body !== null) {
    for await (const chunk of response.body) res.write(chunk)
  }
  res.end()
}

/** Loopback HTTP server whose global guard delegates public Host requests to StubWebAccess. */
class StubWebServer extends Service {
  private server!: Server
  private listenedPort!: number
  private readonly upgradedSockets = new Set<import('node:stream').Duplex>()

  constructor(ctx: Context) {
    super(ctx, 'webServer')
  }

  get port(): number {
    return this.listenedPort
  }

  async [Service.init](): Promise<void> {
    this.server = createServer((request, response) => {
      void this.handle(request, response).catch(() => {
        if (!response.headersSent) response.writeHead(500)
        response.end()
      })
    })
    this.server.on('upgrade', (request, socket) => {
      this.upgradedSockets.add(socket)
      socket.once('close', () => { this.upgradedSockets.delete(socket) })
      void this.handleUpgrade(request, socket).catch(() => { socket.destroy() })
    })
    await new Promise<void>((resolve) => {
      this.server.listen(0, '127.0.0.1', () => {
        this.listenedPort = (this.server.address() as { port: number }).port
        resolve()
      })
    })
    this.ctx.effect(() => async () => {
      await new Promise<void>((resolve) => {
        this.server.close(() => { resolve() })
        this.server.closeAllConnections()
        for (const socket of this.upgradedSockets) socket.destroy()
      })
    }, 'stub webserver')
  }

  private local(request: IncomingMessage): boolean {
    const host = request.headers.host ?? ''
    return host.startsWith('127.') || host.startsWith('localhost')
  }

  private async access(request: IncomingMessage): Promise<'local' | 'remote' | 'authenticated' | Response> {
    if (this.local(request)) return 'local'
    const service = this.ctx.get('webAccess') as StubWebAccess | undefined
    const decision = await service?.authorize(request)
    if (decision === undefined) return 'remote'
    if (decision.kind === 'grant') return 'authenticated'
    if (decision.response === undefined) throw new Error('respond decision is missing its response')
    return decision.response
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const access = await this.access(request)
    if (access instanceof Response) {
      await sendResponse(request, access, response)
      return
    }
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify({
      access,
      path: request.url,
      host: request.headers.host,
      origin: request.headers.origin,
    }))
  }

  private async handleUpgrade(request: IncomingMessage, socket: import('node:stream').Duplex): Promise<void> {
    const access = await this.access(request)
    if (access instanceof Response) {
      socket.end(`HTTP/1.1 ${String(access.status)} Unauthorized\r\nContent-Length: 0\r\n\r\n`)
      return
    }
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\nX-Access: ${access}\r\n\r\n`)
    socket.on('data', chunk => { socket.write(chunk) })
  }
}

/** Minimal shell-env service capturing contributors. */
class StubShellEnv extends Service {
  contributors: { name: string; resolve(): Record<string, string> }[] = []

  constructor(ctx: Context) {
    super(ctx, 'shellEnv')
  }

  register(contributor: { name: string; resolve(): Record<string, string> }): () => void {
    this.contributors.push(contributor)
    return () => { this.contributors = this.contributors.filter(entry => entry !== contributor) }
  }
}

/** Minimal system-prompt service capturing sections. */
class StubSystemPrompt extends Service {
  sections: { name: string; text(): string }[] = []

  constructor(ctx: Context) {
    super(ctx, 'systemPrompt')
  }

  section(section: { name: string; text(): string }): () => void {
    this.sections.push(section)
    return () => { this.sections = this.sections.filter(entry => entry !== section) }
  }
}

interface Composition {
  loaded: Context
  credentials: () => StubCredentials
  webAccess: () => StubWebAccess
  shellEnv: () => StubShellEnv
  systemPrompt: () => StubSystemPrompt
  targetBase: () => Promise<string>
}

interface CompositionOptions {
  withCredentials?: boolean
  withWebAccess?: boolean
  withShell?: boolean
  withPassword?: boolean
  seeds?: Record<string, string>
  wait?: boolean
}

const FIXTURES = fileURLToPath(new URL('fixtures/', import.meta.url))
const QUICK_URL = 'https://alpha-bravo-charlie.trycloudflare.com'
const PUBLIC_HOST = 'public.example'
const FAKE_PREFIX = 'fake-cloudflared-'

let root: string | undefined
let context: Context | undefined

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
  vi.restoreAllMocks()
})

async function fixtureExecutable(fixture: string): Promise<string> {
  const target = join(root!, fixture)
  await writeFile(target, await readFile(join(FIXTURES, fixture)))
  await chmod(target, 0o755)
  return target
}

async function liveFixturePids(): Promise<string[]> {
  const pids: string[] = []
  for (const entry of await readdir(tmpdir())) {
    const hit = new RegExp(`^${FAKE_PREFIX}(\\d+)\\.pid$`).exec(entry)
    if (hit === null) continue
    try {
      process.kill(Number(hit[1]), 0)
      pids.push(hit[1]!)
    } catch {
      // The process already exited.
    }
  }
  return pids
}

async function loadComposition(config: Record<string, unknown>, options?: CompositionOptions): Promise<Composition> {
  const seeds = {
    ...(options?.withPassword === false ? {} : { DSH_WEB_PASSWORD: 's3kret-passw0rd' }),
    ...options?.seeds,
  }
  const rows = [
    "- name: '@deepseek-ai/dsh-host-webserver'",
    ...(options?.withWebAccess === false ? [] : ["- name: '@deepseek-ai/dsh-host-web-access'"]),
    ...(options?.withCredentials === false ? [] : [
      "- name: '@deepseek-ai/dsh-credentials'",
      '  config:',
      `    seeds: ${JSON.stringify(seeds)}`,
    ]),
    ...(options?.withShell === false ? [] : [
      "- name: '@deepseek-ai/dsh-shell-env'",
      "- name: '@deepseek-ai/dsh-system-prompt'",
    ]),
    "- name: '@deepseek-ai/dsh-auth-tunnel'",
    '  config:',
    ...Object.entries(config).map(([key, value]) => `    ${key}: ${JSON.stringify(value)}`),
    '',
  ]
  const configPath = join(root!, 'cordis.yml')
  await writeFile(configPath, rows.join('\n'))

  context = new Context()
  context.baseUrl = pathToFileURL(root!).href + '/'
  await context.plugin(Loader)
  context.loader.builtins.include = Include
  const credentialsPlugin = (ctx: Context, input?: { seeds?: Record<string, string> }): void => {
    const service = new StubCredentials(ctx)
    for (const [ref, value] of Object.entries(input?.seeds ?? {})) service.set(ref, value)
  }
  const shellEnvPlugin = (ctx: Context): void => { void new StubShellEnv(ctx) }
  const systemPromptPlugin = (ctx: Context): void => { void new StubSystemPrompt(ctx) }
  const tunnel = await import('../src/index.ts')
  const modules = new Map<string, unknown>([
    ['@deepseek-ai/dsh-host-webserver', StubWebServer],
    ['@deepseek-ai/dsh-host-web-access', StubWebAccess],
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
    credentials: () => loaded.get('credentials') as unknown as StubCredentials,
    webAccess: () => loaded.get('webAccess') as unknown as StubWebAccess,
    shellEnv: () => loaded.get('shellEnv') as unknown as StubShellEnv,
    systemPrompt: () => loaded.get('systemPrompt') as unknown as StubSystemPrompt,
    async targetBase() {
      for (const entry of await readdir(tmpdir())) {
        if (new RegExp(`^${FAKE_PREFIX}\\d+\\.url$`).test(entry)) {
          return (await readFile(join(tmpdir(), entry), 'utf8')).trim()
        }
      }
      throw new Error('no fake recorded its WebServer target')
    },
  }
}

async function bootQuick(overrides?: Record<string, unknown>, options?: CompositionOptions): Promise<Composition> {
  return loadComposition({
    sessionTtlHours: 720,
    mode: 'quick',
    executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
    startupTimeoutMs: 15_000,
    ...overrides,
  }, options)
}

function publicFetch(base: string, path: string, init?: RequestInit): Promise<Response> {
  const target = new URL(base)
  return new Promise((resolve, reject) => {
    const headers = Object.fromEntries(new Headers(init?.headers).entries())
    const request = httpRequest({
      host: '127.0.0.1',
      port: Number(target.port),
      path,
      method: init?.method ?? 'GET',
      headers: { host: PUBLIC_HOST, ...headers },
    }, (response) => {
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      response.on('end', () => {
        const responseHeaders = new Headers()
        for (let index = 0; index < response.rawHeaders.length; index += 2) {
          responseHeaders.append(response.rawHeaders[index]!, response.rawHeaders[index + 1]!)
        }
        resolve(new Response(Buffer.concat(chunks), {
          status: response.statusCode ?? 500,
          statusText: response.statusMessage,
          headers: responseHeaders,
        }))
      })
    })
    request.on('error', reject)
    if (typeof init?.body === 'string') request.end(init.body)
    else request.end()
  })
}

async function login(base: string, password = 's3kret-passw0rd'): Promise<Headers> {
  const response = await publicFetch(base, '/dsh-auth-tunnel/login', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-proto': 'https' },
    body: `password=${encodeURIComponent(password)}`,
  })
  expect(response.status).toBe(303)
  expect(response.headers.get('set-cookie')).toContain('dsh_auth_tunnel=v1.')
  return response.headers
}

async function rawRequest(port: number, lines: string[]): Promise<string> {
  const socket = connect(port, '127.0.0.1')
  await once(socket, 'connect')
  socket.write(lines.join('\r\n'))
  const [data] = await once(socket, 'data') as [Buffer]
  socket.end()
  return String(data)
}

async function sleep(ms: number): Promise<void> {
  await new Promise<void>(resolve => setTimeout(resolve, ms))
}

describe('global password authentication', () => {
  it('protects metadata and routes registered by any plugin while preserving direct loopback use', { timeout: 60_000 }, async () => {
    const { targetBase } = await bootQuick()
    const base = await targetBase()
    const target = new URL(base)

    expect((await publicFetch(base, '/manifest.webmanifest')).status).toBe(401)
    expect((await publicFetch(base, '/future-plugin/route')).status).toBe(401)
    const local = await fetch(`${base}/future-plugin/route`)
    expect((await local.json() as { access: string }).access).toBe('local')

    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const manifest = await publicFetch(base, '/manifest.webmanifest', { headers: { cookie } })
    expect(manifest.status).toBe(200)
    expect(await manifest.json()).toMatchObject({ access: 'authenticated', host: PUBLIC_HOST })
    expect(base).toBe(`http://127.0.0.1:${target.port}`)
  })

  it('serves the login dance, preserves public request facts, rotates sessions, and logs out', { timeout: 60_000 }, async () => {
    const { credentials, targetBase } = await bootQuick()
    const base = await targetBase()

    const navigation = await publicFetch(base, '/anything', {
      redirect: 'manual', headers: { accept: 'text/html' },
    })
    expect(navigation.status).toBe(302)
    expect(navigation.headers.get('location')).toBe('/dsh-auth-tunnel/login')
    expect(await (await publicFetch(base, '/api/probe')).text()).toBe('{"error":"authentication required"}')

    const page = await publicFetch(base, '/dsh-auth-tunnel/login')
    expect(await page.text()).toContain('访问密码')
    const wrong = await publicFetch(base, '/dsh-auth-tunnel/login', {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=nope',
    })
    expect(wrong.headers.get('location')).toBe('/dsh-auth-tunnel/login?error=1')

    const good = await login(base)
    const cookie = good.get('set-cookie')!.split(';', 1)[0]!
    expect(good.get('set-cookie')).toContain('HttpOnly')
    expect(good.get('set-cookie')).toContain('SameSite=Strict')
    expect(good.get('set-cookie')).toContain('Secure')
    const accepted = await publicFetch(base, '/api/probe', {
      headers: { cookie, origin: `https://${PUBLIC_HOST}` },
    })
    expect(await accepted.json()).toEqual({
      access: 'authenticated', path: '/api/probe', host: PUBLIC_HOST, origin: `https://${PUBLIC_HOST}`,
    })

    credentials().set('DSH_WEB_PASSWORD', 'rotated')
    expect((await publicFetch(base, '/api/probe', { headers: { cookie } })).status).toBe(401)
    const rotated = (await login(base, 'rotated')).get('set-cookie')!.split(';', 1)[0]!
    const logout = await publicFetch(base, '/dsh-auth-tunnel/logout', {
      redirect: 'manual', headers: { cookie: rotated, 'x-forwarded-proto': 'https' },
    })
    expect(logout.status).toBe(303)
    expect(logout.headers.get('location')).toBe('/dsh-auth-tunnel/login')
    expect(logout.headers.get('set-cookie')).toContain('Max-Age=0')
  })

  it('bounds login bodies, validates content type, and fails closed when the credential disappears', { timeout: 60_000 }, async () => {
    const { credentials, targetBase } = await bootQuick()
    const base = await targetBase()
    expect((await publicFetch(base, '/dsh-auth-tunnel/login', { method: 'POST' })).status).toBe(415)
    expect((await publicFetch(base, '/dsh-auth-tunnel/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `password=${'x'.repeat(20_000)}`,
    })).status).toBe(413)
    credentials().set('DSH_WEB_PASSWORD', undefined)
    expect((await publicFetch(base, '/dsh-auth-tunnel/login', {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=s3kret-passw0rd',
    })).status).toBe(503)
  })

  it('authenticates upgrades through the same cookie without proxying the socket', { timeout: 60_000 }, async () => {
    const { targetBase } = await bootQuick()
    const base = await targetBase()
    const port = Number(new URL(base).port)
    const denied = await rawRequest(port, [
      'GET /events HTTP/1.1', `Host: ${PUBLIC_HOST}`, 'Connection: Upgrade', 'Upgrade: dsh-echo', '', '',
    ])
    expect(denied).toContain('401 Unauthorized')

    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const socket = connect(port, '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /events HTTP/1.1',
      `Host: ${PUBLIC_HOST}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n'))
    const [head] = await once(socket, 'data') as [Buffer]
    expect(String(head)).toContain('101 Switching Protocols')
    expect(String(head)).toContain('X-Access: authenticated')
    socket.write('hello')
    const [echo] = await once(socket, 'data') as [Buffer]
    expect(String(echo)).toBe('hello')
    socket.destroy()
  })

  it('contains credential-store failures to the exact HTTP or upgrade request', { timeout: 60_000 }, async () => {
    const { credentials, targetBase } = await bootQuick()
    const base = await targetBase()
    const port = Number(new URL(base).port)
    credentials().fault = true
    expect((await publicFetch(base, '/')).status).toBe(500)
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    const closed = once(socket, 'close')
    socket.write(['GET /events HTTP/1.1', `Host: ${PUBLIC_HOST}`, 'Connection: Upgrade', 'Upgrade: dsh', '', ''].join('\r\n'))
    await closed
    credentials().fault = false
    expect((await publicFetch(base, '/dsh-auth-tunnel/login')).status).toBe(200)
  })
})

describe('tunnel lifecycle', () => {
  it('publishes the URL to the console, shell, and model', { timeout: 60_000 }, async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const { shellEnv, systemPrompt } = await bootQuick()
    expect(consoleSpy.mock.calls.flat().join('\n')).toContain(`cloudflare tunnel: ${QUICK_URL}`)
    expect(shellEnv().contributors.find(entry => entry.name === 'auth-tunnel')?.resolve().DSH_PUBLIC_URL).toBe(QUICK_URL)
    expect(systemPrompt().sections.find(entry => entry.name === 'app:public-access')?.text()).toContain(QUICK_URL)
  })

  it('teardown kills cloudflared and releases authentication without closing the WebServer', { timeout: 60_000 }, async () => {
    const { loaded, targetBase } = await bootQuick()
    const base = await targetBase()
    expect((await liveFixturePids()).length).toBe(1)
    const entry = [...loaded.loader.entries()].find(item => item.options.name === '@deepseek-ai/dsh-auth-tunnel')!
    await entry.fiber!.dispose()
    await sleep(100)
    expect(await liveFixturePids()).toEqual([])
    const publicAfter = await publicFetch(base, '/after-dispose')
    expect((await publicAfter.json() as { access: string }).access).toBe('remote')
  })

  it('escalates a stubborn cloudflared and reports unexpected exits', { timeout: 60_000 }, async () => {
    await bootQuick({ executable: await fixtureExecutable('fake-cloudflared-stubborn.sh') })
    await context!.fiber.dispose()
    context = undefined
    await sleep(2600)
    expect(await liveFixturePids()).toEqual([])

    const composition = await bootQuick()
    const pids = await liveFixturePids()
    const logged: string[] = []
    composition.loaded.logger.exporter({ export(message) { logged.push(String(message.args[0])) } })
    process.kill(Number(pids[0]!), 'SIGTERM')
    await sleep(1500)
    expect(logged.some(line => line.includes(QUICK_URL) && line.includes('now dead'))).toBe(true)
  })
})

describe('activation dependencies and failures', () => {
  async function expectBootFailure(
    config: Record<string, unknown>,
    pattern: RegExp,
    options?: Pick<CompositionOptions, 'withPassword' | 'seeds'>,
  ): Promise<void> {
    const composition = await loadComposition(config, { wait: false, ...options })
    await expect(composition.loaded.loader.await()).rejects.toThrow(pattern)
    await sleep(100)
  }

  it.each([
    ['credentials', { withCredentials: false }],
    ['webAccess', { withWebAccess: false }],
  ] as const)('stays pending without the %s service', { timeout: 60_000 }, async (_name, options) => {
    const composition = await bootQuick(undefined, options)
    const tunnel = [...composition.loaded.loader.entries()]
      .find(entry => entry.options.name === '@deepseek-ai/dsh-auth-tunnel')
    expect(tunnel?.fiber?.state).toBe(0)
    expect(await liveFixturePids()).toEqual([])
  })

  it('rejects missing password and contradictory quick-mode keys before leaving a child', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'quick', executable: await fixtureExecutable('fake-cloudflared-quick.sh'), startupTimeoutMs: 15_000,
    }, /credential reference "DSH_WEB_PASSWORD" is not configured/, { withPassword: false })
    await expectBootFailure({
      mode: 'quick', tokenRef: 'DSH_TUNNEL_TOKEN', executable: await fixtureExecutable('fake-cloudflared-quick.sh'), startupTimeoutMs: 15_000,
    }, /tokenRef and publicHostname belong to token mode/)
    expect(await liveFixturePids()).toEqual([])
  })

  it('reports spawn, early-exit, and timeout failures and releases the authenticator', { timeout: 60_000 }, async () => {
    await expectBootFailure({ mode: 'quick', executable: '/nonexistent/cloudflared', startupTimeoutMs: 15_000 }, /failed to spawn/)
    await expectBootFailure({
      mode: 'quick', executable: await fixtureExecutable('fake-cloudflared-crash.sh'), startupTimeoutMs: 15_000,
    }, /exited before the tunnel came up.*fixture fatal/s)
    await expectBootFailure({
      mode: 'quick', executable: await fixtureExecutable('fake-cloudflared-silent.sh'), startupTimeoutMs: 50,
    }, /produced no public URL/)
    await sleep(300)
    expect(await liveFixturePids()).toEqual([])
  })

  it('runs token mode without a second origin port and validates its named-tunnel facts', { timeout: 60_000 }, async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })
    expect(consoleSpy.mock.calls.flat().join('\n')).toContain('cloudflare tunnel: https://gui.example.com')
    expect(composition.systemPrompt().sections.find(entry => entry.name === 'app:public-access')?.text())
      .toContain('https://gui.example.com')

    await expectBootFailure({
      mode: 'token', tokenRef: 'DSH_TUNNEL_TOKEN', executable: await fixtureExecutable('fake-cloudflared-token.sh'), startupTimeoutMs: 15_000,
    }, /token mode requires publicHostname/, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })
    await expectBootFailure({
      mode: 'token', tokenRef: 'DSH_TUNNEL_TOKEN', publicHostname: 'gui.example.com', executable: await fixtureExecutable('fake-cloudflared-token.sh'), startupTimeoutMs: 15_000,
    }, /credential reference "DSH_TUNNEL_TOKEN" is not configured/)
  })
})
