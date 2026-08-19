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
import { ServerResponse } from 'node:http'
import { connect, connect as netConnect, createServer as createNetServer, type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Context, Service } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { SettingsProvider, settingsNamespace, type SettingsNamespace } from '@deepseek-ai/dsh-settings'
import z from '@deepseek-ai/schemastery'
import { Config } from '../src/index.ts'

/** Minimal in-memory credentials service for the composition (rotate via set). */
class StubCredentials extends Service {
  constructor(ctx: Context) {
    super(ctx, 'credentials')
  }

  async resolve(request: string): Promise<{ value: string; source: string } | undefined> {
    this.resolveStarted?.(request)
    if (this.resolveDelayMs > 0) {
      await new Promise<void>(resolve => { setTimeout(resolve, this.resolveDelayMs) })
    }
    if (this.resolveBarrier !== undefined
      && (this.resolveBarrierRef === undefined || this.resolveBarrierRef === request)) {
      await this.resolveBarrier
    }
    if (this.fault) return Promise.reject(new Error('credential store exploded'))
    const hit = this.values.get(request)
    this.afterResolve?.(request)
    return hit === undefined ? undefined : { value: hit, source: 'test' }
  }

  /** Test knob: make every resolve throw (per-request error containment). */
  fault = false

  /** Test knob: reject the next credential write before it changes storage. */
  failNextSet = false

  /** Test knob: hold a credential write after it enters the commit phase. */
  setBarrier: Promise<void> | undefined

  /** Test knob: observe a credential write before its barrier. */
  setStarted: ((ref: string) => void) | undefined

  /** Test knob: hold credential resolution before startup creates a controller. */
  resolveDelayMs = 0

  /** Test knob: release concurrent credential resolutions together. */
  resolveBarrier: Promise<void> | undefined

  /** Test knob: limit the credential barrier to one reference. */
  resolveBarrierRef: string | undefined

  /** Test knob: observe a credential lookup before a barrier holds it. */
  resolveStarted: ((ref: string) => void) | undefined

  /** Test knob: mutate credential state after reading a value but before returning it. */
  afterResolve: ((ref: string) => void) | undefined

  /** Test knob: set or delete one credential. */
  async set(ref: string, value: string | undefined): Promise<void> {
    if (this.failNextSet) {
      this.failNextSet = false
      throw new Error('credential persistence failed')
    }
    this.setStarted?.(ref)
    if (this.setBarrier !== undefined) await this.setBarrier
    if (value === undefined) {
      this.values.delete(ref)
    } else {
      this.values.set(ref, value)
    }
    this.ctx.emit('credentials/updated', credentialRef(ref))
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

/** Writable in-memory settings provider exercising the real rc7 service definition. */
class StubSettings extends SettingsProvider {
  writable = true
  failNextPersist = false
  persistBarrier: Promise<void> | undefined
  persistStarted: (() => void) | undefined
  private document: Record<string, unknown>

  constructor(ctx: Context, config?: { document?: Record<string, unknown> }) {
    super(ctx)
    this.document = structuredClone(config?.document ?? {})
  }

  protected load(): Promise<Record<string, unknown>> {
    return Promise.resolve(structuredClone(this.document))
  }

  protected async persist(ns: SettingsNamespace, section: Record<string, unknown>): Promise<void> {
    if (this.failNextPersist) {
      this.failNextPersist = false
      throw new Error('settings persistence failed')
    }
    this.persistStarted?.()
    if (this.persistBarrier !== undefined) await this.persistBarrier
    this.document = { ...this.document, [ns]: structuredClone(section) }
  }
}

interface StubbedContext {
  loaded: Context
  credentials: () => StubCredentials
  settings: () => StubSettings
  shellEnv: () => StubShellEnv
  systemPrompt: () => StubSystemPrompt
  gateBase: () => Promise<string>
  runtimeStatus: () => Promise<RuntimeStatus>
}

interface RuntimeStatus {
  phase: 'stopped' | 'applying' | 'running' | 'error'
  running: boolean
  revision: number
  publicUrl?: string
  message?: string
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
  /** Register no settings provider row. */
  withSettings?: boolean
  /** Make the settings row activate after the tunnel row. */
  settingsAfterTunnel?: boolean
  /** Initial raw settings document. */
  settingsDocument?: Record<string, unknown>
  /** Seed no DSH_WEB_PASSWORD. */
  withPassword?: boolean
  /** Extra seeded credentials. */
  seeds?: Record<string, string>
  /** Delay every credential resolution. */
  credentialResolveDelayMs?: number
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
    "- name: 'dsh-auth-tunnel'",
    '  config:',
    ...Object.entries(tunnelConfig).map(([key, value]) => `    ${key}: ${JSON.stringify(value)}`),
  ]
  const settingsRows = options?.withSettings === false ? [] : [
    "- name: '@deepseek-ai/dsh-settings'",
    '  config:',
    `    document: ${JSON.stringify(options?.settingsDocument ?? {})}`,
  ]
  const rows: string[] = [
    "- name: '@deepseek-ai/dsh-host-webserver'",
    '  config:',
    "    host: '127.0.0.1'",
    '    port: 0',
    ...(options?.settingsAfterTunnel === true ? [] : settingsRows),
    ...(options?.credentialsAfterWebServer === true ? [] : credentialRows),
    ...(options?.withShell === false ? [] : [
      "- name: '@deepseek-ai/dsh-shell-env'",
      "- name: '@deepseek-ai/dsh-system-prompt'",
    ]),
    ...tunnelRows,
    ...(options?.settingsAfterTunnel === true ? settingsRows : []),
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
    service.resolveDelayMs = options?.credentialResolveDelayMs ?? 0
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
    ['@deepseek-ai/dsh-settings', StubSettings],
    ['dsh-auth-tunnel', tunnel],
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
    settings: () => loaded.get('settings')! as unknown as StubSettings,
    shellEnv: () => loaded.get('shellEnv')! as unknown as StubShellEnv,
    systemPrompt: () => loaded.get('systemPrompt')! as unknown as StubSystemPrompt,
    async gateBase(): Promise<string> {
      for (const pid of await liveFixturePids()) {
        const path = join(tmpdir(), `${FAKE_PREFIX}${pid}.url`)
        try {
          return (await readFile(path, 'utf8')).trim()
        } catch {
          // Token fixtures do not record a --url target.
        }
      }
      throw new Error('no fake recorded its gate target')
    },
    async runtimeStatus(): Promise<RuntimeStatus> {
      const response = await fetch(`http://127.0.0.1:${String(loaded.webServer.port)}/dsh-auth-tunnel/status`)
      expect(response.status).toBe(200)
      return response.json() as Promise<RuntimeStatus>
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

/** Start an authenticated JSON request but hold its body incomplete until finish(). */
async function beginJsonPost(
  port: number,
  path: string,
  cookie: string,
  body: Record<string, unknown>,
): Promise<() => Promise<string>> {
  const serialized = JSON.stringify(body)
  const socket = connect(port, '127.0.0.1')
  socket.on('error', () => {})
  await once(socket, 'connect')
  const response = once(socket, 'data') as Promise<[Buffer]>
  socket.write([
    `POST ${path} HTTP/1.1`,
    `Host: 127.0.0.1:${String(port)}`,
    'Content-Type: application/json',
    `Content-Length: ${String(Buffer.byteLength(serialized))}`,
    `Cookie: ${cookie}`,
    '',
    serialized.slice(0, 1),
  ].join('\r\n'))
  return async () => {
    socket.write(serialized.slice(1))
    const [data] = await response
    socket.end()
    return String(data)
  }
}

/** Wait one bounded interval in real time. */
async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms)
  })
}

/** Poll one runtime state transition with a bounded real-time deadline. */
async function waitForStatus(
  composition: StubbedContext,
  predicate: (status: RuntimeStatus) => boolean,
  timeoutMs = 5000,
): Promise<RuntimeStatus> {
  const deadline = Date.now() + timeoutMs
  let latest = await composition.runtimeStatus()
  while (!predicate(latest)) {
    if (Date.now() >= deadline) throw new Error(`runtime status did not converge: ${JSON.stringify(latest)}`)
    await sleep(25)
    latest = await composition.runtimeStatus()
  }
  return latest
}

describe('password gate over the loopback webserver', () => {
  it('exposes only plugin-owned remote settings after the live switch is enabled', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    let settingsRequests = 0
    composition.loaded.webServer.register({
      kind: 'exact', path: '/api/settings.describe', handler: (_req, res) => {
        settingsRequests += 1
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end('{"ok":true}')
      },
    })
    composition.settings().register(settingsNamespace('locale'), z.object({
      preference: z.union(['zh', 'en']).required(false),
    }))
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const rpc = (method: string, payload: object = {}): RequestInit => ({
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'client-request', rpcId: `rpc-${method}`, method, payload }),
    })

    const denied = await fetch(`${base}/api/settings.describe`, rpc('settings.describe'))
    expect(denied.status).toBe(403)
    expect(await denied.json()).toEqual({ error: 'remote settings disabled' })
    expect(settingsRequests).toBe(0)
    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(403)

    const beforeEnable = await composition.runtimeStatus()
    await composition.settings().update(settingsNamespace('auth-tunnel'), { allowRemoteSettings: true })
    await waitForStatus(composition, status => status.revision > beforeEnable.revision && status.phase === 'running')

    const allowed = await fetch(`${base}/api/settings.describe`, rpc('settings.describe'))
    expect(allowed.status).toBe(200)
    expect(settingsRequests).toBe(0)
    expect(await allowed.json()).toMatchObject({
      type: 'server-response',
      rpcId: 'rpc-settings.describe',
      result: { ok: true, value: { namespaces: [{ ns: 'auth-tunnel' }] } },
    })
    expect((await fetch(`${base}/api/settings.mutate`, rpc('settings.mutate', {
      ns: 'auth-tunnel', ops: [],
    }))).status).toBe(403)

    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number; value: { allowRemoteSettings: boolean; sessionTtlHours: number } }
    }
    expect(opened.settings.value.allowRemoteSettings).toBe(true)
    const updated = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: '',
      }),
    })
    expect(updated.status).toBe(200)
    const committed = await updated.json() as {
      settings: { revision: number; value: { sessionTtlHours: number } }
    }
    expect(committed.settings.value.sessionTtlHours).toBe(24)
    expect(composition.settings().get(settingsNamespace('auth-tunnel'))).toMatchObject({ sessionTtlHours: 24 })

    const locale = await fetch(`${base}/dsh-auth-tunnel/locale`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ locale: 'en' }),
    })
    expect(locale.status).toBe(200)
    expect(composition.settings().get(settingsNamespace('locale'))).toEqual({ preference: 'en' })

    const beforeDisable = await composition.runtimeStatus()
    const disabled = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: committed.settings.revision,
        writes: [{ field: 'allowRemoteSettings', op: 'set', value: false }],
        password: '',
      }),
    })
    expect(disabled.status).toBe(200)
    expect(await disabled.json()).toMatchObject({ settings: { value: { allowRemoteSettings: false } } })
    await waitForStatus(composition, status => status.revision > beforeDisable.revision && status.phase === 'running')
    expect((await fetch(`${base}/api/settings.describe`, rpc('settings.describe'))).status).toBe(403)
    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(403)
  })

  it('rejects a pending settings descriptor after remote settings are revoked', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const before = await composition.runtimeStatus()
    const finish = await beginJsonPost(port, '/api/settings.describe', cookie, {
      type: 'client-request',
      rpcId: 'pending-settings-describe',
      method: 'settings.describe',
      payload: {},
    })
    await sleep(50)

    await composition.settings().update(settingsNamespace('auth-tunnel'), { allowRemoteSettings: false })
    await waitForStatus(composition, status => status.revision > before.revision)

    const response = await finish()
    expect(response).toContain(' 403 ')
    expect(response).not.toContain('auth-tunnel')
  })

  it('rotates the long-lived access password verbatim through the plugin endpoint without echoing it', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ expectedRevision: opened.settings.revision, writes: [], password: '  replacement-password  ' }),
    })
    expect(response.status).toBe(200)
    expect(await response.text()).not.toContain('replacement-password')
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD')).toMatchObject({ value: '  replacement-password  ' })
    expect((await login(base, undefined, '  replacement-password  ')).get('set-cookie')).toContain('dsh_auth_tunnel=')
  })

  it('serializes concurrent password-only rotations from the same session', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    const request = (password: string) => ({
      expectedRevision: opened.settings.revision,
      writes: [],
      password,
    })
    const finishFirst = await beginJsonPost(port, '/dsh-auth-tunnel/settings', cookie, request('first-password'))
    const finishSecond = await beginJsonPost(port, '/dsh-auth-tunnel/settings', cookie, request('second-password'))
    await sleep(50)

    const responses = await Promise.all([finishFirst(), finishSecond()])

    expect(responses.filter(response => response.includes(' 200 '))).toHaveLength(1)
    expect(responses.filter(response => response.includes(' 409 '))).toHaveLength(1)
  })

  it('rejects a pending remote save after remote settings are revoked', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const before = await composition.runtimeStatus()
    const finish = await beginJsonPost(port, '/dsh-auth-tunnel/settings', cookie, {
      writes: [{ field: 'allowRemoteSettings', op: 'set', value: true }],
      password: '',
    })
    await sleep(50)

    await composition.settings().update(settingsNamespace('auth-tunnel'), { allowRemoteSettings: false })
    await waitForStatus(composition, status => status.revision > before.revision)
    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(403)

    expect(await finish()).toContain(' 409 ')
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).allowRemoteSettings).toBe(false)
  })

  it('requires a revision fence while the live gate still uses the previous password reference', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const finish = await beginJsonPost(port, '/dsh-auth-tunnel/settings', cookie, {
      writes: [],
      password: 'overwritten-password',
    })
    await sleep(50)

    await composition.settings().update(settingsNamespace('auth-tunnel'), { passwordRef: 'ALT_WEB_PASSWORD' })

    expect(await finish()).toContain(' 409 ')
    expect(await composition.credentials().resolve('ALT_WEB_PASSWORD'))
      .toMatchObject({ value: 'alternate-password' })
  })

  it('rejects a stale password-only remote save before rotating the current credential', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    await composition.settings().update(settingsNamespace('auth-tunnel'), { passwordRef: 'ALT_WEB_PASSWORD' })
    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [],
        password: 'stale-page-password',
      }),
    })

    expect(response.status).toBe(401)
    expect(await composition.credentials().resolve('ALT_WEB_PASSWORD'))
      .toMatchObject({ value: 'alternate-password' })
  })

  it('rechecks the settings revision after password-only authorization waits', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    let signalResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { signalResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'DSH_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      signalResolveStarted()
    }

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [],
        password: 'stale-page-password',
      }),
    })
    await resolveStarted
    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    releaseResolve()

    expect((await responseTask).status).toBe(409)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 's3kret-passw0rd' })
  })

  it('requires a new remote password reference to be configured separately', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'NEW_REMOTE_PASSWORD' }],
        password: 'new-password',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
    expect(await composition.credentials().resolve('NEW_REMOTE_PASSWORD')).toBeUndefined()
  })

  it('ignores an inactive quick-mode tokenRef collision in remote saves', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({
      allowRemoteSettings: true,
      tokenRef: 'DSH_WEB_PASSWORD',
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: '',
      }),
    })

    expect(response.status).toBe(200)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).sessionTtlHours).toBe(24)
  })

  it('rolls back remote settings when the credential write fails', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    composition.credentials().failNextSet = true

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: 'replacement-password',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).sessionTtlHours).toBe(720)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 's3kret-passw0rd' })
  })

  it('rolls back remote settings when the access credential changes during persistence', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: 'stale-remote-password',
      }),
    })
    await persistStarted
    composition.credentials().set('DSH_WEB_PASSWORD', 'local-admin-password')
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()

    expect((await responseTask).status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).sessionTtlHours).toBe(720)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 'local-admin-password' })
  })

  it('rolls back passwordless remote settings when the authorizing credential changes during persistence', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: '',
      }),
    })
    await persistStarted
    composition.credentials().set('DSH_WEB_PASSWORD', 'local-admin-password')
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()

    expect((await responseTask).status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).sessionTtlHours).toBe(720)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 'local-admin-password' })
  })

  it('fences the credential that authorized a reference-changing remote save', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { NEXT_WEB_PASSWORD: 'next-password' },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
        password: '',
      }),
    })
    await persistStarted
    composition.credentials().set('DSH_WEB_PASSWORD', 'local-admin-password')
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()

    expect((await responseTask).status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 'local-admin-password' })
    expect(await composition.credentials().resolve('NEXT_WEB_PASSWORD'))
      .toMatchObject({ value: 'next-password' })
  })

  it('rolls back a passwordless reference change when the target credential is deleted during persistence', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { NEXT_WEB_PASSWORD: 'next-password' },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
        password: '',
      }),
    })
    await persistStarted
    composition.credentials().set('NEXT_WEB_PASSWORD', undefined)
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()

    expect((await responseTask).status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
    expect(await composition.credentials().resolve('NEXT_WEB_PASSWORD')).toBeUndefined()
  })

  it('rejects a remote save that rotates the active password and tunnel route together', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'gatePort', op: 'set', value: 32_345 }],
        password: 'combined-password',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).gatePort).toBe(0)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 's3kret-passw0rd' })
  })

  it('rejects a passwordless remote passwordRef collision in token mode', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({
      allowRemoteSettings: true,
      tokenRef: 'DSH_TUNNEL_TOKEN',
    }, { seeds: { DSH_TUNNEL_TOKEN: 'tunnel-token' } })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [
          { field: 'mode', op: 'set', value: 'token' },
          { field: 'passwordRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' },
          { field: 'publicHostname', op: 'set', value: 'gui.example.com' },
          { field: 'gatePort', op: 'set', value: 32_309 },
        ],
        password: '',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
  })

  it('rejects a passwordless switch to an unconfigured access credential', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'MISSING_PASSWORD' }],
        password: '',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
  })

  it('rejects a passwordless switch to an empty resolved access credential', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { EMPTY_PASSWORD: '' },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'EMPTY_PASSWORD' }],
        password: '',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
  })

  it('rejects a remote password that cannot fit through the login endpoint', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [],
        password: 'x'.repeat(20_000),
      }),
    })

    expect(response.status).toBe(409)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 's3kret-passw0rd' })
  })

  it('rejects duplicate remote writes without committing their final value', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [
          { field: 'sessionTtlHours', op: 'set', value: 24 },
          { field: 'sessionTtlHours', op: 'set', value: 48 },
        ],
        password: '',
      }),
    })

    expect(response.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).sessionTtlHours).toBe(720)
  })

  it('rejects password-only remote saves while Host settings are read-only', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    composition.settings().writable = false

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [],
        password: 'read-only-password',
      }),
    })

    expect(response.status).toBe(409)
    expect(await composition.credentials().resolve('DSH_WEB_PASSWORD'))
      .toMatchObject({ value: 's3kret-passw0rd' })
  })

  it.each(['DSH_TUNNEL_TOKEN', 'OTHER_HOST_SECRET'])(
    'does not let a remote password write overwrite existing non-access credential %s',
    { timeout: 60_000 },
    async (targetRef) => {
      const composition = await bootQuick({
        allowRemoteSettings: true,
        tokenRef: 'DSH_TUNNEL_TOKEN',
      }, {
        seeds: {
          DSH_TUNNEL_TOKEN: 'tunnel-token',
          OTHER_HOST_SECRET: 'other-secret',
        },
      })
      const base = await composition.gateBase()
      const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
      const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
        settings: { revision: number }
      }

      const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({
          expectedRevision: opened.settings.revision,
          writes: [{ field: 'passwordRef', op: 'set', value: targetRef }],
          password: 'attacker-selected-password',
        }),
      })

      expect(response.status).toBe(409)
      expect(await composition.credentials().resolve('DSH_TUNNEL_TOKEN')).toMatchObject({ value: 'tunnel-token' })
      expect(await composition.credentials().resolve('OTHER_HOST_SECRET')).toMatchObject({ value: 'other-secret' })
      expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
    },
  )

  it('returns the complete remote save before stopping the active tunnel', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'enabled', op: 'set', value: false }],
        password: '',
      }),
    })
    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ settings: { value: { enabled: false } } })
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
    expect(await liveFixturePids()).toEqual([])
  })

  it('keeps the previous gate alive until a route-changing save response finishes', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    const before = await composition.runtimeStatus()
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/settings') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'gatePort', op: 'set', value: nextPort }],
        password: '',
      }),
    }).catch(() => undefined)
    await responseHeld
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    await sleep(3700)
    releaseResponse()

    expect((await responseTask)?.status).toBe(200)
  })

  it('keeps the previous tunnel child alive until a process-changing save response finishes', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const delayedExecutable = await fixtureExecutable('fake-cloudflared-delayed.sh')
    const composition = await bootQuick({ allowRemoteSettings: true, executable: quickExecutable })
    const originalPid = (await liveFixturePids())[0]!
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    const before = await composition.runtimeStatus()
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/settings') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'executable', op: 'set', value: delayedExecutable }],
        password: '',
      }),
    })
    await responseHeld
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    await sleep(3700)
    expect(await liveFixturePids()).toContain(originalPid)

    releaseResponse()
    expect((await responseTask).status).toBe(200)
    const retiredDeadline = Date.now() + 5000
    while ((await liveFixturePids()).includes(originalPid)) {
      if (Date.now() >= retiredDeadline) throw new Error('previous tunnel child was not retired')
      await sleep(25)
    }
  })

  it('restores the previous tunnel when its replacement exits during the response fence', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const crashingExecutable = await fixtureExecutable('fake-cloudflared-late-crash.sh')
    const composition = await bootQuick({ allowRemoteSettings: true, executable: quickExecutable })
    const originalPid = (await liveFixturePids())[0]!
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    const before = await composition.runtimeStatus()
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/settings') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'executable', op: 'set', value: crashingExecutable }],
        password: '',
      }),
    }).catch(() => undefined)
    await responseHeld
    let released = false
    try {
      await waitForStatus(
        composition,
        status => status.revision > before.revision
          && status.phase === 'running'
          && status.publicUrl?.includes('late-crash') === true,
      )
      const failed = await waitForStatus(
        composition,
        status => status.phase === 'error' && !status.running,
        7000,
      )
      expect(await liveFixturePids()).toContain(originalPid)

      releaseResponse()
      released = true
      expect((await responseTask)?.status).toBe(200)
      const restored = await waitForStatus(
        composition,
        status => status.revision > failed.revision
          && status.phase === 'error'
          && status.running
          && status.publicUrl === QUICK_URL,
      )
      expect(restored.message).toContain('kept the previous public URL')
      expect(await liveFixturePids()).toEqual([originalPid])
    } finally {
      if (!released) releaseResponse()
    }
  })

  it('returns the complete locale response before a local disable stops the tunnel', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    composition.settings().register(settingsNamespace('locale'), z.object({
      preference: z.union(['zh', 'en']).required(false),
    }))
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/locale') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    const responseTask = fetch(`${base}/dsh-auth-tunnel/locale`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ locale: 'en' }),
    }).catch(() => undefined)
    await responseHeld
    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    await sleep(250)
    const beforeRelease = await composition.runtimeStatus()
    releaseResponse()
    const response = await responseTask

    expect(beforeRelease).toMatchObject({ phase: 'applying', running: false })
    expect(response?.status).toBe(200)
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
    expect(composition.settings().get(settingsNamespace('locale'))).toEqual({ preference: 'en' })
  })

  it('rolls back a locale write when the authorizing credential changes during persistence', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    composition.settings().register(settingsNamespace('locale'), z.object({
      preference: z.union(['zh', 'en']).required(false),
    }))
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted

    const responseTask = fetch(`${base}/dsh-auth-tunnel/locale`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ locale: 'en' }),
    })
    await persistStarted
    composition.credentials().set('DSH_WEB_PASSWORD', 'local-admin-password')
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()

    expect((await responseTask).status).toBe(409)
    expect(composition.settings().get(settingsNamespace('locale'))).toEqual({})
  })

  it('keeps a failed locale response fenced during a tunnel handoff', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const delayedExecutable = await fixtureExecutable('fake-cloudflared-delayed.sh')
    const composition = await bootQuick({ allowRemoteSettings: true, executable: quickExecutable })
    composition.settings().register(settingsNamespace('locale'), z.object({
      preference: z.union(['zh', 'en']).required(false),
    }))
    const originalPid = (await liveFixturePids())[0]!
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/locale') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    const responseTask = fetch(`${base}/dsh-auth-tunnel/locale`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ locale: 'en' }),
    }).catch(() => undefined)
    await persistStarted
    const beforeCredential = await composition.runtimeStatus()
    await composition.credentials().set('DSH_WEB_PASSWORD', 'local-admin-password')
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()
    await responseHeld
    let responseReleased = false
    try {
      await waitForStatus(
        composition,
        status => status.revision > beforeCredential.revision && status.phase === 'running',
      )
      const beforeHandoff = await composition.runtimeStatus()
      await composition.settings().update(settingsNamespace('auth-tunnel'), { executable: delayedExecutable })
      await waitForStatus(
        composition,
        status => status.revision > beforeHandoff.revision && status.phase === 'running',
      )
      await sleep(3700)
      expect(await liveFixturePids()).toContain(originalPid)

      releaseResponse()
      responseReleased = true
      expect((await responseTask)?.status).toBe(409)
      const retiredDeadline = Date.now() + 5000
      while ((await liveFixturePids()).includes(originalPid)) {
        if (Date.now() >= retiredDeadline) throw new Error('failed locale response did not release the handoff')
        await sleep(25)
      }
      expect(composition.settings().get(settingsNamespace('locale'))).toEqual({})
    } finally {
      composition.settings().persistStarted = undefined
      composition.settings().persistBarrier = undefined
      releasePersist()
      if (!responseReleased) releaseResponse()
    }
  })

  it('does not let pre-commit credential resolution delay local tunnel shutdown', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { NEXT_WEB_PASSWORD: 'next-password' },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'NEXT_WEB_PASSWORD'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'NEXT_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
        password: '',
      }),
    }).catch(() => undefined)
    await resolveStarted
    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
    expect(await liveFixturePids()).toEqual([])

    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: true })
    await waitForStatus(composition, status => status.phase === 'running' && status.running)
    const resumedBase = await composition.gateBase()
    const resumedCookie = (await login(resumedBase)).get('set-cookie')!.split(';', 1)[0]!
    const resumed = await (await fetch(`${resumedBase}/dsh-auth-tunnel/settings`, {
      headers: { cookie: resumedCookie },
    })).json() as { settings: { revision: number } }
    const resumedSave = await fetch(`${resumedBase}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie: resumedCookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: resumed.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: '',
      }),
    })
    expect(resumedSave.status).toBe(200)
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).sessionTtlHours).toBe(24)

    composition.credentials().resolveBarrier = undefined
    composition.credentials().resolveBarrierRef = undefined
    releaseResolve()
    await responseTask
    expect(composition.settings().get(settingsNamespace('auth-tunnel')).passwordRef).toBe('DSH_WEB_PASSWORD')
  })

  it('detaches a stale pre-commit save after the access password rotates', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { NEXT_WEB_PASSWORD: 'next-password' },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'NEXT_WEB_PASSWORD'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'NEXT_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }
    const staleTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
        password: '',
      }),
    }).catch(() => undefined)
    await resolveStarted

    await composition.credentials().set('DSH_WEB_PASSWORD', 'rotated-password')
    const freshCookie = (await login(base, undefined, 'rotated-password')).get('set-cookie')!.split(';', 1)[0]!
    const freshOpened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, {
      headers: { cookie: freshCookie },
    })).json() as { settings: { revision: number } }
    const freshSave = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie: freshCookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: freshOpened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: '',
      }),
    })
    try {
      const outcome = await Promise.race([
        freshSave,
        sleep(3000).then(() => undefined),
      ])
      expect(outcome?.status).toBe(200)
    } finally {
      composition.credentials().resolveBarrier = undefined
      composition.credentials().resolveBarrierRef = undefined
      releaseResolve()
    }
    expect((await staleTask)?.status).toBe(409)
    expect(composition.settings().get(settingsNamespace('auth-tunnel'))).toMatchObject({
      passwordRef: 'DSH_WEB_PASSWORD',
      sessionTtlHours: 24,
    })
  })

  it('revokes public access while a committed credential write delays shutdown', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    composition.loaded.webServer.register({
      kind: 'exact', path: '/api/disable-probe', handler: (_req, res) => {
        res.writeHead(200)
        res.end('ok')
      },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    expect((await fetch(`${base}/api/disable-probe`, { headers: { cookie } })).status).toBe(200)
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releaseSet = (): void => {}
    composition.credentials().setBarrier = new Promise<void>((resolve) => { releaseSet = resolve })
    let markSetStarted = (): void => {}
    const setStarted = new Promise<void>((resolve) => { markSetStarted = resolve })
    composition.credentials().setStarted = (ref) => {
      if (ref !== 'DSH_WEB_PASSWORD') return
      composition.credentials().setStarted = undefined
      markSetStarted()
    }

    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [],
        password: 'replacement-password',
      }),
    }).catch(() => undefined)
    await setStarted
    let released = false
    try {
      await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })

      const denied = await fetch(`${base}/api/disable-probe`, { headers: { cookie } })
      expect(denied.status).toBe(503)
      expect(await composition.runtimeStatus()).toMatchObject({ phase: 'applying', running: false })
      expect(composition.shellEnv().contributors).toEqual([])
      expect(composition.systemPrompt().sections).toEqual([])
      expect(await liveFixturePids()).toHaveLength(1)

      releaseSet()
      released = true
      expect((await responseTask)?.status).toBe(200)
      await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
      expect(await liveFixturePids()).toEqual([])
    } finally {
      composition.credentials().setBarrier = undefined
      composition.credentials().setStarted = undefined
      if (!released) releaseSet()
    }
  })

  it('releases the remote mutation fence when the writer disconnects before the response', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).json() as {
      settings: { revision: number }
    }
    let releasePersist = (): void => {}
    composition.settings().persistBarrier = new Promise<void>((resolve) => { releasePersist = resolve })
    let markPersistStarted = (): void => {}
    const persistStarted = new Promise<void>((resolve) => { markPersistStarted = resolve })
    composition.settings().persistStarted = markPersistStarted
    const body = JSON.stringify({
      expectedRevision: opened.settings.revision,
      writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      password: '',
    })
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    socket.write([
      'POST /dsh-auth-tunnel/settings HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Content-Type: application/json',
      `Content-Length: ${String(Buffer.byteLength(body))}`,
      `Cookie: ${cookie}`,
      '',
      body,
    ].join('\r\n'))
    await persistStarted
    socket.destroy()
    await sleep(50)
    composition.settings().persistStarted = undefined
    composition.settings().persistBarrier = undefined
    releasePersist()
    await sleep(50)

    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
    expect(await liveFixturePids()).toEqual([])
  })

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

  it('does not mint a session when the login policy changes during credential resolution', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    const base = await composition.gateBase()
    composition.credentials().afterResolve = (ref) => {
      if (ref !== 'DSH_WEB_PASSWORD') return
      composition.credentials().afterResolve = undefined
      composition.credentials().set(ref, 'rotated-password')
    }

    const response = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=s3kret-passw0rd',
    })

    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe('/dsh-auth-tunnel/login?error=1')
    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('rejects an HTTP request when the access credential rotates during authentication', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    let proxied = 0
    composition.loaded.webServer.register({
      kind: 'exact', path: '/api/auth-race', handler: (_req, res) => {
        proxied += 1
        res.writeHead(200)
        res.end()
      },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    composition.credentials().afterResolve = (ref) => {
      if (ref !== 'DSH_WEB_PASSWORD') return
      composition.credentials().afterResolve = undefined
      composition.credentials().set(ref, 'rotated-password')
    }

    const response = await fetch(`${base}/api/auth-race`, { headers: { cookie } })

    expect(response.status).toBe(401)
    expect(proxied).toBe(0)
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

  it('cancels an authenticated proxied HTTP request when the access credential rotates', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    let markStarted = (): void => {}
    const started = new Promise<void>((resolve) => { markStarted = resolve })
    let markCancelled = (): void => {}
    const cancelled = new Promise<void>((resolve) => { markCancelled = resolve })
    let executed = false
    composition.loaded.webServer.register({
      kind: 'exact', path: '/slow-action', handler: (req, res) => {
        markStarted()
        req.once('aborted', markCancelled)
        req.once('end', () => {
          executed = true
          res.end('completed')
        })
      },
    })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const body = 'execute-after-revocation'
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    const closed = once(socket, 'close').then(() => 'closed')
    socket.write([
      'POST /slow-action HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      `Content-Length: ${String(Buffer.byteLength(body))}`,
      `Cookie: ${cookie}`,
      '',
      body.slice(0, 1),
    ].join('\r\n'))
    await started

    composition.credentials().set('DSH_WEB_PASSWORD', 'rotated-password')

    expect(await Promise.race([closed, sleep(3000).then(() => 'timeout')])).toBe('closed')
    await Promise.race([
      cancelled,
      sleep(3000).then(() => { throw new Error('upstream request survived the credential rotation') }),
    ])
    expect(executed).toBe(false)
  })

  it('invalidates pending authentication before closing a gate', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    let executed = false
    composition.loaded.webServer.register({
      kind: 'exact', path: '/shutdown-action', handler: (_req, res) => {
        executed = true
        res.end('completed')
      },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'DSH_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }

    const responseTask = fetch(`${base}/shutdown-action`, { headers: { cookie } }).catch(() => undefined)
    await resolveStarted
    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
    composition.credentials().resolveBarrier = undefined
    releaseResolve()
    await responseTask
    await sleep(250)

    expect(executed).toBe(false)
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

  it('closes authenticated upgrades when the access credential rotates', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    composition.loaded.webServer.registerUpgrade({
      path: '/events',
      handler: (_req, socket) => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\n\r\n')
        socket.on('data', (chunk: Buffer) => { socket.write(chunk) })
      },
    })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    socket.write([
      'GET /events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n'))
    const [head] = await once(socket, 'data') as [Buffer]
    expect(String(head)).toContain('101 Switching Protocols')
    const closed = once(socket, 'close')

    composition.credentials().set('DSH_WEB_PASSWORD', 'rotated-password')

    await closed
    expect(socket.destroyed).toBe(true)
  })

  it('rejects an upgrade when the access credential rotates during authentication', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    composition.loaded.webServer.registerUpgrade({
      path: '/events',
      handler: (_req, socket) => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\n\r\n')
      },
    })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    composition.credentials().afterResolve = (ref) => {
      if (ref !== 'DSH_WEB_PASSWORD') return
      composition.credentials().afterResolve = undefined
      composition.credentials().set(ref, 'rotated-password')
    }
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    const outcome = new Promise<string>((resolve) => {
      socket.once('data', (data: Buffer) => { resolve(String(data)) })
      socket.once('close', () => { resolve('closed') })
    })
    socket.write([
      'GET /events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n'))

    expect(await outcome).toBe('closed')
    socket.destroy()
  })

  it('closes upgraded sockets before disabling the gate', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    composition.loaded.webServer.registerUpgrade({
      path: '/events',
      handler: (_req, socket) => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\n\r\n')
      },
    })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    socket.write([
      'GET /events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n'))
    const [head] = await once(socket, 'data') as [Buffer]
    expect(String(head)).toContain('101 Switching Protocols')
    const closed = once(socket, 'close').then(() => 'closed')

    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })

    expect(await Promise.race([closed, sleep(3000).then(() => 'timeout')])).toBe('closed')
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
    expect(socket.destroyed).toBe(true)
  })

  it('closes upgrades on the retained gate after a passwordRef update fails', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    composition.loaded.webServer.registerUpgrade({
      path: '/events',
      handler: (_req, socket) => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: dsh-echo\r\nConnection: Upgrade\r\n\r\n')
        socket.on('data', (chunk: Buffer) => { socket.write(chunk) })
      },
    })
    const base = await composition.gateBase()
    const port = Number(new URL(base).port)
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const socket = connect(port, '127.0.0.1')
    socket.on('error', () => {})
    await once(socket, 'connect')
    socket.write([
      'GET /events HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Connection: Upgrade',
      'Upgrade: dsh-echo',
      `Cookie: ${cookie}`,
      '',
      '',
    ].join('\r\n'))
    const [head] = await once(socket, 'data') as [Buffer]
    expect(String(head)).toContain('101 Switching Protocols')

    const closed = once(socket, 'close').then(() => 'closed')
    await composition.settings().update(settingsNamespace('auth-tunnel'), { passwordRef: 'MISSING_PASSWORD' })
    const outcome = await Promise.race([closed, sleep(750).then(() => 'timeout')])
    await waitForStatus(composition, status => status.phase === 'error' && status.running)
    socket.destroy()
    expect(outcome).toBe('closed')
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

  it('serializes a live settings update behind initial tunnel startup', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-delayed.sh'),
      startupTimeoutMs: 15_000,
    }, { wait: false })
    const deadline = Date.now() + 5000
    while ((await liveFixturePids()).length === 0) {
      if (Date.now() >= deadline) throw new Error('initial cloudflared did not start')
      await sleep(25)
    }

    await composition.settings().update(settingsNamespace('auth-tunnel'), { sessionTtlHours: 24 })
    await composition.loaded.loader.await()
    await sleep(800)

    expect(await liveFixturePids()).toHaveLength(1)
    expect(await composition.runtimeStatus()).toMatchObject({ phase: 'running', running: true })
  })

  it('latches a password reference changed while the initial gate is being created', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-delayed.sh'),
      startupTimeoutMs: 15_000,
    }, {
      wait: false,
      credentialResolveDelayMs: 700,
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const namespace = settingsNamespace('auth-tunnel')
    const settingsDeadline = Date.now() + 3000
    while (composition.settings().get(namespace) === undefined) {
      if (Date.now() >= settingsDeadline) throw new Error('auth-tunnel settings were not registered')
      await sleep(10)
    }
    await composition.settings().update(namespace, { passwordRef: 'ALT_WEB_PASSWORD' })
    const gateDeadline = Date.now() + 5000
    while ((await liveFixturePids()).length === 0) {
      if (Date.now() >= gateDeadline) throw new Error('initial cloudflared did not start')
      await sleep(10)
    }
    composition.credentials().resolveDelayMs = 0
    const base = await composition.gateBase()

    const staleLogin = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=s3kret-passw0rd',
    })
    expect(staleLogin.headers.get('set-cookie')).toBeNull()
    await login(base, undefined, 'alternate-password')
    await composition.loaded.loader.await()
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

  it('teardown cancels a staged startup without waiting for its timeout', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const silentExecutable = await fixtureExecutable('fake-cloudflared-silent.sh')
    const composition = await bootQuick({ executable: quickExecutable, startupTimeoutMs: 10_000 })
    const base = await composition.gateBase()

    await composition.settings().update(settingsNamespace('auth-tunnel'), { executable: silentExecutable })
    const deadline = Date.now() + 5000
    while ((await liveFixturePids()).length < 2) {
      if (Date.now() >= deadline) throw new Error('staged cloudflared did not start')
      await sleep(25)
    }

    const startedAt = Date.now()
    await context!.fiber.dispose()
    const elapsed = Date.now() - startedAt
    context = undefined

    expect(elapsed).toBeLessThan(4000)
    expect(await liveFixturePids()).toEqual([])
    await expect(fetch(`${base}/dsh-auth-tunnel/login`)).rejects.toThrow()
  })

  it('a live disable cancels a staged startup without waiting for its timeout', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const silentExecutable = await fixtureExecutable('fake-cloudflared-silent.sh')
    const composition = await bootQuick({ executable: quickExecutable, startupTimeoutMs: 10_000 })

    await composition.settings().update(settingsNamespace('auth-tunnel'), { executable: silentExecutable })
    const deadline = Date.now() + 5000
    while ((await liveFixturePids()).length < 2) {
      if (Date.now() >= deadline) throw new Error('staged cloudflared did not start')
      await sleep(25)
    }

    const startedAt = Date.now()
    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    await waitForStatus(composition, status => status.phase === 'stopped', 4000)

    expect(Date.now() - startedAt).toBeLessThan(4000)
    expect(await liveFixturePids()).toEqual([])
  })

  it('returns a committed disable response before cleaning up a staged token gate', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      allowRemoteSettings: true,
      executable: await fixtureExecutable('fake-cloudflared-silent.sh'),
      startupTimeoutMs: 10_000,
    }, { wait: false, seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })
    const base = `http://127.0.0.1:${String(gatePort)}`
    const childDeadline = Date.now() + 5000
    while ((await liveFixturePids()).length === 0) {
      if (Date.now() >= childDeadline) throw new Error('staged cloudflared did not start')
      await sleep(25)
    }
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${base}/dsh-auth-tunnel/settings`, {
      headers: { cookie },
    })).json() as { settings: { revision: number } }
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/settings') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    let responseSettled = false
    const responseTask = fetch(`${base}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'enabled', op: 'set', value: false }],
        password: '',
      }),
    }).catch(() => undefined).finally(() => { responseSettled = true })
    await responseHeld
    let released = false
    try {
      const stoppedDeadline = Date.now() + 5000
      while ((await liveFixturePids()).length !== 0) {
        if (Date.now() >= stoppedDeadline) throw new Error('staged cloudflared did not stop')
        await sleep(25)
      }
      await sleep(100)
      expect(responseSettled).toBe(false)
      releaseResponse()
      released = true
      const response = await responseTask
      expect(response?.status).toBe(200)
      expect(await response?.json()).toMatchObject({ settings: { value: { enabled: false } } })
      await composition.loaded.loader.await()
      await waitForStatus(composition, status => status.phase === 'stopped' && !status.running)
      expect(await liveFixturePids()).toEqual([])
    } finally {
      if (!released) releaseResponse()
    }
  })

  it('a live disable stays latched before staged startup is created', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-silent.sh'),
      startupTimeoutMs: 10_000,
    }, { wait: false, credentialResolveDelayMs: 500 })

    await composition.settings().update(settingsNamespace('auth-tunnel'), { enabled: false })
    const outcome = await Promise.race([
      composition.loaded.loader.await().then(() => 'loaded'),
      sleep(3000).then(() => 'timeout'),
    ])

    expect(outcome).toBe('loaded')
    await waitForStatus(composition, status => status.phase === 'stopped')
    expect(await liveFixturePids()).toEqual([])
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

  it('rejects timer values that Node or the session verifier cannot represent', () => {
    expect(() => Config({ sessionTtlHours: 3_000_000_000 })).toThrow()
    expect(() => Config({ startupTimeoutMs: 2_147_483_648 })).toThrow()
  })

  it('stays pending when the composition offers no credentials service', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
      startupTimeoutMs: 15_000,
    }, { withCredentials: false })
    const tunnel = [...composition.loaded.loader.entries()]
      .find(entry => entry.options.name === 'dsh-auth-tunnel')
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

  it('quick mode ignores preserved token-mode settings so the card can switch modes', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
      startupTimeoutMs: 15_000,
    })
    expect((await fetch(`${await composition.gateBase()}/dsh-auth-tunnel/login`)).status).toBe(200)
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

  it('does not publish a tunnel that exits immediately after reporting readiness', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-ready-exit.sh'),
      startupTimeoutMs: 15_000,
    }, { wait: false })

    await expect(composition.loaded.loader.await()).rejects.toThrow(/exited before adoption/)
    expect(composition.shellEnv().contributors).toEqual([])
    expect(composition.systemPrompt().sections).toEqual([])
    expect(await liveFixturePids()).toEqual([])
  })

  it('redacts the named-tunnel token from early-exit diagnostics', { timeout: 60_000 }, async () => {
    const token = 'fixture-token-must-not-leak'
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort: 32_308,
      executable: await fixtureExecutable('fake-cloudflared-token-crash.sh'),
      startupTimeoutMs: 15_000,
    }, { wait: false, seeds: { DSH_TUNNEL_TOKEN: token } })
    const pending = composition.loaded.loader.await() as Promise<unknown>
    await expect(pending).rejects.toSatisfy((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error)
      return message.includes('[REDACTED]') && !message.includes(token)
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

  it('rejects a shared access-password and tunnel-token credential at boot', { timeout: 60_000 }, async () => {
    await expectBootFailure({
      mode: 'token',
      passwordRef: 'SHARED_SECRET',
      tokenRef: 'SHARED_SECRET',
      publicHostname: 'gui.example.com',
      gatePort: 32_313,
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, /access password credential conflicts with the tunnel token credential/, {
      seeds: { SHARED_SECRET: 'shared-secret' },
    })
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
    }, /token mode requires .*gatePort/, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' } })

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

describe('rc7 plugin settings', () => {
  const namespace = settingsNamespace('auth-tunnel')

  it('keeps settings available without starting public access while disabled', { timeout: 60_000 }, async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const composition = await loadComposition({
      enabled: false,
      mode: 'token',
      executable: '/missing/cloudflared',
    }, { withPassword: false })

    const descriptor = composition.settings().describe().find(entry => entry.ns === namespace)
    expect(descriptor).toMatchObject({
      ns: namespace,
      applies: 'live',
      value: { enabled: false, allowRemoteSettings: false, mode: 'token' },
    })
    expect(await composition.runtimeStatus()).toMatchObject({ phase: 'stopped', running: false })
    expect(consoleSpy).not.toHaveBeenCalled()
    expect(composition.shellEnv().contributors).toEqual([])
    expect(composition.systemPrompt().sections).toEqual([])
    expect(await liveFixturePids()).toEqual([])
    await expect(composition.settings().update(namespace, { enabled: true }))
      .rejects.toThrow(/token mode requires tokenRef/)
  })

  it('withholds remote settings when a password reference cannot be applied', { timeout: 60_000 }, async () => {
    const composition = await loadComposition({
      allowRemoteSettings: true,
      mode: 'quick',
      executable: await fixtureExecutable('fake-cloudflared-quick.sh'),
      startupTimeoutMs: 15_000,
    }, {
      withPassword: false,
      seeds: {
        ALT_WEB_PASSWORD: 'settings-password',
        NEXT_WEB_PASSWORD: 'next-settings-password',
      },
      settingsDocument: { 'auth-tunnel': { passwordRef: 'ALT_WEB_PASSWORD' } },
    })

    const descriptor = composition.settings().describe().find(entry => entry.ns === namespace)
    expect(descriptor).toMatchObject({
      ns: namespace,
      applies: 'live',
      value: { enabled: true, passwordRef: 'ALT_WEB_PASSWORD', mode: 'quick' },
    })
    expect(descriptor?.base).toMatchObject({ enabled: true, passwordRef: 'DSH_WEB_PASSWORD', mode: 'quick' })

    const base = await composition.gateBase()
    await login(base, undefined, 'settings-password')

    const beforeRotation = await composition.runtimeStatus()
    await composition.settings().update(namespace, { passwordRef: 'NEXT_WEB_PASSWORD' })
    await waitForStatus(composition, status => status.revision > beforeRotation.revision && status.phase === 'running')
    const oldPassword = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=settings-password',
    })
    expect(oldPassword.headers.get('location')).toBe('/dsh-auth-tunnel/login?error=1')
    const cookie = (await login(base, undefined, 'next-settings-password')).get('set-cookie')!.split(';', 1)[0]!

    const beforeFailure = await composition.runtimeStatus()
    await composition.settings().update(namespace, { passwordRef: 'MISSING_PASSWORD' })
    const failed = await waitForStatus(
      composition,
      status => status.revision > beforeFailure.revision && status.phase === 'error',
    )
    expect(failed).toMatchObject({ running: true, publicUrl: QUICK_URL })
    expect(failed.message).toContain('MISSING_PASSWORD')
    const unavailable = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=next-settings-password',
    })
    expect(unavailable.status).toBe(503)

    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(401)
    composition.credentials().set('MISSING_PASSWORD', 'repaired-password')
    await waitForStatus(
      composition,
      status => status.revision > failed.revision && status.phase === 'running',
    )
    await login(base, undefined, 'repaired-password')
    expect((await liveFixturePids()).length).toBe(1)
  })

  it('starts the configured token tunnel when its missing credential is repaired', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const tokenExecutable = await fixtureExecutable('fake-cloudflared-token.sh')
    const composition = await bootQuick({ executable: quickExecutable })
    const previousGate = await composition.gateBase()
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')

    await composition.settings().update(namespace, {
      mode: 'token',
      tokenRef: 'MISSING_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: tokenExecutable,
    })
    const failed = await waitForStatus(composition, status => status.phase === 'error')
    expect(failed).toMatchObject({ running: true, publicUrl: QUICK_URL })
    expect((await fetch(`${previousGate}/dsh-auth-tunnel/login`)).status).toBe(200)

    composition.credentials().set('MISSING_TUNNEL_TOKEN', 'fixture-token')
    const recovered = await waitForStatus(
      composition,
      status => status.revision > failed.revision && status.phase === 'running',
      7000,
    )
    expect(recovered.publicUrl).toBe('https://gui.example.com')
    expect((await fetch(`http://127.0.0.1:${String(gatePort)}/dsh-auth-tunnel/login`)).status).toBe(200)
  })

  it('restarts an active token tunnel when its credential rotates', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token-1' } })
    const originalPids = await liveFixturePids()
    const before = await composition.runtimeStatus()

    composition.credentials().set('DSH_TUNNEL_TOKEN', 'fixture-token-2')
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
      7000,
    )
    const handoffDeadline = Date.now() + 6000
    while ((await liveFixturePids()).length > 1) {
      if (Date.now() >= handoffDeadline) throw new Error('token replacement handoff did not finish')
      await sleep(25)
    }

    const replacementPids = await liveFixturePids()
    expect(replacementPids).toHaveLength(1)
    expect(replacementPids).not.toEqual(originalPids)
  })

  it('switches to a valid target when the discarded fallback token no longer resolves', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'TOKEN_A',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token-recording.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { TOKEN_A: 'fixture-token-a', TOKEN_B: 'fixture-token-b' } })

    composition.credentials().set('TOKEN_A', undefined)
    await composition.settings().update(namespace, { tokenRef: 'TOKEN_B' })

    const deadline = Date.now() + 7000
    let applied = ''
    while (Date.now() < deadline) {
      const pids = await liveFixturePids()
      if (pids.length === 1) {
        applied = await readFile(join(tmpdir(), `${FAKE_PREFIX}${pids[0]!}.token`), 'utf8').catch(() => '')
        if (applied === 'fixture-token-b') break
      }
      await sleep(25)
    }
    expect(applied).toBe('fixture-token-b')
    expect(await composition.runtimeStatus()).toMatchObject({ phase: 'running', running: true })
  })

  it('restarts the retained token tunnel after a different configured token fails', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token-recording.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token-1' } })

    await composition.settings().update(namespace, { tokenRef: 'MISSING_TUNNEL_TOKEN' })
    const failed = await waitForStatus(composition, status => status.phase === 'error' && status.running)
    const originalPids = await liveFixturePids()

    composition.credentials().set('DSH_TUNNEL_TOKEN', 'fixture-token-2')
    await waitForStatus(
      composition,
      status => status.revision > failed.revision && status.phase === 'error' && status.running,
      7000,
    )

    const replacementPids = await liveFixturePids()
    expect(replacementPids).toHaveLength(1)
    expect(replacementPids).not.toEqual(originalPids)
    expect(await readFile(join(tmpdir(), `${FAKE_PREFIX}${replacementPids[0]!}.token`), 'utf8'))
      .toBe('fixture-token-2')
  })

  it('restores the retained token tunnel when its refreshed child crashes during handoff', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token-rotated-crash.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token-1' } })
    const originalPids = await liveFixturePids()

    await composition.settings().update(namespace, { tokenRef: 'MISSING_TUNNEL_TOKEN' })
    const failed = await waitForStatus(composition, status => status.phase === 'error' && status.running)
    composition.credentials().set('DSH_TUNNEL_TOKEN', 'fixture-token-2')

    const restored = await waitForStatus(
      composition,
      status => status.revision > failed.revision && status.phase === 'error' && status.running,
      7000,
    )
    expect(restored.publicUrl).toBe('https://gui.example.com')
    expect(await liveFixturePids()).toEqual(originalPids)
  })

  it('applies the latest token when it rotates again during a restart', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token-recording.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { DSH_TUNNEL_TOKEN: 'fixture-token-1' } })

    composition.credentials().set('DSH_TUNNEL_TOKEN', 'fixture-token-2')
    const stagingDeadline = Date.now() + 5000
    while ((await liveFixturePids()).length < 2) {
      if (Date.now() >= stagingDeadline) throw new Error('first token replacement did not start')
      await sleep(25)
    }
    composition.credentials().set('DSH_TUNNEL_TOKEN', 'fixture-token-3')

    const appliedDeadline = Date.now() + 12_000
    let applied = ''
    while (Date.now() < appliedDeadline) {
      const pids = await liveFixturePids()
      if (pids.length === 1) {
        applied = await readFile(join(tmpdir(), `${FAKE_PREFIX}${pids[0]!}.token`), 'utf8').catch(() => '')
        if (applied === 'fixture-token-3') break
      }
      await sleep(25)
    }
    expect(applied).toBe('fixture-token-3')
  })

  it('refreshes a rotated fallback token after the replacement crashes during handoff', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'TOKEN_A',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: await fixtureExecutable('fake-cloudflared-token-rotated-crash.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { TOKEN_A: 'fixture-token-1', TOKEN_B: 'fixture-token-2' } })
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { tokenRef: 'TOKEN_B' })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
      5000,
    )
    composition.credentials().set('TOKEN_A', 'fixture-token-3')

    const deadline = Date.now() + 12_000
    let retainedToken = ''
    while (Date.now() < deadline) {
      const pids = await liveFixturePids()
      if (pids.length === 1) {
        retainedToken = await readFile(join(tmpdir(), `${FAKE_PREFIX}${pids[0]!}.token`), 'utf8').catch(() => '')
        if (retainedToken === 'fixture-token-3') break
      }
      await sleep(25)
    }
    expect(retainedToken).toBe('fixture-token-3')
  })

  it('keeps a refreshed fallback child alive until a committed response finishes', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const composition = await loadComposition({
      mode: 'token',
      tokenRef: 'TOKEN_A',
      publicHostname: 'gui.example.com',
      gatePort,
      allowRemoteSettings: true,
      executable: await fixtureExecutable('fake-cloudflared-token-rotated-crash.sh'),
      startupTimeoutMs: 15_000,
    }, { seeds: { TOKEN_A: 'fixture-token-1', TOKEN_B: 'fixture-token-2' } })
    composition.settings().register(settingsNamespace('locale'), z.object({
      preference: z.union(['zh', 'en']).required(false),
    }))
    const originalPid = (await liveFixturePids())[0]!
    const base = `http://127.0.0.1:${String(gatePort)}`
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const originalEnd = ServerResponse.prototype.end
    let releaseResponse = (): void => {}
    let markResponseHeld = (): void => {}
    const responseHeld = new Promise<void>((resolve) => { markResponseHeld = resolve })
    let held = false
    vi.spyOn(ServerResponse.prototype, 'end').mockImplementation((function (
      this: ServerResponse,
      ...args: unknown[]
    ): ServerResponse {
      if (!held && this.req.url === '/dsh-auth-tunnel/locale') {
        held = true
        releaseResponse = () => { Reflect.apply(originalEnd, this, args) }
        markResponseHeld()
        return this
      }
      return Reflect.apply(originalEnd, this, args) as ServerResponse
    }) as typeof ServerResponse.prototype.end)

    const responseTask = fetch(`${base}/dsh-auth-tunnel/locale`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ locale: 'en' }),
    }).catch(() => undefined)
    await responseHeld
    let released = false
    try {
      const before = await composition.runtimeStatus()
      await composition.settings().update(namespace, { tokenRef: 'TOKEN_B' })
      await waitForStatus(
        composition,
        status => status.revision > before.revision && status.phase === 'running',
        5000,
      )
      composition.credentials().set('TOKEN_A', 'fixture-token-3')

      const refreshDeadline = Date.now() + 7000
      let refreshedPid: string | undefined
      while (refreshedPid === undefined) {
        for (const pid of await liveFixturePids()) {
          const token = await readFile(join(tmpdir(), `${FAKE_PREFIX}${pid}.token`), 'utf8').catch(() => '')
          if (pid !== originalPid && token === 'fixture-token-3') refreshedPid = pid
        }
        if (Date.now() >= refreshDeadline) throw new Error('rotated fallback child did not start')
        if (refreshedPid === undefined) await sleep(25)
      }

      await sleep(3700)
      expect(await liveFixturePids()).toContain(originalPid)
      releaseResponse()
      released = true
      expect((await responseTask)?.status).toBe(200)
      const retiredDeadline = Date.now() + 5000
      while ((await liveFixturePids()).includes(originalPid)) {
        if (Date.now() >= retiredDeadline) throw new Error('refreshed fallback child did not retire its predecessor')
        await sleep(25)
      }
    } finally {
      if (!released) releaseResponse()
    }
  })

  it('starts and stops the gate and cloudflared from the live enabled switch', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ enabled: false })
    expect(await composition.runtimeStatus()).toMatchObject({ phase: 'stopped', running: false })
    expect(await liveFixturePids()).toEqual([])

    await composition.settings().update(namespace, { enabled: true })
    const running = await waitForStatus(composition, status => status.phase === 'running')
    expect(running.publicUrl).toBe(QUICK_URL)
    const firstGate = await composition.gateBase()
    expect((await fetch(`${firstGate}/dsh-auth-tunnel/login`)).status).toBe(200)
    expect(composition.shellEnv().contributors).toHaveLength(1)
    expect(composition.systemPrompt().sections).toHaveLength(1)

    await composition.settings().update(namespace, { enabled: false })
    await waitForStatus(composition, status => status.phase === 'stopped')
    expect(await liveFixturePids()).toEqual([])
    expect(composition.shellEnv().contributors).toEqual([])
    expect(composition.systemPrompt().sections).toEqual([])
    await expect(fetch(`${firstGate}/dsh-auth-tunnel/login`)).rejects.toThrow()

    await composition.settings().update(namespace, { enabled: true })
    await waitForStatus(composition, status => status.phase === 'running')
    expect((await liveFixturePids()).length).toBe(1)
    expect((await fetch(`${await composition.gateBase()}/dsh-auth-tunnel/login`)).status).toBe(200)
  })

  it('restores a live gate when a pending disable is immediately superseded', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    composition.loaded.webServer.register({
      kind: 'exact', path: '/api/re-enabled', handler: (_req, res) => {
        res.writeHead(200)
        res.end('ok')
      },
    })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    const originalPids = await liveFixturePids()
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { enabled: false })
    expect(await composition.runtimeStatus()).toMatchObject({ phase: 'applying', running: false })
    expect(composition.shellEnv().contributors).toEqual([])
    expect(composition.systemPrompt().sections).toEqual([])
    await composition.settings().update(namespace, { enabled: true })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running' && status.running,
    )

    expect((await fetch(`${base}/api/re-enabled`, { headers: { cookie } })).status).toBe(200)
    expect(await liveFixturePids()).toEqual(originalPids)
    expect(composition.shellEnv().contributors).toHaveLength(1)
    expect(composition.systemPrompt().sections).toHaveLength(1)
  })

  it('disables the active tunnel while password validation is stalled', { timeout: 60_000 }, async () => {
    const composition = await bootQuick(undefined, {
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const base = await composition.gateBase()
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'ALT_WEB_PASSWORD'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'ALT_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }

    await composition.settings().update(namespace, { passwordRef: 'ALT_WEB_PASSWORD' })
    await resolveStarted
    try {
      const startedAt = Date.now()
      await composition.settings().update(namespace, { enabled: false })
      await waitForStatus(composition, status => status.phase === 'stopped' && !status.running, 3000)

      expect(Date.now() - startedAt).toBeLessThan(3000)
      expect(await liveFixturePids()).toEqual([])
      await expect(fetch(`${base}/dsh-auth-tunnel/login`)).rejects.toThrow()
    } finally {
      composition.credentials().resolveBarrier = undefined
      composition.credentials().resolveBarrierRef = undefined
      releaseResolve()
    }
  })

  it('supersedes a stalled enabled password check with the latest enabled reference', { timeout: 60_000 }, async () => {
    const composition = await bootQuick(undefined, {
      seeds: {
        ALT_WEB_PASSWORD: 'alternate-password',
        NEXT_WEB_PASSWORD: 'next-password',
      },
    })
    const base = await composition.gateBase()
    const before = await composition.runtimeStatus()
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'ALT_WEB_PASSWORD'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'ALT_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }

    await composition.settings().update(namespace, { passwordRef: 'ALT_WEB_PASSWORD' })
    await resolveStarted
    try {
      await composition.settings().update(namespace, { passwordRef: 'NEXT_WEB_PASSWORD' })
      await waitForStatus(
        composition,
        status => status.revision > before.revision && status.phase === 'running' && status.running,
        3000,
      )
      await login(base, undefined, 'next-password')
    } finally {
      composition.credentials().resolveBarrier = undefined
      composition.credentials().resolveBarrierRef = undefined
      releaseResolve()
    }
  })

  it('disables the active tunnel while tunnel-token resolution is stalled', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const tokenExecutable = await fixtureExecutable('fake-cloudflared-token.sh')
    const composition = await bootQuick({ gatePort }, {
      seeds: { DSH_TUNNEL_TOKEN: 'fixture-token' },
    })
    const base = await composition.gateBase()
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'DSH_TUNNEL_TOKEN'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'DSH_TUNNEL_TOKEN') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }

    await composition.settings().update(namespace, {
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      executable: tokenExecutable,
    })
    await resolveStarted
    try {
      const startedAt = Date.now()
      await composition.settings().update(namespace, { enabled: false })
      await waitForStatus(composition, status => status.phase === 'stopped' && !status.running, 3000)

      expect(Date.now() - startedAt).toBeLessThan(3000)
      expect(await liveFixturePids()).toEqual([])
      await expect(fetch(`${base}/dsh-auth-tunnel/login`)).rejects.toThrow()
    } finally {
      composition.credentials().resolveBarrier = undefined
      composition.credentials().resolveBarrierRef = undefined
      releaseResolve()
    }
  })

  it('supersedes a stalled enabled token startup with the latest enabled target', { timeout: 60_000 }, async () => {
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const gatePort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const tokenExecutable = await fixtureExecutable('fake-cloudflared-token-recording.sh')
    const composition = await bootQuick(undefined, {
      seeds: { TOKEN_A: 'fixture-token-a', TOKEN_B: 'fixture-token-b' },
    })
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'TOKEN_A'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'TOKEN_A') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }

    await composition.settings().update(namespace, {
      mode: 'token',
      tokenRef: 'TOKEN_A',
      publicHostname: 'gui.example.com',
      gatePort,
      executable: tokenExecutable,
    })
    await resolveStarted
    await composition.settings().update(namespace, { tokenRef: 'TOKEN_B' })
    try {
      const deadline = Date.now() + 3000
      let applied = false
      while (Date.now() < deadline) {
        for (const pid of await liveFixturePids()) {
          const token = await readFile(join(tmpdir(), `${FAKE_PREFIX}${pid}.token`), 'utf8').catch(() => '')
          if (token === 'fixture-token-b') applied = true
        }
        if (applied) break
        await sleep(25)
      }
      expect(applied).toBe(true)
    } finally {
      composition.credentials().resolveBarrier = undefined
      composition.credentials().resolveBarrierRef = undefined
      releaseResolve()
    }
  })

  it('restarts a staged startup when its timeout changes', { timeout: 60_000 }, async () => {
    const silentExecutable = await fixtureExecutable('fake-cloudflared-silent.sh')
    const composition = await bootQuick({ startupTimeoutMs: 10_000 })
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { executable: silentExecutable })
    const childDeadline = Date.now() + 5000
    while ((await liveFixturePids()).length < 2) {
      if (Date.now() >= childDeadline) throw new Error('staged cloudflared did not start')
      await sleep(25)
    }

    await composition.settings().update(namespace, { startupTimeoutMs: 50 })
    const failed = await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'error' && status.running,
      3000,
    )
    expect(failed.message).toContain('produced no public URL')
    expect(await liveFixturePids()).toHaveLength(1)
  })

  it('keeps the previous public path alive for the runtime-status handoff', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    const previousGate = await composition.gateBase()
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const before = await composition.runtimeStatus()

    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    expect((await fetch(`${previousGate}/dsh-auth-tunnel/status`, { headers: { cookie } })).status).toBe(200)
    expect((await fetch(`http://127.0.0.1:${String(nextPort)}/dsh-auth-tunnel/login`)).status).toBe(200)

    await sleep(3000)
    expect((await fetch(`${previousGate}/dsh-auth-tunnel/status`, { headers: { cookie } })).status).toBe(200)
    await sleep(700)
    await expect(fetch(`${previousGate}/dsh-auth-tunnel/status`, { headers: { cookie } })).rejects.toThrow()
  })

  it('revokes the old credential on the previous gate during a port handoff', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const previousGate = await composition.gateBase()
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, {
      gatePort: nextPort,
      passwordRef: 'ALT_WEB_PASSWORD',
    })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )

    const response = await fetch(`${previousGate}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ writes: [], password: 'overwritten-password' }),
    })
    expect(response.status).toBe(401)
    expect(await composition.credentials().resolve('ALT_WEB_PASSWORD'))
      .toMatchObject({ value: 'alternate-password' })
  })

  it('switches every live gate to a newly committed password reference immediately', { timeout: 60_000 }, async () => {
    const composition = await bootQuick(undefined, {
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const previousGate = await composition.gateBase()
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    expect(await liveFixturePids()).toHaveLength(2)

    await composition.settings().update(namespace, { passwordRef: 'ALT_WEB_PASSWORD' })

    expect((await fetch(`${previousGate}/dsh-auth-tunnel/status`, { headers: { cookie } })).status).toBe(401)
    expect((await fetch(`http://127.0.0.1:${String(nextPort)}/dsh-auth-tunnel/status`, {
      headers: { cookie },
    })).status).toBe(401)
    await login(previousGate, undefined, 'alternate-password')
    await login(`http://127.0.0.1:${String(nextPort)}`, undefined, 'alternate-password')
  })

  it('applies a reduced session lifetime to every live gate during a port handoff', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    const previousGate = await composition.gateBase()
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    expect(await liveFixturePids()).toHaveLength(2)

    await composition.settings().update(namespace, { sessionTtlHours: 1 })

    expect((await login(previousGate)).get('set-cookie')).toContain('Max-Age=3600')
    expect((await login(`http://127.0.0.1:${String(nextPort)}`)).get('set-cookie')).toContain('Max-Age=3600')
  })

  it('serializes password rotations across both gates during a port handoff', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const previousGate = await composition.gateBase()
    const previousPort = Number(new URL(previousGate).port)
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    const opened = await (await fetch(`http://127.0.0.1:${String(nextPort)}/dsh-auth-tunnel/settings`, {
      headers: { cookie },
    })).json() as { settings: { revision: number } }
    const request = (password: string) => ({
      expectedRevision: opened.settings.revision,
      writes: [],
      password,
    })
    const finishPrevious = await beginJsonPost(previousPort, '/dsh-auth-tunnel/settings', cookie, request('first-password'))
    const finishCandidate = await beginJsonPost(nextPort, '/dsh-auth-tunnel/settings', cookie, request('second-password'))
    await sleep(50)
    let releaseResolves = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolves = resolve })

    const responsesTask = Promise.all([finishPrevious(), finishCandidate()])
    await sleep(50)
    releaseResolves()
    const responses = await responsesTask

    expect(responses.filter(response => response.includes(' 200 '))).toHaveLength(1)
    expect(responses.filter(response => response.includes(' 409 '))).toHaveLength(1)
  })

  it('detaches a previous gate pre-commit save when a port handoff retires it', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true }, {
      seeds: { NEXT_WEB_PASSWORD: 'next-password' },
    })
    const previousGate = await composition.gateBase()
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const opened = await (await fetch(`${previousGate}/dsh-auth-tunnel/settings`, {
      headers: { cookie },
    })).json() as { settings: { revision: number } }
    let releaseResolve = (): void => {}
    composition.credentials().resolveBarrier = new Promise<void>((resolve) => { releaseResolve = resolve })
    composition.credentials().resolveBarrierRef = 'NEXT_WEB_PASSWORD'
    let markResolveStarted = (): void => {}
    const resolveStarted = new Promise<void>((resolve) => { markResolveStarted = resolve })
    composition.credentials().resolveStarted = (ref) => {
      if (ref !== 'NEXT_WEB_PASSWORD') return
      composition.credentials().resolveStarted = undefined
      markResolveStarted()
    }
    const staleTask = fetch(`${previousGate}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
        password: '',
      }),
    }).catch(() => undefined)
    await resolveStarted

    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()
    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    await sleep(3700)

    const nextGate = `http://127.0.0.1:${String(nextPort)}`
    const nextCookie = (await login(nextGate)).get('set-cookie')!.split(';', 1)[0]!
    const nextOpened = await (await fetch(`${nextGate}/dsh-auth-tunnel/settings`, {
      headers: { cookie: nextCookie },
    })).json() as { settings: { revision: number } }
    const freshSave = fetch(`${nextGate}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie: nextCookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: nextOpened.settings.revision,
        writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
        password: '',
      }),
    })
    try {
      const outcome = await Promise.race([
        freshSave,
        sleep(3000).then(() => undefined),
      ])
      expect(outcome?.status).toBe(200)
    } finally {
      composition.credentials().resolveBarrier = undefined
      composition.credentials().resolveBarrierRef = undefined
      releaseResolve()
    }
    await staleTask
    expect(composition.settings().get(namespace)).toMatchObject({
      passwordRef: 'DSH_WEB_PASSWORD',
      sessionTtlHours: 24,
    })
  })

  it('interrupts an adopted port handoff when the tunnel is disabled', { timeout: 60_000 }, async () => {
    const composition = await bootQuick()
    const previousGate = await composition.gateBase()
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    expect(await liveFixturePids()).toHaveLength(2)

    const startedAt = Date.now()
    await composition.settings().update(namespace, { enabled: false })
    await waitForStatus(composition, status => status.phase === 'stopped', 3000)

    expect(Date.now() - startedAt).toBeLessThan(3000)
    expect(await liveFixturePids()).toEqual([])
    await expect(fetch(`${previousGate}/dsh-auth-tunnel/login`)).rejects.toThrow()
    await expect(fetch(`http://127.0.0.1:${String(nextPort)}/dsh-auth-tunnel/login`)).rejects.toThrow()
  })

  it('returns a remote disable response before interrupting a port handoff', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const previousGate = await composition.gateBase()
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    const opened = await (await fetch(`${previousGate}/dsh-auth-tunnel/settings`, {
      headers: { cookie },
    })).json() as { settings: { revision: number } }

    const response = await fetch(`${previousGate}/dsh-auth-tunnel/settings`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({
        expectedRevision: opened.settings.revision,
        writes: [{ field: 'enabled', op: 'set', value: false }],
        password: '',
      }),
    })

    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ settings: { value: { enabled: false } } })
    await waitForStatus(composition, status => status.phase === 'stopped' && !status.running, 3000)
    expect(await liveFixturePids()).toEqual([])
  })

  it('revokes remote settings on every gate retained during a port handoff', { timeout: 60_000 }, async () => {
    const composition = await bootQuick({ allowRemoteSettings: true })
    const previousGate = await composition.gateBase()
    const cookie = (await login(previousGate)).get('set-cookie')!.split(';', 1)[0]!
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')
    const before = await composition.runtimeStatus()

    await composition.settings().update(namespace, { gatePort: nextPort })
    await waitForStatus(
      composition,
      status => status.revision > before.revision && status.phase === 'running',
    )
    expect(await liveFixturePids()).toHaveLength(2)

    await composition.settings().update(namespace, { allowRemoteSettings: false })

    expect((await fetch(`${previousGate}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(403)
    expect((await fetch(`http://127.0.0.1:${String(nextPort)}/dsh-auth-tunnel/settings`, {
      headers: { cookie },
    })).status).toBe(403)
  })

  it('keeps the old tunnel when a live process rebuild fails', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const silentExecutable = await fixtureExecutable('fake-cloudflared-silent.sh')
    const composition = await loadComposition({
      mode: 'quick',
      executable: quickExecutable,
      startupTimeoutMs: 15_000,
    })
    const base = await composition.gateBase()
    const originalPids = await liveFixturePids()
    expect(originalPids).toHaveLength(1)

    await composition.settings().update(namespace, { startupTimeoutMs: 50 })
    await composition.settings().update(namespace, { executable: silentExecutable })
    const failed = await waitForStatus(composition, status => status.phase === 'error', 7000)
    expect(failed).toMatchObject({ running: true, publicUrl: QUICK_URL })
    expect(failed.message).toContain('produced no public URL')
    expect(await liveFixturePids()).toEqual(originalPids)
    expect((await fetch(`${base}/dsh-auth-tunnel/login`)).status).toBe(200)
    expect(composition.shellEnv().contributors[0]?.resolve().DSH_PUBLIC_URL).toBe(QUICK_URL)

    await composition.settings().update(namespace, { executable: quickExecutable })
    await waitForStatus(composition, status => status.phase === 'running')
  })

  it('revokes remote settings on the old gate before a replacement can fail', { timeout: 60_000 }, async () => {
    const silentExecutable = await fixtureExecutable('fake-cloudflared-silent.sh')
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!
    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(200)

    await composition.settings().update(namespace, {
      allowRemoteSettings: false,
      executable: silentExecutable,
      startupTimeoutMs: 50,
    })
    const failed = await waitForStatus(composition, status => status.phase === 'error', 7000)

    expect(failed).toMatchObject({ running: true, publicUrl: QUICK_URL })
    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(403)
  })

  it('keeps a concurrent remote-settings revocation when a handoff rolls back', { timeout: 60_000 }, async () => {
    const crashingExecutable = await fixtureExecutable('fake-cloudflared-ready-crash.sh')
    const composition = await bootQuick({ allowRemoteSettings: true })
    const base = await composition.gateBase()
    const cookie = (await login(base)).get('set-cookie')!.split(';', 1)[0]!

    await composition.settings().update(namespace, { executable: crashingExecutable })
    await waitForStatus(
      composition,
      status => status.phase === 'running' && status.publicUrl?.includes('ready-then-crash') === true,
    )
    await composition.settings().update(namespace, { allowRemoteSettings: false })
    const restored = await waitForStatus(
      composition,
      status => status.phase === 'error' && status.running && status.publicUrl === QUICK_URL,
      7000,
    )

    expect(restored.message).toContain('kept the previous public URL')
    expect((await fetch(`${base}/dsh-auth-tunnel/settings`, { headers: { cookie } })).status).toBe(403)
  })

  it('keeps the candidate password policy when a tunnel handoff rolls back', { timeout: 60_000 }, async () => {
    const crashingExecutable = await fixtureExecutable('fake-cloudflared-ready-crash.sh')
    const composition = await bootQuick(undefined, {
      seeds: { ALT_WEB_PASSWORD: 'alternate-password' },
    })
    const base = await composition.gateBase()

    await composition.settings().update(namespace, {
      passwordRef: 'ALT_WEB_PASSWORD',
      executable: crashingExecutable,
    })
    await waitForStatus(
      composition,
      status => status.phase === 'error' && status.running && status.publicUrl === QUICK_URL,
      7000,
    )

    const oldPassword = await fetch(`${base}/dsh-auth-tunnel/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=s3kret-passw0rd',
    })
    expect(oldPassword.headers.get('location')).toBe('/dsh-auth-tunnel/login?error=1')
    await login(base, undefined, 'alternate-password')
  })

  it('restores the previous tunnel when a ready replacement dies during handoff', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const crashingExecutable = await fixtureExecutable('fake-cloudflared-ready-crash.sh')
    const composition = await bootQuick({ executable: quickExecutable })
    const base = await composition.gateBase()
    const originalPids = await liveFixturePids()

    await composition.settings().update(namespace, { executable: crashingExecutable })
    const recovered = await waitForStatus(
      composition,
      status => status.phase === 'error' && status.running,
      7000,
    )

    expect(recovered.publicUrl).toBe(QUICK_URL)
    expect(recovered.message).toContain('kept the previous public URL')
    expect(await liveFixturePids()).toEqual(originalPids)
    expect((await fetch(`${base}/dsh-auth-tunnel/login`)).status).toBe(200)
    expect(composition.shellEnv().contributors[0]?.resolve().DSH_PUBLIC_URL).toBe(QUICK_URL)
  })

  it('rebuilds the gate after both sides of a gate-port handoff die', { timeout: 60_000 }, async () => {
    const quickExecutable = await fixtureExecutable('fake-cloudflared-quick.sh')
    const crashingExecutable = await fixtureExecutable('fake-cloudflared-ready-crash.sh')
    const composition = await bootQuick({ executable: quickExecutable })
    const [previousPid] = await liveFixturePids()
    const probeServer = createNetServer()
    probeServer.listen(0, '127.0.0.1')
    await once(probeServer, 'listening')
    const nextPort = (probeServer.address() as AddressInfo).port
    probeServer.close()
    await once(probeServer, 'close')

    await composition.settings().update(namespace, {
      gatePort: nextPort,
      executable: crashingExecutable,
    })
    await waitForStatus(
      composition,
      status => status.phase === 'running' && status.publicUrl?.includes('ready-then-crash') === true,
    )
    process.kill(Number(previousPid), 'SIGTERM')
    const failed = await waitForStatus(
      composition,
      status => status.phase === 'error' && !status.running,
      7000,
    )
    const stoppedDeadline = Date.now() + 6000
    while ((await liveFixturePids()).length !== 0) {
      if (Date.now() >= stoppedDeadline) throw new Error('failed gate handoff did not stop both tunnels')
      await sleep(25)
    }

    await composition.settings().update(namespace, { executable: quickExecutable })
    await waitForStatus(
      composition,
      status => status.revision > failed.revision && status.phase === 'running',
      7000,
    )
    expect((await fetch(`http://127.0.0.1:${String(nextPort)}/dsh-auth-tunnel/login`)).status).toBe(200)
  })

  it('waits safely when no settings provider is mounted', { timeout: 60_000 }, async () => {
    const composition = await bootQuick(undefined, { withSettings: false })
    expect(composition.loaded.get('settings')).toBeUndefined()
    const tunnel = [...composition.loaded.loader.entries()]
      .find(entry => entry.options.name === 'dsh-auth-tunnel')
    expect(tunnel?.fiber?.state).toBe(0)
    expect(await liveFixturePids()).toEqual([])
  })

  it('loads delayed persisted settings before opening public access', { timeout: 60_000 }, async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const composition = await bootQuick(undefined, {
      settingsAfterTunnel: true,
      settingsDocument: { 'auth-tunnel': { enabled: false } },
    })

    expect(composition.settings().get(namespace)).toMatchObject({ enabled: false })
    expect(await composition.runtimeStatus()).toMatchObject({ phase: 'stopped', running: false })
    expect(await liveFixturePids()).toEqual([])
    expect(consoleSpy).not.toHaveBeenCalledWith(expect.stringContaining('cloudflare tunnel:'))
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
      "      name: 'dsh-auth-tunnel'",
      '      config:',
      '        enabled: true',
    ].join('\n'))
    expect(patch).not.toMatch(/^- id: auth-tunnel$/m)
  })
})
