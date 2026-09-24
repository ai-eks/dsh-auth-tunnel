import { readFileSync } from 'node:fs'
import * as cordis from '@deepseek-ai/cordis'
import type { ConnectionHandle } from '@deepseek-ai/dsh-api-remotes/client'
import { describe, expect, it, vi } from 'vitest'
import {
  apply, changeDraftField, commitCardChanges, commitCredentialWrite, commitSettingsWrites,
  installRemoteLocalePersistence, parseDraft, parseRemoteSettingsDocument, RemoteSettingsStore,
  promoteTunnelConnection, RuntimeStatusStore, runtimeStatusLocaleKey, validateSettingsValues,
  type AuthTunnelSettings, type RuntimeStatusSnapshot, type SettingsWrite,
} from '../src/client/index.tsx'

const quick: AuthTunnelSettings = {
  enabled: true,
  allowRemoteSettings: true,
  passwordRef: 'DSH_WEB_PASSWORD',
  sessionTtlHours: 720,
  mode: 'quick',
  gatePort: 0,
  executable: 'cloudflared',
  startupTimeoutMs: 15_000,
}

function remoteDocument(revision: number, overrides: Partial<AuthTunnelSettings> = {}, locale?: 'zh' | 'en') {
  const value = { ...quick, allowRemoteSettings: true, ...overrides }
  return parseRemoteSettingsDocument({
    settings: {
      value,
      base: quick,
      user: { allowRemoteSettings: true, ...overrides },
      revision,
      writable: true,
    },
    ...(locale === undefined ? {} : { locale }),
  })
}

function cardApi(options: { configured?: readonly string[]; credentialError?: string } = {}) {
  const mutate = vi.fn(() => Promise.resolve({
    ok: true as const,
    value: {
      ns: 'auth-tunnel', schema: {}, value: quick, user: {}, applies: 'live' as const,
      secrets: [], revision: 8,
    },
  }))
  const describe = vi.fn((refs: string[]) => Promise.resolve({
    ok: true as const,
    value: Object.fromEntries(refs.map(ref => [ref, {
      configured: options.configured?.includes(ref) === true,
      writable: true,
    }])),
  }))
  const set = vi.fn(() => Promise.resolve(options.credentialError === undefined
    ? { ok: true as const, value: undefined }
    : {
        ok: false as const, error: { code: 'credential-rejected', message: options.credentialError },
      }))
  return {
    api: { settings: { mutate }, credentials: { describe, set } } as never,
    mutate,
    describe,
    set,
  }
}

describe('auth-tunnel settings card contract', () => {
  it('validates token-only requirements before saving', () => {
    expect(validateSettingsValues(quick)).toEqual({})
    expect(validateSettingsValues({ ...quick, mode: 'token' })).toEqual({
      tokenRef: 'tokenRefRequired',
      publicHostname: 'hostnameRequired',
      gatePort: 'fixedPortRequired',
    })
    expect(validateSettingsValues({ ...quick, enabled: false, mode: 'token' })).toEqual({})
    expect(validateSettingsValues({
      ...quick,
      mode: 'token',
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort: 32_309,
    })).toEqual({})
    expect(validateSettingsValues({ ...quick, sessionTtlHours: 3_000_000_000 })).toEqual({
      sessionTtlHours: 'invalidNumber',
    })
  })

  it('preserves nonempty Token fields when an edited draft switches to Quick', () => {
    const switched = changeDraftField({
      values: {
        enabled: 'true',
        allowRemoteSettings: 'false',
        passwordRef: 'DSH_WEB_PASSWORD',
        sessionTtlHours: '720',
        mode: 'token',
        tokenRef: 'NEXT_TUNNEL_TOKEN',
        publicHostname: 'next.example.com',
        gatePort: '0',
        executable: 'cloudflared',
        startupTimeoutMs: '15000',
      },
      edits: { mode: 'set', tokenRef: 'set', publicHostname: 'set' },
      password: '',
      token: 'unsaved-token',
    }, 'mode', 'quick', 'set')
    const target = parseDraft(switched)

    expect(target).toMatchObject({
      mode: 'quick',
      tokenRef: 'NEXT_TUNNEL_TOKEN',
      publicHostname: 'next.example.com',
    })
    expect(validateSettingsValues(target)).toEqual({})
    expect(switched.token).toBe('')
  })

  it.each([
    { operation: 'selecting Quick', action: 'set' as const },
    { operation: 'resetting a saved Token override', action: 'unset' as const },
    { operation: 'resetting an unsaved Token selection', action: undefined },
  ])('keeps an invalid hostname correctable when $operation', ({ action }) => {
    const switched = changeDraftField({
      values: {
        enabled: 'true', allowRemoteSettings: 'true', passwordRef: 'DSH_WEB_PASSWORD',
        sessionTtlHours: '720', mode: 'token', tokenRef: 'DSH_TUNNEL_TOKEN',
        publicHostname: 'not a hostname', gatePort: '0', executable: 'cloudflared',
        startupTimeoutMs: '15000',
      },
      edits: { mode: 'set', publicHostname: 'set' },
      password: '', token: 'unsaved-token',
    }, 'mode', 'quick', action)

    expect(switched.values.publicHostname).toBe('not a hostname')
    expect(switched.edits.publicHostname).toBe('set')
    expect(switched.edits.mode).toBe(action)
    expect(switched.token).toBe('')
    expect(validateSettingsValues(parseDraft(switched))).toEqual({ publicHostname: 'invalidHostname' })

    const corrected = changeDraftField(switched, 'publicHostname', 'next.example.com', 'set')
    expect(validateSettingsValues(parseDraft(corrected))).toEqual({})
  })

  it('commits configuration as one revision-fenced settings mutation', async () => {
    const { api, mutate } = cardApi()
    const writes: SettingsWrite[] = [
      { field: 'enabled', op: 'set', value: false },
      { field: 'mode', op: 'set', value: 'token' },
      { field: 'tokenRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' },
    ]

    await commitCardChanges(api, 7, writes, quick, {
      ...quick, enabled: false, mode: 'token', tokenRef: 'DSH_TUNNEL_TOKEN',
    }, '')

    expect(mutate).toHaveBeenCalledOnce()
    expect(mutate).toHaveBeenCalledWith(
      'auth-tunnel',
      [
        { op: 'set', path: ['enabled'], value: false },
        { op: 'set', path: ['mode'], value: 'token' },
        { op: 'set', path: ['tokenRef'], value: 'DSH_TUNNEL_TOKEN' },
      ],
      7,
    )
  })

  it('writes a password only to the current credential', async () => {
    const { api, mutate, describe, set } = cardApi()

    await commitCardChanges(api, 7, [], quick, quick, '  replacement password  ')

    expect(set).toHaveBeenCalledWith('DSH_WEB_PASSWORD', '  replacement password  ')
    expect(mutate).not.toHaveBeenCalled()
    expect(describe).not.toHaveBeenCalled()
  })

  it('writes a directly entered Tunnel Token to credentials before saving its settings', async () => {
    const { api, mutate, set } = cardApi()
    const target = {
      ...quick,
      mode: 'token' as const,
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort: 7677,
    }
    const writes: SettingsWrite[] = [
      { field: 'mode', op: 'set', value: 'token' },
      { field: 'publicHostname', op: 'set', value: 'gui.example.com' },
      { field: 'gatePort', op: 'set', value: 7677 },
    ]

    await commitCardChanges(api, 7, writes, quick, target, '', 'direct-tunnel-token')

    expect(set).toHaveBeenCalledWith('DSH_TUNNEL_TOKEN', 'direct-tunnel-token')
    expect(set.mock.invocationCallOrder[0]).toBeLessThan(mutate.mock.invocationCallOrder[0]!)
    expect(mutate).toHaveBeenCalledWith(
      'auth-tunnel',
      expect.not.arrayContaining([
        expect.objectContaining({ value: 'direct-tunnel-token' }),
      ]),
      7,
    )
  })

  it('allows rotating only the directly entered Tunnel Token', async () => {
    const { api, mutate, set } = cardApi()
    const token = {
      ...quick,
      mode: 'token' as const,
      tokenRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort: 7677,
    }

    await commitCardChanges(api, 7, [], token, token, '', 'replacement-token')

    expect(set).toHaveBeenCalledWith('DSH_TUNNEL_TOKEN', 'replacement-token')
    expect(mutate).not.toHaveBeenCalled()
  })

  it('rejects combined password and configuration changes before either write', async () => {
    const { api, mutate, set } = cardApi()

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      quick,
      { ...quick, sessionTtlHours: 24 },
      'replacement',
    )).rejects.toThrow('must be saved separately')

    expect(mutate).not.toHaveBeenCalled()
    expect(set).not.toHaveBeenCalled()
  })

  it('preflights a new password reference before committing configuration', async () => {
    const { api, describe, mutate } = cardApi({ configured: ['NEXT_PASSWORD'] })

    await commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'NEXT_PASSWORD' },
      '',
    )

    expect(describe).toHaveBeenCalledWith(['NEXT_PASSWORD'])
    expect(mutate).toHaveBeenCalledOnce()
  })

  it('reports a missing new password reference without compensating writes', async () => {
    const { api, mutate } = cardApi()

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'MISSING_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'MISSING_PASSWORD' },
      '',
    )).rejects.toThrow('not configured')

    expect(mutate).not.toHaveBeenCalled()
  })

  it('rejects oversized passwords and token credential collisions', async () => {
    const { api, mutate, set } = cardApi({ configured: ['DSH_TUNNEL_TOKEN'] })
    await expect(commitCardChanges(api, 7, [], quick, quick, 'x'.repeat(16 * 1024)))
      .rejects.toThrow('too long')
    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' }],
      { ...quick, mode: 'token', tokenRef: 'DSH_TUNNEL_TOKEN', publicHostname: 'gui.example.com', gatePort: 7677 },
      { ...quick, mode: 'token', passwordRef: 'DSH_TUNNEL_TOKEN', tokenRef: 'DSH_TUNNEL_TOKEN', publicHostname: 'gui.example.com', gatePort: 7677 },
      '',
    )).rejects.toThrow('conflicts')
    expect(mutate).not.toHaveBeenCalled()
    expect(set).not.toHaveBeenCalled()
  })

  it('surfaces rejected credential and settings writes directly', async () => {
    const rejectedCredential = cardApi({ credentialError: 'credential store is read only' })
    await expect(commitCredentialWrite(
      rejectedCredential.api,
      'DSH_WEB_PASSWORD',
      'replacement',
    )).rejects.toThrow('read only')

    const mutate = vi.fn(() => Promise.resolve({
      ok: false as const, error: { code: 'revision-conflict', message: 'settings revision changed' },
    }))
    await expect(commitSettingsWrites(
      { settings: { mutate } } as never,
      7,
      [{ field: 'enabled', op: 'set', value: false }],
    )).rejects.toThrow('revision changed')
  })

  it('parses only complete browser-safe remote documents', () => {
    expect(remoteDocument(3, { sessionTtlHours: 24 }, 'en')).toMatchObject({
      locale: 'en',
      snapshot: { status: 'ready', revision: 3, value: { sessionTtlHours: 24 } },
    })
    expect(() => parseRemoteSettingsDocument({
      settings: { value: { ...quick, enabled: 'yes' }, revision: 3, writable: true },
    })).toThrow('invalid auth-tunnel settings document')
  })

  it('loads and commits the authenticated remote scope', async () => {
    const read = vi.fn(() => Promise.resolve(remoteDocument(3)))
    const commit = vi.fn(() => Promise.resolve(remoteDocument(4, { sessionTtlHours: 24 })))
    const store = new RemoteSettingsStore({ read, commit })
    let notifications = 0
    const unsubscribe = store.subscribe(() => { notifications += 1 })

    await store.refresh()
    await store.commit({
      expectedRevision: 3,
      writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      password: '',
      token: '',
    })

    expect(read).toHaveBeenCalledOnce()
    expect(commit).toHaveBeenCalledOnce()
    expect(store.getSnapshot()).toMatchObject({ revision: 4, value: { sessionTtlHours: 24 } })
    expect(notifications).toBe(2)
    unsubscribe()
    store.dispose()
  })

  it('does not let a read started before a commit overwrite the committed document', async () => {
    let resolveRead = (_document: ReturnType<typeof remoteDocument>): void => {}
    const pendingRead = new Promise<ReturnType<typeof remoteDocument>>((resolve) => { resolveRead = resolve })
    const store = new RemoteSettingsStore({
      read: vi.fn(() => pendingRead),
      commit: vi.fn(() => Promise.resolve(remoteDocument(4, { sessionTtlHours: 24 }))),
    })

    const readTask = store.refresh()
    await store.commit({ expectedRevision: 3, writes: [], password: 'replacement', token: '' })
    resolveRead(remoteDocument(3))
    await readTask

    expect(store.getSnapshot()).toMatchObject({ revision: 4, value: { sessionTtlHours: 24 } })
    store.dispose()
  })

  it('marks revoked remote access read-only and does not retry failed reads', async () => {
    vi.useFakeTimers()
    try {
      const forbidden = Object.assign(new Error('forbidden'), { status: 403 })
      const read = vi.fn()
        .mockResolvedValueOnce(remoteDocument(3))
        .mockRejectedValue(forbidden)
      const store = new RemoteSettingsStore({ read, commit: vi.fn() })
      const unsubscribe = store.subscribe(() => {})

      await store.refresh()
      await store.refresh()
      expect(store.getSnapshot()).toMatchObject({ status: 'ready', writable: false, revision: 3 })
      await vi.advanceTimersByTimeAsync(10_000)
      expect(read).toHaveBeenCalledTimes(2)

      unsubscribe()
      store.dispose()
    } finally {
      vi.useRealTimers()
    }
  })

  it('refreshes once after a rejected remote commit', async () => {
    const read = vi.fn(() => Promise.resolve(remoteDocument(4, { sessionTtlHours: 24 })))
    const store = new RemoteSettingsStore({
      read,
      commit: vi.fn(() => Promise.reject(new Error('settings revision changed'))),
    })

    await expect(store.commit({ expectedRevision: 3, writes: [], password: '', token: '' }))
      .rejects.toThrow('settings revision changed')
    expect(read).toHaveBeenCalledOnce()
    expect(store.getSnapshot()).toMatchObject({ revision: 4, value: { sessionTtlHours: 24 } })
    store.dispose()
  })

  it('adopts a remote locale and attempts later changes only once', async () => {
    let localeChanged = (_snapshot: { active: string }): void => {}
    const stopLocale = vi.fn()
    const stopStore = vi.fn()
    const setLocale = vi.fn()
    const document = remoteDocument(3, {}, 'en')
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('offline'))
    const ctx = {
      on: (_event: string, listener: typeof localeChanged) => {
        localeChanged = listener
        return stopLocale
      },
      locale: { setLocale },
    }
    const store = {
      getDocument: () => document,
      subscribe: () => stopStore,
    }
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const dispose = installRemoteLocalePersistence(ctx as never, store as never)
    expect(setLocale).toHaveBeenCalledWith('en')
    localeChanged({ active: 'fr' })
    expect(fetch).not.toHaveBeenCalled()
    localeChanged({ active: 'zh' })
    await vi.waitFor(() => { expect(fetch).toHaveBeenCalledOnce() })
    expect(fetch).toHaveBeenCalledWith('/dsh-auth-tunnel/locale', expect.objectContaining({
      body: JSON.stringify({ locale: 'zh' }),
    }))

    dispose()
    expect(stopLocale).toHaveBeenCalledOnce()
    expect(stopStore).toHaveBeenCalledOnce()
    fetch.mockRestore()
    warn.mockRestore()
  })

  it('keeps one failed status poll before publishing unavailable', async () => {
    const running: RuntimeStatusSnapshot = {
      phase: 'running', running: true, revision: 7, publicUrl: 'https://gui.example.com',
    }
    let fail = false
    const store = new RuntimeStatusStore(() => fail
      ? Promise.reject(new Error('offline'))
      : Promise.resolve(running))

    expect(runtimeStatusLocaleKey(store.getSnapshot())).toBe('statusUnavailable')
    await store.refresh()
    expect(store.getSnapshot()).toBe(running)
    fail = true
    await store.refresh()
    expect(store.getSnapshot()).toBe(running)
    await store.refresh()
    expect(store.getSnapshot()).toEqual({ phase: 'unavailable', running: false, revision: 7 })
    expect(runtimeStatusLocaleKey({ phase: 'error', running: true, revision: 8 })).toBe('statusErrorRunning')
    expect(runtimeStatusLocaleKey({ phase: 'error', running: false, revision: 9 })).toBe('statusErrorStopped')
    store.dispose()
  })

  it('registers its browser card on its bundle configuration page', () => {
    let registeredNamespace = ''
    let registeredLocale = ''
    let dictionaryNamespace = ''
    const scope = {
      getSnapshot: () => ({
        status: 'loading' as const,
        value: undefined,
        base: undefined,
        user: undefined,
        revision: undefined,
        writable: false,
        mode: 'host' as const,
      }),
      subscribe: () => () => {},
    }
    const ctx = {
      get: (name: string) => name === 'connection'
        ? { isLoopback: true }
        : undefined,
      remote: { settings: {}, credentials: {} },
      configForms: { get: () => scope },
      inject: (_services: string[], install: (child: unknown) => unknown) => install(ctx),
      effect: (install: () => unknown) => install(),
      locale: {
        register: (namespace: string) => {
          dictionaryNamespace = namespace
          return () => {}
        },
      },
      slots: {
        inject: (_name: string, install: () => unknown) => install(),
        register: (options: { key: string; locale: string }) => {
          registeredNamespace = options.key
          registeredLocale = options.locale
          return () => {}
        },
      },
    }

    apply(ctx as never)
    expect(registeredNamespace).toBe('dsh-auth-tunnel')
    expect(registeredLocale).toBe('settings.auth-tunnel')
    expect(dictionaryNamespace).toBe('settings.auth-tunnel')
  })

  it('promotes only a non-loopback tunnel connection before configuration forms bind', () => {
    const remote = { isLoopback: false } as never
    const unrelatedRemote = { isLoopback: false } as never
    const local = { isLoopback: true } as never

    expect(promoteTunnelConnection(remote, 'other=1; dsh_auth_tunnel_surface=1')).toBe(true)
    expect(remote).toMatchObject({ isLoopback: true })
    expect(promoteTunnelConnection(unrelatedRemote, 'other=1')).toBe(false)
    expect(unrelatedRemote).toMatchObject({ isLoopback: false })
    expect(promoteTunnelConnection(local, 'dsh_auth_tunnel_surface=1')).toBe(false)
    expect(local).toMatchObject({ isLoopback: true })
  })

  it('keeps the Auth Tunnel card on its fenced remote store after promoting the shared connection', () => {
    const bind = vi.fn()
    const connection = { isLoopback: false }
    const child = {
      configForms: { get: bind },
      effect: vi.fn(),
      locale: { register: vi.fn() },
      slots: {
        inject: (_name: string, install: () => unknown) => install(),
        register: vi.fn(() => () => {}),
      },
    }
    const ctx = {
      get: (name: string) => name === 'connection' ? connection : undefined,
      inject: (_services: string[], install: (scope: unknown) => unknown) => {
        expect(connection.isLoopback).toBe(true)
        return install(child)
      },
    }

    vi.stubGlobal('document', { cookie: 'dsh_auth_tunnel_surface=1' })
    try {
      apply(ctx as never)
    } finally {
      vi.unstubAllGlobals()
    }

    expect(bind).not.toHaveBeenCalled()
    expect(child.slots.register).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'plugins.bundle.config', key: 'dsh-auth-tunnel' }),
      expect.any(Function),
    )
  })

  it('updates Host facts already cached by the current Gateway before settings services activate', async () => {
    let gateway: typeof import('@deepseek-ai/dsh-api-gateway/client') | undefined
    const load = ({ factory }: { factory: (require: (name: string) => unknown) => typeof gateway }): void => {
      gateway = factory((name) => {
        if (name !== '@deepseek-ai/cordis') throw new Error(`unexpected Gateway external: ${name}`)
        return cordis
      })
    }
    const source = readFileSync(new URL(import.meta.resolve('@deepseek-ai/dsh-api-gateway/client')), 'utf8')
    new Function('window', source)({ __ModuleLoader__: { load } })
    if (gateway === undefined) throw new Error('Gateway client bundle was not loaded')

    const ctx = new cordis.Context()
    const connection = {
      isLoopback: false,
      generation: { getSnapshot: () => undefined, subscribe: () => () => {} },
      rpc: { call: vi.fn(), open: vi.fn() },
      registerGenerationSource: () => () => {},
      start: () => ({ stop: () => {} }),
    } as unknown as ConnectionHandle
    ctx.provide('connection', connection)
    vi.stubGlobal('document', { cookie: 'dsh_auth_tunnel_surface=1' })
    try {
      await ctx.plugin({ inject: ['connection'], apply: gateway.apply })
      const host = ctx.remote.$host
      expect(host.isLoopback).toBe(false)

      await ctx.plugin({ inject: ['connection'], apply })

      expect(connection.isLoopback).toBe(true)
      expect(ctx.remote.$host).toBe(host)
      expect(ctx.remote.$host.isLoopback).toBe(true)
    } finally {
      await ctx.fiber.dispose()
      vi.unstubAllGlobals()
    }
  })
})
