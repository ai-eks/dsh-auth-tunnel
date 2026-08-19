import { describe, expect, it, vi } from 'vitest'
import {
  apply, commitCardChanges, commitCredentialWrite, commitSettingsWrites,
  installRemoteLocalePersistence, parseRemoteSettingsDocument, RemoteSettingsStore,
  RuntimeStatusStore, runtimeStatusLocaleKey, validateSettingsValues,
  type AuthTunnelSettings, type RuntimeStatusSnapshot, type SettingsWrite,
} from '../src/client/index.tsx'

const quick: AuthTunnelSettings = {
  enabled: true,
  allowRemoteSettings: false,
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
    rpcId: 'test',
    result: {
      ok: true as const,
      value: {
        ns: 'auth-tunnel', schema: {}, value: quick, user: {}, applies: 'live' as const,
        secrets: [], revision: 8,
      },
    },
  }))
  const describe = vi.fn(({ refs }: { refs: string[] }) => Promise.resolve({
    rpcId: 'test',
    result: {
      ok: true as const,
      value: {
        credentials: Object.fromEntries(refs.map(ref => [ref, {
          configured: options.configured?.includes(ref) === true,
          writable: true,
        }])),
      },
    },
  }))
  const set = vi.fn(() => Promise.resolve(options.credentialError === undefined
    ? { rpcId: 'test', result: { ok: true as const, value: {} } }
    : {
        rpcId: 'test',
        result: { ok: false as const, error: { code: 'credential-rejected', message: options.credentialError } },
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
    expect(mutate).toHaveBeenCalledWith({
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [
        { op: 'set', path: ['enabled'], value: false },
        { op: 'set', path: ['mode'], value: 'token' },
        { op: 'set', path: ['tokenRef'], value: 'DSH_TUNNEL_TOKEN' },
      ],
    })
  })

  it('writes a password only to the current credential', async () => {
    const { api, mutate, describe, set } = cardApi()

    await commitCardChanges(api, 7, [], quick, quick, '  replacement password  ')

    expect(set).toHaveBeenCalledWith({
      ref: 'DSH_WEB_PASSWORD',
      value: '  replacement password  ',
    })
    expect(mutate).not.toHaveBeenCalled()
    expect(describe).not.toHaveBeenCalled()
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

    expect(describe).toHaveBeenCalledWith({ refs: ['NEXT_PASSWORD'] })
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
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'revision-conflict', message: 'settings revision changed' } },
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
    await store.commit({ expectedRevision: 3, writes: [], password: 'replacement' })
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

    await expect(store.commit({ expectedRevision: 3, writes: [], password: '' }))
      .rejects.toThrow('settings revision changed')
    expect(read).toHaveBeenCalledOnce()
    expect(store.getSnapshot()).toMatchObject({ revision: 4, value: { sessionTtlHours: 24 } })
    store.dispose()
  })

  it('adopts a remote locale and attempts later changes only once', async () => {
    let localeChanged = (_snapshot: { active: 'zh' | 'en' }): void => {}
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

  it('registers its browser card under the Host settings namespace', () => {
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
        ? { api: { settings: {}, credentials: {} }, isLoopback: true }
        : undefined,
      settingsScope: { bind: () => scope },
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
    expect(registeredNamespace).toBe('auth-tunnel')
    expect(registeredLocale).toBe('settings.auth-tunnel')
    expect(dictionaryNamespace).toBe('settings.auth-tunnel')
  })
})
