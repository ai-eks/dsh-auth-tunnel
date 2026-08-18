import { describe, expect, it, vi } from 'vitest'
import {
  apply, commitCardChanges, commitCredentialWrite, commitSettingsWrites, parseRemoteSettingsDocument,
  installRemoteLocalePersistence, RemoteSettingsStore, RuntimeStatusStore, runtimeStatusLocaleKey,
  validateSettingsValues,
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

function successfulCardApi(user: Record<string, unknown>, order: string[], configuredRefs: readonly string[] = []) {
  const mutate = vi.fn(() => {
    order.push('settings')
    return Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          ns: 'auth-tunnel', schema: {}, value: {}, user,
          applies: 'live' as const, secrets: [], revision: 8,
        },
      },
    })
  })
  const set = vi.fn(() => {
    order.push('credential')
    return Promise.resolve({ rpcId: 'test', result: { ok: true as const, value: {} } })
  })
  const describe = vi.fn(({ refs }: { refs: string[] }) => {
    order.push('credential-check')
    return Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          credentials: Object.fromEntries(refs.map(ref => [ref, {
            configured: configuredRefs.includes(ref),
            writable: true,
          }])),
        },
      },
    })
  })
  return { api: { settings: { mutate }, credentials: { describe, set } } as never, describe, mutate, set }
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
    expect(validateSettingsValues({ ...quick, startupTimeoutMs: 2_147_483_648 })).toEqual({
      startupTimeoutMs: 'invalidInteger',
    })
  })

  it('commits a disable plus configuration switch as one revision-fenced mutation', async () => {
    const writes: SettingsWrite[] = [
      { field: 'enabled', op: 'set', value: false },
      { field: 'mode', op: 'set', value: 'token' },
      { field: 'tokenRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' },
      { field: 'publicHostname', op: 'set', value: 'gui.example.com' },
      { field: 'gatePort', op: 'set', value: 32_309 },
    ]
    const mutate = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          ns: 'auth-tunnel', schema: {}, value: {}, user: {
            enabled: false,
            mode: 'token',
            tokenRef: 'DSH_TUNNEL_TOKEN',
            publicHostname: 'gui.example.com',
            gatePort: 32_309,
          },
          applies: 'live' as const, secrets: [], revision: 8,
        },
      },
    }))

    const committed = await commitSettingsWrites({ settings: { mutate } } as never, 7, writes)
    expect(mutate).toHaveBeenCalledTimes(1)
    expect(mutate).toHaveBeenCalledWith({
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [
        { op: 'set', path: ['enabled'], value: false },
        { op: 'set', path: ['mode'], value: 'token' },
        { op: 'set', path: ['tokenRef'], value: 'DSH_TUNNEL_TOKEN' },
        { op: 'set', path: ['publicHostname'], value: 'gui.example.com' },
        { op: 'set', path: ['gatePort'], value: 32_309 },
      ],
    })
    expect(committed.revision).toBe(8)
  })

  it('writes an access password only through the write-only credentials domain', async () => {
    const set = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: true as const, value: {} },
    }))

    await commitCredentialWrite({ credentials: { set } } as never, 'DSH_WEB_PASSWORD', 'new-password')

    expect(set).toHaveBeenCalledTimes(1)
    expect(set).toHaveBeenCalledWith({ ref: 'DSH_WEB_PASSWORD', value: 'new-password' })
  })

  it('surfaces a rejected credential write as a failed save', async () => {
    const set = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'credential-rejected', message: 'read only' } },
    }))

    await expect(commitCredentialWrite(
      { credentials: { set } } as never,
      'DSH_WEB_PASSWORD',
      'new-password',
    )).rejects.toThrow('read only')
  })

  it('commits settings before rotating the active password so a public session can finish saving', async () => {
    const order: string[] = []
    const { api, set } = successfulCardApi({ sessionTtlHours: 24 }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      quick,
      { ...quick, sessionTtlHours: 24 },
      '  rotated-password  ',
    )

    expect(order).toEqual(['settings', 'credential'])
    expect(set).toHaveBeenCalledWith({ ref: 'DSH_WEB_PASSWORD', value: '  rotated-password  ' })
  })

  it('commits a newly selected password reference before writing its credential', async () => {
    const order: string[] = []
    const { api } = successfulCardApi({ passwordRef: 'NEXT_WEB_PASSWORD' }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
      'next-password',
    )

    expect(order).toEqual(['credential-check', 'settings', 'credential'])
  })

  it('does not create a new local credential when the settings mutation fails', async () => {
    const set = vi.fn()
    const mutate = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'conflict', message: 'settings revision changed' } },
    }))
    const describe = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: { credentials: { NEXT_WEB_PASSWORD: { configured: false, writable: true } } },
      },
    }))

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe, set } } as never,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
      'next-password',
    )).rejects.toThrow('settings revision changed')

    expect(set).not.toHaveBeenCalled()
  })

  it('stores the password before enabling a currently stopped tunnel', async () => {
    const order: string[] = []
    const { api } = successfulCardApi({ enabled: true }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'enabled', op: 'set', value: true }],
      { ...quick, enabled: false },
      quick,
      'first-password',
    )

    expect(order).toEqual(['settings', 'credential'])
  })

  it('rejects a passwordless local passwordRef change targeting the tunnel token', async () => {
    const order: string[] = []
    const { api, describe, mutate, set } = successfulCardApi({}, order)
    const current = { ...quick, tokenRef: 'DSH_TUNNEL_TOKEN' }

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' }],
      current,
      { ...current, passwordRef: 'DSH_TUNNEL_TOKEN' },
      '',
    )).rejects.toThrow('conflicts')

    expect(describe).not.toHaveBeenCalled()
    expect(set).not.toHaveBeenCalled()
    expect(mutate).not.toHaveBeenCalled()
  })

  it('rejects a local password write targeting another configured credential', async () => {
    const order: string[] = []
    const { api, mutate, set } = successfulCardApi({}, order, ['OTHER_HOST_SECRET'])

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'OTHER_HOST_SECRET' }],
      quick,
      { ...quick, passwordRef: 'OTHER_HOST_SECRET' },
      'replacement',
    )).rejects.toThrow('already exists')

    expect(order).toEqual(['credential-check'])
    expect(set).not.toHaveBeenCalled()
    expect(mutate).not.toHaveBeenCalled()
  })

  it('revision-fences a password-only local save before writing the credential', async () => {
    const mutate = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'conflict', message: 'settings revision changed' } },
    }))
    const set = vi.fn()

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe: vi.fn(), set } } as never,
      7,
      [],
      quick,
      quick,
      'replacement',
    )).rejects.toThrow('settings revision changed')

    expect(mutate).toHaveBeenCalledWith({
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [],
    })
    expect(set).not.toHaveBeenCalled()
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
      set: () => Promise.resolve(),
      unset: () => Promise.resolve(),
    }
    const ctx = {
      get: (name: string) => name === 'connection' ? { api: { settings: {} }, isLoopback: true } : undefined,
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

  it('loads and commits the authenticated remote scope without Harness settingsScope', async () => {
    const document = (revision: number, sessionTtlHours: number) => parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true, sessionTtlHours },
        base: quick,
        user: { allowRemoteSettings: true, sessionTtlHours },
        revision,
        writable: true,
      },
      locale: 'en',
    })
    const read = vi.fn(() => Promise.resolve(document(3, 720)))
    const commit = vi.fn(() => Promise.resolve(document(4, 24)))
    const store = new RemoteSettingsStore({ read, commit })
    let notifications = 0
    const dispose = store.subscribe(() => { notifications += 1 })

    await store.refresh()
    expect(read).toHaveBeenCalledOnce()
    expect(store.getSnapshot()).toMatchObject({
      status: 'ready', revision: 3, writable: true, value: { sessionTtlHours: 720 },
    })

    await store.commit({
      expectedRevision: 3,
      writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      password: '',
    })
    expect(commit).toHaveBeenCalledWith({
      expectedRevision: 3,
      writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      password: '',
    })
    expect(store.getSnapshot()).toMatchObject({ revision: 4, value: { sessionTtlHours: 24 } })
    expect(notifications).toBe(2)
    dispose()
    store.dispose()
  })

  it('makes the remote scope read-only after it revokes its own access', async () => {
    const document = (allowRemoteSettings: boolean) => parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings },
        base: quick,
        user: { allowRemoteSettings },
        revision: allowRemoteSettings ? 3 : 4,
        writable: true,
      },
    })
    const store = new RemoteSettingsStore({
      read: vi.fn(() => Promise.resolve(document(true))),
      commit: vi.fn(() => Promise.resolve(document(false))),
    })

    await store.refresh()
    await store.commit({
      expectedRevision: 3,
      writes: [{ field: 'allowRemoteSettings', op: 'set', value: false }],
      password: '',
    })

    expect(store.getSnapshot()).toMatchObject({
      status: 'ready', revision: 4, writable: false, value: { allowRemoteSettings: false },
    })
    expect(store.getDocument()?.snapshot.writable).toBe(false)
    store.dispose()
  })

  it('retries an unavailable initial remote settings read while subscribed', async () => {
    vi.useFakeTimers()
    try {
      const document = parseRemoteSettingsDocument({
        settings: {
          value: { ...quick, allowRemoteSettings: true },
          base: quick,
          user: { allowRemoteSettings: true },
          revision: 3,
          writable: true,
        },
      })
      const read = vi.fn()
        .mockRejectedValueOnce(new Error('handoff'))
        .mockResolvedValue(document)
      const store = new RemoteSettingsStore({ read, commit: vi.fn() })
      const unsubscribe = store.subscribe(() => {})

      await store.refresh()
      expect(store.getSnapshot().status).toBe('unavailable')
      await vi.advanceTimersByTimeAsync(1000)
      expect(read).toHaveBeenCalledTimes(2)
      expect(store.getSnapshot()).toMatchObject({ status: 'ready', revision: 3 })

      unsubscribe()
      store.dispose()
    } finally {
      vi.useRealTimers()
    }
  })

  it('adopts the persisted locale after an unavailable initial remote read recovers', async () => {
    vi.useFakeTimers()
    try {
      const document = parseRemoteSettingsDocument({
        settings: {
          value: { ...quick, allowRemoteSettings: true },
          base: quick,
          user: { allowRemoteSettings: true },
          revision: 3,
          writable: true,
        },
        locale: 'en',
      })
      const read = vi.fn()
        .mockRejectedValueOnce(new Error('handoff'))
        .mockResolvedValue(document)
      const store = new RemoteSettingsStore({ read, commit: vi.fn() })
      const setLocale = vi.fn()
      const dispose = installRemoteLocalePersistence({
        on: vi.fn(() => () => {}),
        locale: { setLocale },
      } as never, store)

      await vi.advanceTimersByTimeAsync(1000)
      expect(read).toHaveBeenCalledTimes(2)
      expect(setLocale).toHaveBeenCalledWith('en')

      dispose()
      store.dispose()
    } finally {
      vi.useRealTimers()
    }
  })

  it('refreshes the remote settings snapshot after a rejected commit', async () => {
    const latest = parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true, sessionTtlHours: 24 },
        base: quick,
        user: { allowRemoteSettings: true, sessionTtlHours: 24 },
        revision: 4,
        writable: true,
      },
    })
    const read = vi.fn(() => Promise.resolve(latest))
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

  it('keeps a stable external runtime snapshot and maps every visible state', async () => {
    const running: RuntimeStatusSnapshot = {
      phase: 'running', running: true, revision: 7, publicUrl: 'https://gui.example.com',
    }
    let fail = false
    let live = running
    const store = new RuntimeStatusStore(() => fail
      ? Promise.reject(new Error('offline'))
      : Promise.resolve(live))

    expect(runtimeStatusLocaleKey(store.getSnapshot())).toBe('statusUnavailable')
    await store.refresh()
    expect(store.getSnapshot()).toBe(running)
    expect(runtimeStatusLocaleKey(store.getSnapshot())).toBe('statusRunning')
    expect(runtimeStatusLocaleKey({ phase: 'stopped', running: false, revision: 8 })).toBe('statusStopped')
    expect(runtimeStatusLocaleKey({ phase: 'applying', running: true, revision: 9 })).toBe('statusApplying')
    expect(runtimeStatusLocaleKey({ phase: 'error', running: true, revision: 10 })).toBe('statusErrorRunning')
    expect(runtimeStatusLocaleKey({ phase: 'error', running: false, revision: 11 })).toBe('statusErrorStopped')

    fail = true
    await store.refresh()
    expect(store.getSnapshot()).toBe(running)
    store.settingsCommitted(false)
    expect(store.getSnapshot()).toEqual({ phase: 'stopped', running: false, revision: 7 })
    fail = false
    await store.refresh()
    expect(store.getSnapshot()).toEqual({ phase: 'stopped', running: false, revision: 7 })

    live = { phase: 'stopped', running: false, revision: 8 }
    await store.refresh()
    expect(store.getSnapshot()).toBe(live)
    store.settingsCommitted(true)
    expect(store.getSnapshot()).toEqual({ phase: 'applying', running: false, revision: 8 })
    await store.refresh()
    expect(store.getSnapshot()).toEqual({ phase: 'applying', running: false, revision: 8 })

    live = { phase: 'running', running: true, revision: 9, publicUrl: 'https://next.example.com' }
    await store.refresh()
    expect(store.getSnapshot()).toBe(live)
    store.dispose()

    const unavailable = new RuntimeStatusStore(() => Promise.reject(new Error('offline')))
    await unavailable.refresh()
    expect(unavailable.getSnapshot()).toEqual({ phase: 'unavailable', running: false, revision: 0 })
    unavailable.dispose()
  })
})
