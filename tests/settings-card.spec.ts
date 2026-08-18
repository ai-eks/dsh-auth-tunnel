import { describe, expect, it, vi } from 'vitest'
import {
  apply, commitCardChanges, commitCredentialWrite, commitSettingsWrites, parseRemoteSettingsDocument,
  RemoteSettingsStore, RuntimeStatusStore, runtimeStatusLocaleKey, validateSettingsValues,
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

function successfulCardApi(user: Record<string, unknown>, order: string[]) {
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
  return { api: { settings: { mutate }, credentials: { set } } as never, mutate, set }
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
      true,
      'DSH_WEB_PASSWORD',
      'DSH_WEB_PASSWORD',
      '  rotated-password  ',
    )

    expect(order).toEqual(['settings', 'credential'])
    expect(set).toHaveBeenCalledWith({ ref: 'DSH_WEB_PASSWORD', value: '  rotated-password  ' })
  })

  it('populates a newly selected password reference before settings activate it', async () => {
    const order: string[] = []
    const { api } = successfulCardApi({ passwordRef: 'NEXT_WEB_PASSWORD' }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
      true,
      'DSH_WEB_PASSWORD',
      'NEXT_WEB_PASSWORD',
      'next-password',
    )

    expect(order).toEqual(['credential', 'settings'])
  })

  it('stores the password before enabling a currently stopped tunnel', async () => {
    const order: string[] = []
    const { api } = successfulCardApi({ enabled: true }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'enabled', op: 'set', value: true }],
      false,
      'DSH_WEB_PASSWORD',
      'DSH_WEB_PASSWORD',
      'first-password',
    )

    expect(order).toEqual(['credential', 'settings'])
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
