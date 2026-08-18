import { describe, expect, it, vi } from 'vitest'
import {
  apply, commitSettingsWrites, RuntimeStatusStore, runtimeStatusLocaleKey, validateSettingsValues,
  type AuthTunnelSettings, type RuntimeStatusSnapshot, type SettingsWrite,
} from '../src/client/index.tsx'

const quick: AuthTunnelSettings = {
  enabled: true,
  passwordRef: 'DSH_WEB_PASSWORD',
  sessionTtlHours: 720,
  mode: 'quick',
  gatePort: 0,
  executable: 'cloudflared',
  startupTimeoutMs: 15_000,
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
      get: (name: string) => name === 'connection' ? { api: { settings: {} } } : undefined,
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
