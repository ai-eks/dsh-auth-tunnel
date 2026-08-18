import { describe, expect, it } from 'vitest'
import {
  apply, orderSettingsWrites, RuntimeStatusStore, runtimeStatusLocaleKey, validateSettingsValues,
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

  it('orders activation and mode switches so every intermediate Host section stays valid', () => {
    const writes: SettingsWrite[] = [
      { field: 'enabled', op: 'set', value: true },
      { field: 'mode', op: 'set', value: 'token' },
      { field: 'tokenRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' },
      { field: 'publicHostname', op: 'set', value: 'gui.example.com' },
      { field: 'gatePort', op: 'set', value: 32_309 },
    ]
    expect(orderSettingsWrites(writes, { enabled: true, mode: 'token' }).map(write => write.field)).toEqual([
      'tokenRef', 'publicHostname', 'gatePort', 'mode', 'enabled',
    ])
    expect(orderSettingsWrites([
      { ...writes[0]!, value: false },
      ...writes.slice(1),
    ], { enabled: false, mode: 'quick' }).map(write => write.field)).toEqual([
      'enabled', 'mode', 'tokenRef', 'publicHostname', 'gatePort',
    ])
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
    const store = new RuntimeStatusStore(() => fail
      ? Promise.reject(new Error('offline'))
      : Promise.resolve(running))

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
    expect(store.getSnapshot()).toEqual({ phase: 'unavailable', running: false, revision: 7 })
    store.dispose()
  })
})
