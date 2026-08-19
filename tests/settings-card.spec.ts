import { describe, expect, it, vi } from 'vitest'
import {
  apply, commitCardChanges, commitCredentialWrite, commitSettingsWrites, parseRemoteSettingsDocument,
  installRemoteLocalePersistence, installRemoteSettingsRuntimeRecovery,
  RemoteSettingsStore, RuntimeStatusStore, runtimeStatusLocaleKey,
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
  const settingsDescribe = vi.fn(() => {
    order.push('settings-read')
    return Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          writable: true,
          hasDocument: true,
          namespaces: [{
            ns: 'auth-tunnel', schema: {}, value: { ...quick, ...user }, user,
            applies: 'live' as const, secrets: [], revision: 8,
          }],
        },
      },
    })
  })
  return {
    api: { settings: { mutate, describe: settingsDescribe }, credentials: { describe, set } } as never,
    describe,
    mutate,
    set,
  }
}

describe('auth-tunnel settings card contract', () => {
  it('validates token-only requirements before saving', () => {
    expect(validateSettingsValues(quick)).toEqual({})
    expect(validateSettingsValues({ ...quick, publicHostname: 'https://invalid.example.com' })).toEqual({})
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
      {},
    )

    expect(order).toEqual(['settings', 'credential', 'settings-read'])
    expect(set).toHaveBeenCalledWith({ ref: 'DSH_WEB_PASSWORD', value: '  rotated-password  ' })
  })

  it('rejects an active route change combined with an access password rotation', async () => {
    const order: string[] = []
    const { api, mutate, set } = successfulCardApi({ gatePort: 32_345 }, order)

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'gatePort', op: 'set', value: 32_345 }],
      quick,
      { ...quick, gatePort: 32_345 },
      'replacement-password',
      {},
    )).rejects.toThrow('separately from tunnel route changes')

    expect(mutate).not.toHaveBeenCalled()
    expect(set).not.toHaveBeenCalled()
  })

  it('requires a newly selected password reference to be configured separately', async () => {
    const order: string[] = []
    const { api } = successfulCardApi({ passwordRef: 'NEXT_WEB_PASSWORD' }, order)

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
      'next-password',
      {},
    )).rejects.toThrow('configured separately')

    expect(order).toEqual([])
  })

  it('does not replace the current credential when the settings mutation fails', async () => {
    const set = vi.fn()
    const mutate = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'conflict', message: 'settings revision changed' } },
    }))

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe: vi.fn(), set } } as never,
      7,
      [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      quick,
      { ...quick, sessionTtlHours: 24 },
      'next-password',
      {},
    )).rejects.toThrow('settings revision changed')

    expect(set).not.toHaveBeenCalled()
  })

  it('stores the password before enabling a currently stopped tunnel', async () => {
    const order: string[] = []
    const { api, mutate } = successfulCardApi({ enabled: true }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'enabled', op: 'set', value: true }],
      { ...quick, enabled: false },
      quick,
      'first-password',
      {},
    )

    expect(order).toEqual(['settings', 'credential', 'settings'])
    expect(mutate).toHaveBeenNthCalledWith(1, {
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [],
    })
    expect(mutate).toHaveBeenNthCalledWith(2, {
      ns: 'auth-tunnel',
      expectedRevision: 8,
      ops: [{ op: 'set', path: ['enabled'], value: true }],
    })
  })

  it('stores the password before granting remote settings access on an active tunnel', async () => {
    const order: string[] = []
    const { api, mutate } = successfulCardApi({ allowRemoteSettings: true }, order)

    await commitCardChanges(
      api,
      7,
      [{ field: 'allowRemoteSettings', op: 'set', value: true }],
      quick,
      { ...quick, allowRemoteSettings: true },
      'replacement-password',
      {},
    )

    expect(order).toEqual(['settings', 'credential', 'settings'])
    expect(mutate).toHaveBeenNthCalledWith(1, {
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [],
    })
    expect(mutate).toHaveBeenNthCalledWith(2, {
      ns: 'auth-tunnel',
      expectedRevision: 8,
      ops: [{ op: 'set', path: ['allowRemoteSettings'], value: true }],
    })
  })

  it('preserves a replaced credential when enabling loses its revision fence', async () => {
    const mutate = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, enabled: false },
            user: { enabled: false },
            applies: 'live' as const, secrets: [], revision: 8,
          },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: { ok: false as const, error: { code: 'conflict', message: 'settings revision changed' } },
      })
    const set = vi.fn(() => Promise.resolve({
      rpcId: 'test', result: { ok: true as const, value: {} },
    }))
    const unset = vi.fn(() => Promise.resolve({
      rpcId: 'test', result: { ok: true as const, value: {} },
    }))

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe: vi.fn(), set, unset } } as never,
      7,
      [{ field: 'enabled', op: 'set', value: true }],
      { ...quick, enabled: false },
      quick,
      'first-password',
      { enabled: false },
    )).rejects.toThrow('settings revision changed')

    expect(mutate).toHaveBeenNthCalledWith(1, {
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [],
    })
    expect(set).toHaveBeenCalledWith({ ref: 'DSH_WEB_PASSWORD', value: 'first-password' })
    expect(unset).not.toHaveBeenCalled()
    expect(mutate).toHaveBeenNthCalledWith(2, {
      ns: 'auth-tunnel',
      expectedRevision: 8,
      ops: [{ op: 'set', path: ['enabled'], value: true }],
    })
  })

  it('restores stopped settings when the pre-enablement credential write fails', async () => {
    const mutate = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, enabled: false, sessionTtlHours: 24 },
            user: { enabled: false, sessionTtlHours: 24 },
            applies: 'live' as const, secrets: [], revision: 8,
          },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, enabled: false },
            user: { enabled: false }, applies: 'live' as const, secrets: [], revision: 9,
          },
        },
      })
    const set = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'credential-rejected', message: 'read only' } },
    }))

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe: vi.fn(), set } } as never,
      7,
      [
        { field: 'sessionTtlHours', op: 'set', value: 24 },
        { field: 'enabled', op: 'set', value: true },
      ],
      { ...quick, enabled: false },
      { ...quick, sessionTtlHours: 24 },
      'first-password',
      { enabled: false },
    )).rejects.toThrow('read only')

    expect(mutate).toHaveBeenCalledTimes(2)
    expect(mutate).toHaveBeenNthCalledWith(2, {
      ns: 'auth-tunnel',
      expectedRevision: 8,
      ops: [{ op: 'unset', path: ['sessionTtlHours'] }],
    })
  })

  it('rejects a passwordless local passwordRef change targeting the token-mode tunnel credential', async () => {
    const order: string[] = []
    const { api, describe, mutate, set } = successfulCardApi({}, order)
    const current = { ...quick, tokenRef: 'DSH_TUNNEL_TOKEN' }
    const target = {
      ...current,
      mode: 'token' as const,
      passwordRef: 'DSH_TUNNEL_TOKEN',
      publicHostname: 'gui.example.com',
      gatePort: 32_309,
    }

    await expect(commitCardChanges(
      api,
      7,
      [
        { field: 'mode', op: 'set', value: 'token' },
        { field: 'passwordRef', op: 'set', value: 'DSH_TUNNEL_TOKEN' },
        { field: 'publicHostname', op: 'set', value: 'gui.example.com' },
        { field: 'gatePort', op: 'set', value: 32_309 },
      ],
      current,
      target,
      '',
      {},
    )).rejects.toThrow('conflicts')

    expect(describe).not.toHaveBeenCalled()
    expect(set).not.toHaveBeenCalled()
    expect(mutate).not.toHaveBeenCalled()
  })

  it('ignores an inactive quick-mode tokenRef collision', async () => {
    const order: string[] = []
    const { api, mutate } = successfulCardApi({ sessionTtlHours: 24 }, order)
    const current = { ...quick, tokenRef: 'DSH_WEB_PASSWORD' }

    await commitCardChanges(
      api,
      7,
      [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      current,
      { ...current, sessionTtlHours: 24 },
      '',
      {},
    )

    expect(order).toEqual(['settings'])
    expect(mutate).toHaveBeenCalledOnce()
  })

  it('rejects a passwordless local passwordRef change targeting an unconfigured credential', async () => {
    const order: string[] = []
    const { api, describe, mutate, set } = successfulCardApi({ passwordRef: 'MISSING_PASSWORD' }, order)

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'MISSING_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'MISSING_PASSWORD' },
      '',
      {},
    )).rejects.toThrow('not configured')

    expect(order).toEqual(['credential-check'])
    expect(describe).toHaveBeenCalledWith({ refs: ['MISSING_PASSWORD'] })
    expect(set).not.toHaveBeenCalled()
    expect(mutate).not.toHaveBeenCalled()
  })

  it('rolls back a passwordless reference change when the selected credential disappears', async () => {
    const describe = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: { credentials: { NEXT_WEB_PASSWORD: { configured: true, writable: true } } },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: { credentials: { NEXT_WEB_PASSWORD: { configured: false, writable: true } } },
        },
      })
    const mutate = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
            user: { passwordRef: 'NEXT_WEB_PASSWORD' }, applies: 'live' as const, secrets: [], revision: 8,
          },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: quick,
            user: {}, applies: 'live' as const, secrets: [], revision: 9,
          },
        },
      })

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe, set: vi.fn() } } as never,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
      '',
      {},
    )).rejects.toThrow('not configured')

    expect(describe).toHaveBeenCalledTimes(2)
    expect(mutate).toHaveBeenNthCalledWith(2, {
      ns: 'auth-tunnel',
      expectedRevision: 8,
      ops: [{ op: 'unset', path: ['passwordRef'] }],
    })
  })

  it('rebases a passwordless reference rollback over an unrelated settings edit', async () => {
    const describeCredential = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: { credentials: { NEXT_WEB_PASSWORD: { configured: true, writable: true } } },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: { credentials: { NEXT_WEB_PASSWORD: { configured: false, writable: true } } },
        },
      })
    const describeSettings = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          writable: true,
          hasDocument: true,
          namespaces: [{
            ns: 'auth-tunnel', schema: {},
            value: { ...quick, passwordRef: 'NEXT_WEB_PASSWORD', startupTimeoutMs: 20_000 },
            user: { passwordRef: 'NEXT_WEB_PASSWORD', startupTimeoutMs: 20_000 },
            applies: 'live' as const, secrets: [], revision: 9,
          }],
        },
      },
    }))
    const mutate = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
            user: { passwordRef: 'NEXT_WEB_PASSWORD' }, applies: 'live' as const, secrets: [], revision: 8,
          },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: { ok: false as const, error: { code: 'conflict', message: 'settings revision changed' } },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, startupTimeoutMs: 20_000 },
            user: { startupTimeoutMs: 20_000 }, applies: 'live' as const, secrets: [], revision: 10,
          },
        },
      })

    await expect(commitCardChanges(
      {
        settings: { mutate, describe: describeSettings },
        credentials: { describe: describeCredential, set: vi.fn() },
      } as never,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'NEXT_WEB_PASSWORD' }],
      quick,
      { ...quick, passwordRef: 'NEXT_WEB_PASSWORD' },
      '',
      {},
    )).rejects.toThrow('not configured')

    expect(describeSettings).toHaveBeenCalledWith({})
    expect(mutate).toHaveBeenNthCalledWith(3, {
      ns: 'auth-tunnel',
      expectedRevision: 9,
      ops: [{ op: 'unset', path: ['passwordRef'] }],
    })
  })

  it('rejects replacing another configured credential while switching references', async () => {
    const order: string[] = []
    const { api, mutate, set } = successfulCardApi({}, order, ['OTHER_HOST_SECRET'])

    await expect(commitCardChanges(
      api,
      7,
      [{ field: 'passwordRef', op: 'set', value: 'OTHER_HOST_SECRET' }],
      quick,
      { ...quick, passwordRef: 'OTHER_HOST_SECRET' },
      'replacement',
      {},
    )).rejects.toThrow('configured separately')

    expect(order).toEqual([])
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
      {},
    )).rejects.toThrow('settings revision changed')

    expect(mutate).toHaveBeenCalledWith({
      ns: 'auth-tunnel',
      expectedRevision: 7,
      ops: [],
    })
    expect(set).not.toHaveBeenCalled()
  })

  it('rechecks the selected password reference after a local credential write', async () => {
    const mutate = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          ns: 'auth-tunnel', schema: {}, value: quick, user: {},
          applies: 'live' as const, secrets: [], revision: 8,
        },
      },
    }))
    const describe = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          writable: true,
          hasDocument: true,
          namespaces: [{
            ns: 'auth-tunnel', schema: {}, value: { ...quick, passwordRef: 'ALT_WEB_PASSWORD' },
            user: { passwordRef: 'ALT_WEB_PASSWORD' }, applies: 'live' as const, secrets: [], revision: 9,
          }],
        },
      },
    }))
    let releaseSet = (): void => {}
    const setBarrier = new Promise<void>((resolve) => { releaseSet = resolve })
    let markSetStarted = (): void => {}
    const setStarted = new Promise<void>((resolve) => { markSetStarted = resolve })
    const set = vi.fn(async () => {
      markSetStarted()
      await setBarrier
      return { rpcId: 'test', result: { ok: true as const, value: {} } }
    })

    const save = commitCardChanges(
      { settings: { mutate, describe }, credentials: { describe: vi.fn(), set } } as never,
      7,
      [],
      quick,
      quick,
      'replacement',
      {},
    )
    await setStarted
    releaseSet()

    await expect(save).rejects.toThrow('password reference changed')
    expect(describe).toHaveBeenCalledWith({})
  })

  it('rejects a local password that cannot fit through the login endpoint', async () => {
    const mutate = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: {
        ok: true as const,
        value: {
          ns: 'auth-tunnel', schema: {}, value: quick, user: {},
          applies: 'live' as const, secrets: [], revision: 8,
        },
      },
    }))
    const set = vi.fn(() => Promise.resolve({
      rpcId: 'test', result: { ok: true as const, value: {} },
    }))

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe: vi.fn(), set } } as never,
      7,
      [],
      quick,
      quick,
      'x'.repeat(20_000),
      {},
    )).rejects.toThrow('too long')

    expect(mutate).not.toHaveBeenCalled()
    expect(set).not.toHaveBeenCalled()
  })

  it('rolls back local settings when the credential write fails', async () => {
    const mutate = vi.fn()
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, sessionTtlHours: 24 },
            user: { sessionTtlHours: 24 }, applies: 'live' as const, secrets: [], revision: 8,
          },
        },
      })
      .mockResolvedValueOnce({
        rpcId: 'test',
        result: {
          ok: true as const,
          value: {
            ns: 'auth-tunnel', schema: {}, value: { ...quick, sessionTtlHours: 48 },
            user: { sessionTtlHours: 48 }, applies: 'live' as const, secrets: [], revision: 9,
          },
        },
      })
    const set = vi.fn(() => Promise.resolve({
      rpcId: 'test',
      result: { ok: false as const, error: { code: 'credential-rejected', message: 'read only' } },
    }))

    await expect(commitCardChanges(
      { settings: { mutate }, credentials: { describe: vi.fn(), set } } as never,
      7,
      [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      { ...quick, sessionTtlHours: 48 },
      { ...quick, sessionTtlHours: 24 },
      'replacement',
      { sessionTtlHours: 48 },
    )).rejects.toThrow('read only')

    expect(mutate).toHaveBeenCalledTimes(2)
    expect(mutate).toHaveBeenNthCalledWith(2, {
      ns: 'auth-tunnel',
      expectedRevision: 8,
      ops: [{ op: 'set', path: ['sessionTtlHours'], value: 48 }],
    })
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

  it('refreshes remote settings when runtime status changes', () => {
    let runtimeChanged = (): void => {}
    const stop = vi.fn()
    const runtime = {
      subscribe: vi.fn((listener: () => void) => {
        runtimeChanged = listener
        return stop
      }),
    }
    const remote = { refreshAfterCurrentRead: vi.fn(() => Promise.resolve()) }

    const dispose = installRemoteSettingsRuntimeRecovery(runtime as never, remote as never)
    runtimeChanged()
    expect(remote.refreshAfterCurrentRead).toHaveBeenCalledOnce()
    dispose()
    expect(stop).toHaveBeenCalledOnce()
  })

  it('queues runtime recovery behind an in-flight forbidden settings read', async () => {
    const document = parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true },
        base: quick,
        user: { allowRemoteSettings: true },
        revision: 3,
        writable: true,
      },
    })
    const forbidden = Object.assign(new Error('forbidden'), { status: 403 })
    let rejectPending = (_error: unknown): void => {}
    const pending = new Promise<typeof document>((_resolve, reject) => { rejectPending = reject })
    const read = vi.fn()
      .mockResolvedValueOnce(document)
      .mockImplementationOnce(() => pending)
      .mockResolvedValue(document)
    const store = new RemoteSettingsStore({ read, commit: vi.fn() })
    let runtimeChanged = (): void => {}
    const dispose = installRemoteSettingsRuntimeRecovery({
      subscribe: (listener: () => void) => {
        runtimeChanged = listener
        return () => {}
      },
    } as never, store)

    await store.refresh()
    const stale = store.refresh()
    runtimeChanged()
    rejectPending(forbidden)
    await stale

    await vi.waitFor(() => { expect(read).toHaveBeenCalledTimes(3) })
    expect(store.getSnapshot()).toMatchObject({ status: 'ready', writable: true })
    dispose()
    store.dispose()
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

  it('does not let a read started before a successful commit overwrite the committed document', async () => {
    const document = (revision: number, sessionTtlHours: number) => parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true, sessionTtlHours },
        base: quick,
        user: { allowRemoteSettings: true, sessionTtlHours },
        revision,
        writable: true,
      },
    })
    let resolveRead = (_document: ReturnType<typeof document>): void => {}
    const pendingRead = new Promise<ReturnType<typeof document>>((resolve) => { resolveRead = resolve })
    const store = new RemoteSettingsStore({
      read: vi.fn(() => pendingRead),
      commit: vi.fn(() => Promise.resolve(document(4, 24))),
    })

    const readTask = store.refresh()
    await store.commit({
      expectedRevision: 3,
      writes: [{ field: 'sessionTtlHours', op: 'set', value: 24 }],
      password: '',
    })
    resolveRead(document(3, 720))
    await readTask

    expect(store.getSnapshot()).toMatchObject({ revision: 4, value: { sessionTtlHours: 24 } })
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

  it('makes a loaded remote scope read-only after external authorization is revoked', async () => {
    const document = parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true },
        base: quick,
        user: { allowRemoteSettings: true },
        revision: 3,
        writable: true,
      },
    })
    const forbidden = Object.assign(new Error('forbidden'), { status: 403 })
    const read = vi.fn()
      .mockResolvedValueOnce(document)
      .mockRejectedValue(forbidden)
    const store = new RemoteSettingsStore({
      read,
      commit: vi.fn(() => Promise.reject(new Error('save rejected'))),
    })

    await store.refresh()
    await expect(store.commit({ expectedRevision: 3, writes: [], password: '' }))
      .rejects.toThrow('save rejected')

    expect(store.getSnapshot()).toMatchObject({ status: 'ready', revision: 3, writable: false })
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

  it('retries a transient remote settings refresh after a ready snapshot', async () => {
    vi.useFakeTimers()
    try {
      const document = (revision: number, sessionTtlHours: number) => parseRemoteSettingsDocument({
        settings: {
          value: { ...quick, allowRemoteSettings: true, sessionTtlHours },
          base: quick,
          user: { allowRemoteSettings: true, sessionTtlHours },
          revision,
          writable: true,
        },
      })
      const read = vi.fn()
        .mockResolvedValueOnce(document(3, 720))
        .mockRejectedValueOnce(new Error('handoff'))
        .mockResolvedValue(document(4, 24))
      const store = new RemoteSettingsStore({ read, commit: vi.fn() })
      const unsubscribe = store.subscribe(() => {})

      await store.refresh()
      expect(store.getSnapshot()).toMatchObject({ status: 'ready', revision: 3 })
      await store.refresh()
      expect(store.getSnapshot()).toMatchObject({ status: 'unavailable', revision: 3, writable: false })
      await vi.advanceTimersByTimeAsync(1000)
      expect(read).toHaveBeenCalledTimes(3)
      expect(store.getSnapshot()).toMatchObject({
        status: 'ready', revision: 4, value: { sessionTtlHours: 24 },
      })

      unsubscribe()
      store.dispose()
    } finally {
      vi.useRealTimers()
    }
  })

  it('waits for a recovery signal after a loaded remote scope becomes forbidden', async () => {
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
      const forbidden = Object.assign(new Error('forbidden'), { status: 403 })
      const read = vi.fn()
        .mockResolvedValueOnce(document)
        .mockRejectedValueOnce(forbidden)
        .mockResolvedValue(document)
      const store = new RemoteSettingsStore({ read, commit: vi.fn() })
      const unsubscribe = store.subscribe(() => {})

      await store.refresh()
      await store.refresh()
      expect(store.getSnapshot()).toMatchObject({ status: 'ready', writable: false })
      await vi.advanceTimersByTimeAsync(3000)
      expect(read).toHaveBeenCalledTimes(2)

      await store.refresh()
      expect(read).toHaveBeenCalledTimes(3)
      expect(store.getSnapshot()).toMatchObject({ status: 'ready', revision: 3, writable: true })

      unsubscribe()
      store.dispose()
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not retry an initial forbidden remote settings read', async () => {
    vi.useFakeTimers()
    try {
      const forbidden = Object.assign(new Error('forbidden'), { status: 403 })
      const read = vi.fn(() => Promise.reject(forbidden))
      const store = new RemoteSettingsStore({ read, commit: vi.fn() })
      const unsubscribe = store.subscribe(() => {})

      await store.refresh()
      expect(store.getSnapshot()).toMatchObject({ status: 'unavailable', writable: false })
      await vi.advanceTimersByTimeAsync(3000)
      expect(read).toHaveBeenCalledTimes(1)

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

  it('retries a transient remote locale write', async () => {
    vi.useFakeTimers()
    const fetch = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new Error('handoff'))
      .mockResolvedValue(new Response('{}', { status: 200 }))
    const document = parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true },
        base: quick,
        user: { allowRemoteSettings: true },
        revision: 3,
        writable: true,
      },
      locale: 'zh',
    })
    const store = new RemoteSettingsStore({
      read: vi.fn(() => Promise.resolve(document)),
      commit: vi.fn(),
    })
    let localeChanged = (_snapshot: { active: 'zh' | 'en' }): void => {}
    await store.refresh()
    const dispose = installRemoteLocalePersistence({
      on: vi.fn((_event, listener) => {
        localeChanged = listener as typeof localeChanged
        return () => {}
      }),
      locale: { setLocale: vi.fn() },
    } as never, store)

    try {
      localeChanged({ active: 'en' })
      await vi.advanceTimersByTimeAsync(0)
      expect(fetch).toHaveBeenCalledOnce()
      await vi.advanceTimersByTimeAsync(1000)
      expect(fetch).toHaveBeenCalledTimes(2)
      expect(fetch).toHaveBeenLastCalledWith('/dsh-auth-tunnel/locale', expect.objectContaining({
        body: JSON.stringify({ locale: 'en' }),
      }))
    } finally {
      dispose()
      store.dispose()
      fetch.mockRestore()
      vi.useRealTimers()
    }
  })

  it('keeps a failed locale write queued until remote settings recover', async () => {
    vi.useFakeTimers()
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('handoff'))
    const first = parseRemoteSettingsDocument({
      settings: {
        value: { ...quick, allowRemoteSettings: true },
        base: quick,
        user: { allowRemoteSettings: true },
        revision: 3,
        writable: true,
      },
      locale: 'zh',
    })
    const recovered = { ...first, snapshot: { ...first.snapshot, revision: 4 } }
    let live = first
    const store = new RemoteSettingsStore({
      read: vi.fn(() => Promise.resolve(live)),
      commit: vi.fn(),
    })
    let localeChanged = (_snapshot: { active: 'zh' | 'en' }): void => {}
    await store.refresh()
    const dispose = installRemoteLocalePersistence({
      on: vi.fn((_event, listener) => {
        localeChanged = listener as typeof localeChanged
        return () => {}
      }),
      locale: { setLocale: vi.fn() },
    } as never, store)

    try {
      localeChanged({ active: 'en' })
      await vi.advanceTimersByTimeAsync(0)
      await vi.advanceTimersByTimeAsync(5000)
      expect(fetch).toHaveBeenCalledTimes(6)

      fetch.mockResolvedValue(new Response('{}', { status: 200 }))
      live = recovered
      await store.refresh()
      await vi.advanceTimersByTimeAsync(0)
      expect(fetch).toHaveBeenCalledTimes(7)
      expect(fetch).toHaveBeenLastCalledWith('/dsh-auth-tunnel/locale', expect.objectContaining({
        body: JSON.stringify({ locale: 'en' }),
      }))
    } finally {
      dispose()
      store.dispose()
      fetch.mockRestore()
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
    await store.refresh()
    expect(store.getSnapshot()).toEqual({ phase: 'unavailable', running: false, revision: 7 })
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

    const saveStartedAtRevision = store.getSnapshot().revision
    live = { phase: 'running', running: true, revision: 10, publicUrl: 'https://saved.example.com' }
    await store.refresh()
    store.settingsCommitted(true, saveStartedAtRevision)
    expect(store.getSnapshot()).toBe(live)
    await store.refresh()
    expect(store.getSnapshot()).toBe(live)
    store.dispose()

    const unavailable = new RuntimeStatusStore(() => Promise.reject(new Error('offline')))
    await unavailable.refresh()
    expect(unavailable.getSnapshot()).toEqual({ phase: 'unavailable', running: false, revision: 0 })
    unavailable.dispose()
  })

  it('accepts a lower runtime revision as a new process while a settings fence is pending', async () => {
    let live: RuntimeStatusSnapshot = {
      phase: 'running', running: true, revision: 7, publicUrl: 'https://gui.example.com',
    }
    const store = new RuntimeStatusStore(() => Promise.resolve(live))

    await store.refresh()
    store.settingsCommitted(true)
    expect(store.getSnapshot()).toMatchObject({ phase: 'applying', revision: 7 })

    live = { phase: 'running', running: true, revision: 1, publicUrl: 'https://restarted.example.com' }
    await store.refresh()
    expect(store.getSnapshot()).toBe(live)
    store.dispose()
  })

  it('expires a pending fence when a restarted runtime recovers at the same revision', async () => {
    vi.useFakeTimers()
    try {
      let live: RuntimeStatusSnapshot = {
        phase: 'running', running: true, revision: 7, publicUrl: 'https://gui.example.com',
      }
      const store = new RuntimeStatusStore(() => Promise.resolve(live))

      await store.refresh()
      store.settingsCommitted(true)
      live = { phase: 'running', running: true, revision: 7, publicUrl: 'https://restarted.example.com' }
      await store.refresh()
      expect(store.getSnapshot()).toMatchObject({ phase: 'applying', revision: 7 })

      await vi.advanceTimersByTimeAsync(5000)
      await store.refresh()
      expect(store.getSnapshot()).toBe(live)
      store.dispose()
    } finally {
      vi.useRealTimers()
    }
  })
})
