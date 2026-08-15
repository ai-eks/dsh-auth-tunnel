/**
 * Package-owned invariant companion for `dsh-auth-tunnel`.
 * @module dsh-auth-tunnel/invariant
 */

import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = 'dsh-auth-tunnel'

/** Cordis companion plugin name. */
export const name = 'auth-tunnel-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: the owned relation is "the spawned cloudflared tree
 * dies with its fiber", which cannot be probed from the teardown stream —
 * `internal/plugin` fires before the disposing fiber's effects run, so the
 * child is still legitimately alive at notification time and a liveness
 * probe would false-positive on every correct disposal. Spawn/teardown
 * quiescence is covered by the package's real-composition tests instead.
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
