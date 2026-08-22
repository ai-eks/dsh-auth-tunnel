/** Browser settings card for the Host-side auth-tunnel namespace. */

import { useState, useSyncExternalStore, type CSSProperties } from 'react'
import type {
  ClientContext, SettingsScope, SettingsScopeSnapshot,
} from '@deepseek-ai/dsh-client-runtime/client'
import type {
  ConnectionHandle, IApiClient, SettingsNamespaceView, SettingsPathOpView,
} from '@deepseek-ai/dsh-api-remotes/client'
import type { PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
// Type-only service and slot declarations. Cross-plugin behavior stays on
// Cordis services, so the lazy client bundle imports no plugin implementation.
import type {} from '@deepseek-ai/dsh-client-locale/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings-plugins/client'

const SETTINGS_NAMESPACE = 'auth-tunnel'
const LOCALE_NAMESPACE = 'settings.auth-tunnel'

type LocaleKey =
  | 'title' | 'description' | 'unsaved' | 'readOnly' | 'live'
  | 'enabled' | 'enabledHint' | 'enabledOn' | 'enabledOff'
  | 'allowRemoteSettings' | 'allowRemoteSettingsHint'
  | 'status' | 'statusRunning' | 'statusStopped' | 'statusApplying'
  | 'statusErrorRunning' | 'statusErrorStopped' | 'statusUnavailable' | 'publicUrl'
  | 'accessSection' | 'accessSectionHint' | 'tunnelSection' | 'advancedSection' | 'advancedSectionHint'
  | 'mode' | 'modeHint' | 'quick' | 'token' | 'quickRequirements' | 'tokenRequirements'
  | 'passwordRef' | 'passwordRefHint'
  | 'password' | 'passwordHint' | 'passwordPlaceholder' | 'passwordUpdate' | 'passwordUpdating'
  | 'passwordSaveFailed' | 'separateSaveHint'
  | 'sessionTtlHours' | 'sessionTtlHoursHint'
  | 'tokenRef' | 'tokenRefHint'
  | 'publicHostname' | 'publicHostnameHint'
  | 'quickGatePort' | 'quickGatePortHint' | 'tokenGatePort' | 'tokenGatePortHint'
  | 'executable' | 'executableHint'
  | 'startupTimeoutMs' | 'startupTimeoutMsHint'
  | 'overridden' | 'reset' | 'discard' | 'save' | 'saving' | 'saveFailed'
  | 'required' | 'invalidNumber' | 'invalidInteger' | 'invalidHostname'
  | 'tokenRefRequired' | 'hostnameRequired' | 'fixedPortRequired'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** Auth Tunnel settings-card copy. */
    'settings.auth-tunnel': LocaleKey
  }
}

const zh: Record<LocaleKey, string> = {
  title: 'Auth Tunnel',
  description: '通过 Cloudflare Tunnel 为 Web GUI 提供密码保护的公网访问。',
  unsaved: '未保存',
  readOnly: '当前设置存储为只读。',
  live: '保存后自动应用，无需重启 DeepSeek Harness。隧道级变更期间公网页面可能短暂断开；请打开新显示的地址，失败时重新读取后重试。Token 模式的 Gate 端口仍需与 Cloudflare ingress 一致。',
  enabled: '启用公网隧道',
  enabledHint: '保存后立即启动或停止密码门和 cloudflared，设置卡片会继续保留。',
  enabledOn: '开启',
  enabledOff: '关闭',
  allowRemoteSettings: '允许远程页面修改设置',
  allowRemoteSettingsHint: '仅控制已登录公网页面的 Auth Tunnel 配置和语言。共享访问密码是管理员凭据，因此默认开启。模型、凭据等核心 Host 配置由登录 Gate 单独授权，不受此开关控制。',
  status: '运行状态',
  statusRunning: '运行中',
  statusStopped: '已停止',
  statusApplying: '应用中…',
  statusErrorRunning: '应用失败（旧隧道仍在运行）',
  statusErrorStopped: '应用失败（隧道未运行）',
  statusUnavailable: '暂时无法读取',
  publicUrl: '公网地址',
  accessSection: '访问保护（Quick / Token 共用）',
  accessSectionHint: '两种隧道模式都先经过同一个密码登录页。',
  tunnelSection: 'Cloudflare 隧道',
  advancedSection: '高级设置',
  advancedSectionHint: '通常无需修改；仅在 cloudflared 路径或启动环境特殊时调整。',
  mode: '隧道模式',
  modeHint: '切换模式后，下方只显示该模式会使用的配置。',
  quick: 'Quick（临时隧道）',
  token: 'Token（命名隧道）',
  quickRequirements: 'Quick 只需要上方的访问密码；无需 Cloudflare Token 或自有域名，Gate 端口保持 0 即可自动分配。',
  tokenRequirements: 'Token 启用前必须准备 Tunnel Token、已绑定的公网域名和固定 Gate 端口；Cloudflare ingress 必须指向该端口。',
  passwordRef: '密码凭据引用',
  passwordRefHint: '一般保持 DSH_WEB_PASSWORD。若要切换引用，请先在 Host Credentials 中创建目标凭据，再将下方密码留空后保存。',
  password: '设置或替换访问密码',
  passwordHint: '使用独立按钮写入当前密码凭据，成功后清空且永不回显。该密码可重复登录，直到再次替换；替换后现有公网会话会失效。',
  passwordPlaceholder: '留空表示不修改当前密码',
  passwordUpdate: '更新密码',
  passwordUpdating: '更新中…',
  passwordSaveFailed: '密码未更新，请检查后重试。',
  separateSaveHint: '密码和配置需要分别保存；请先清空密码输入或放弃配置修改。',
  sessionTtlHours: '会话时长（小时）',
  sessionTtlHoursHint: '登录 Cookie 的绝对有效期。',
  tokenRef: 'Tunnel Token 凭据引用（必填）',
  tokenRefHint: '填写已存入凭据服务的名称，例如 DSH_TUNNEL_TOKEN；不是 Token 明文。',
  publicHostname: '公网主机名（必填）',
  publicHostnameHint: 'Cloudflare 控制台中绑定到命名隧道的域名。',
  quickGatePort: 'Gate 端口（自动）',
  quickGatePortHint: '建议保持 0，由插件自动选择可用端口。',
  tokenGatePort: 'Gate 端口（必填）',
  tokenGatePortHint: '必须使用 1–65535 的固定端口，并与 Cloudflare ingress 的 loopback 端口一致。',
  executable: 'cloudflared 可执行文件',
  executableHint: 'PATH 中的命令名或绝对路径。',
  startupTimeoutMs: '启动超时（毫秒）',
  startupTimeoutMsHint: '等待 cloudflared 建立隧道的最长时间。',
  overridden: '已覆盖',
  reset: '恢复默认',
  discard: '放弃修改',
  save: '保存配置',
  saving: '保存中…',
  saveFailed: '设置未保存，请检查配置或是否已在其他页面修改，然后重试。',
  required: '此项不能为空。',
  invalidNumber: '请输入有效数字。',
  invalidInteger: '请输入范围内的整数。',
  invalidHostname: '请输入有效域名，例如 tunnel.example.com。',
  tokenRefRequired: 'Token 模式必须填写 Tunnel Token 凭据引用。',
  hostnameRequired: 'Token 模式必须填写公网主机名。',
  fixedPortRequired: 'Token 模式必须使用 1–65535 的固定端口。',
}

const en: Record<LocaleKey, string> = {
  title: 'Auth Tunnel',
  description: 'Password-gated public access to the Web GUI through Cloudflare Tunnel.',
  unsaved: 'Unsaved',
  readOnly: 'This deployment stores settings read-only.',
  live: 'Saved changes apply automatically without restarting DeepSeek Harness. A tunnel-level switch can briefly interrupt a public page; open the newly displayed URL and reload before retrying a failed save. The Token-mode gate port must still match Cloudflare ingress.',
  enabled: 'Enable public tunnel',
  enabledHint: 'Saving starts or stops the password gate and cloudflared immediately while keeping this card available.',
  enabledOn: 'On',
  enabledOff: 'Off',
  allowRemoteSettings: 'Allow remote pages to change settings',
  allowRemoteSettingsHint: 'Controls Auth Tunnel configuration and language only for signed-in public pages. The shared access password is an administrator credential, so this is enabled by default. Core Host models, credentials, and settings are authorized separately by the login Gate and do not depend on this switch.',
  status: 'Runtime status',
  statusRunning: 'Running',
  statusStopped: 'Stopped',
  statusApplying: 'Applying…',
  statusErrorRunning: 'Apply failed (previous tunnel still running)',
  statusErrorStopped: 'Apply failed (tunnel stopped)',
  statusUnavailable: 'Temporarily unavailable',
  publicUrl: 'Public URL',
  accessSection: 'Access protection (shared by Quick and Token)',
  accessSectionHint: 'Both tunnel modes use the same password login gate.',
  tunnelSection: 'Cloudflare tunnel',
  advancedSection: 'Advanced settings',
  advancedSectionHint: 'Usually unchanged; adjust only for a custom cloudflared path or startup environment.',
  mode: 'Tunnel mode',
  modeHint: 'After switching modes, only settings used by that mode are shown below.',
  quick: 'Quick (temporary tunnel)',
  token: 'Token (named tunnel)',
  quickRequirements: 'Quick only needs the access password above. It needs no Cloudflare Token or custom domain, and gate port 0 selects a port automatically.',
  tokenRequirements: 'Before enabling Token mode, provide a Tunnel Token, bound public hostname, and fixed gate port. Cloudflare ingress must target that port.',
  passwordRef: 'Password credential reference',
  passwordRefHint: 'Normally keep DSH_WEB_PASSWORD. To switch references, create the target in Host Credentials first, then save here with the password below left blank.',
  password: 'Set or replace access password',
  passwordHint: 'Use the separate button to write the current password credential. It is cleared after success and never revealed. Replacing it invalidates existing public sessions.',
  passwordPlaceholder: 'Leave blank to keep the current password',
  passwordUpdate: 'Update password',
  passwordUpdating: 'Updating…',
  passwordSaveFailed: 'The password was not updated. Check it and retry.',
  separateSaveHint: 'Password and configuration are saved separately. Clear the password input or discard configuration edits first.',
  sessionTtlHours: 'Session lifetime (hours)',
  sessionTtlHoursHint: 'Absolute lifetime of the login cookie.',
  tokenRef: 'Tunnel Token credential reference (required)',
  tokenRefHint: 'Name already stored in the credential service, such as DSH_TUNNEL_TOKEN; not the Token literal.',
  publicHostname: 'Public hostname (required)',
  publicHostnameHint: 'Hostname bound to the named tunnel in Cloudflare.',
  quickGatePort: 'Gate port (automatic)',
  quickGatePortHint: 'Keep 0 to let the plugin select an available port.',
  tokenGatePort: 'Gate port (required)',
  tokenGatePortHint: 'Use a fixed port from 1–65535 matching the loopback port in Cloudflare ingress.',
  executable: 'cloudflared executable',
  executableHint: 'A command on PATH or an absolute path.',
  startupTimeoutMs: 'Startup timeout (ms)',
  startupTimeoutMsHint: 'Maximum wait for cloudflared to establish the tunnel.',
  overridden: 'Overridden',
  reset: 'Reset to default',
  discard: 'Discard',
  save: 'Save configuration',
  saving: 'Saving…',
  saveFailed: 'The settings were not saved. Check the configuration or concurrent edits, then retry.',
  required: 'This field is required.',
  invalidNumber: 'Enter a valid number.',
  invalidInteger: 'Enter an integer in range.',
  invalidHostname: 'Enter a valid hostname, such as tunnel.example.com.',
  tokenRefRequired: 'Token mode requires a Tunnel Token credential reference.',
  hostnameRequired: 'Token mode requires a public hostname.',
  fixedPortRequired: 'Token mode requires a fixed port from 1 to 65535.',
}

export type TunnelMode = 'quick' | 'token'

/** Settings values mirrored from the Host schema. Secrets remain credential references. */
export interface AuthTunnelSettings {
  enabled: boolean
  allowRemoteSettings: boolean
  passwordRef: string
  sessionTtlHours: number
  mode: TunnelMode
  tokenRef?: string
  publicHostname?: string
  gatePort: number
  executable: string
  startupTimeoutMs: number
}

export type RuntimePhase = 'stopped' | 'applying' | 'running' | 'error' | 'unavailable'

/** Stable external-store snapshot returned by the Host runtime-status route. */
export interface RuntimeStatusSnapshot {
  phase: RuntimePhase
  running: boolean
  revision: number
  publicUrl?: string
  message?: string
}

type FieldKey = keyof AuthTunnelSettings
type ValidationIssue = Extract<LocaleKey,
  'required' | 'invalidNumber' | 'invalidInteger' | 'invalidHostname'
  | 'tokenRefRequired' | 'hostnameRequired' | 'fixedPortRequired'>
type DraftAction = 'set' | 'unset'

interface Draft {
  values: Record<FieldKey, string>
  edits: Partial<Record<FieldKey, DraftAction>>
  password: string
}

export type SettingsWrite =
  | { field: FieldKey; op: 'set'; value: string | number | boolean }
  | { field: FieldKey; op: 'unset' }

export interface RemoteSettingsCommitRequest {
  expectedRevision: number
  writes: readonly SettingsWrite[]
  password: string
}

interface RemoteSettingsDocument {
  snapshot: SettingsScopeSnapshot<AuthTunnelSettings>
  locale?: 'zh' | 'en'
}

const FIELD_KEYS: readonly FieldKey[] = [
  'enabled', 'allowRemoteSettings', 'passwordRef', 'sessionTtlHours', 'mode', 'tokenRef', 'publicHostname',
  'gatePort', 'executable', 'startupTimeoutMs',
]

const DEFAULT_VALUES: Record<FieldKey, string | number | boolean | undefined> = {
  enabled: true,
  allowRemoteSettings: true,
  passwordRef: 'DSH_WEB_PASSWORD',
  sessionTtlHours: 720,
  mode: 'quick',
  tokenRef: undefined,
  publicHostname: undefined,
  gatePort: 0,
  executable: 'cloudflared',
  startupTimeoutMs: 15_000,
}

const PUBLIC_HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
const MAX_SESSION_TTL_HOURS = Math.floor((Number.MAX_SAFE_INTEGER - Date.now()) / 3_600_000)
const MAX_TIMER_DELAY_MS = 2_147_483_647

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

const RUNTIME_STATUS_PATH = '/dsh-auth-tunnel/status'
const REMOTE_SETTINGS_PATH = '/dsh-auth-tunnel/settings'
const REMOTE_LOCALE_PATH = '/dsh-auth-tunnel/locale'
const TUNNEL_SURFACE_COOKIE = 'dsh_auth_tunnel_surface'
const RUNTIME_STATUS_FAILURE_TOLERANCE = 1
const MAX_LOGIN_BODY_BYTES = 16 * 1024
const INITIAL_RUNTIME_STATUS: RuntimeStatusSnapshot = {
  phase: 'unavailable',
  running: false,
  revision: 0,
}

function parseRuntimeStatus(value: unknown): RuntimeStatusSnapshot {
  const candidate = record(value)
  const phase = candidate.phase
  if (phase !== 'stopped' && phase !== 'applying' && phase !== 'running' && phase !== 'error') {
    throw new Error('invalid auth-tunnel runtime phase')
  }
  if (typeof candidate.running !== 'boolean' || !Number.isSafeInteger(candidate.revision)) {
    throw new Error('invalid auth-tunnel runtime status')
  }
  return {
    phase,
    running: candidate.running,
    revision: candidate.revision as number,
    ...(typeof candidate.publicUrl === 'string' ? { publicUrl: candidate.publicUrl } : {}),
    ...(typeof candidate.message === 'string' ? { message: candidate.message } : {}),
  }
}

/** Whether a password round-trips through a login form within its body limit. */
function fitsLoginForm(password: string): boolean {
  const body = new URLSearchParams({ password }).toString()
  return new TextEncoder().encode(body).byteLength <= MAX_LOGIN_BODY_BYTES
    && new URLSearchParams(body).get('password') === password
}

async function readRuntimeStatus(): Promise<RuntimeStatusSnapshot> {
  const response = await fetch(RUNTIME_STATUS_PATH, {
    cache: 'no-store',
    headers: { accept: 'application/json' },
  })
  if (!response.ok) throw new Error(`auth-tunnel status returned ${String(response.status)}`)
  return parseRuntimeStatus(await response.json())
}

function sameRuntimeStatus(left: RuntimeStatusSnapshot, right: RuntimeStatusSnapshot): boolean {
  return left.phase === right.phase
    && left.running === right.running
    && left.revision === right.revision
    && left.publicUrl === right.publicUrl
    && left.message === right.message
}

/** Polling external store used directly by useSyncExternalStore. */
export class RuntimeStatusStore {
  private snapshot = INITIAL_RUNTIME_STATUS
  private hasSuccessfulRead = false
  private consecutiveFailures = 0
  private readonly listeners = new Set<() => void>()
  private timer: ReturnType<typeof setTimeout> | undefined
  private task: Promise<void> | undefined
  private disposed = false

  constructor(private readonly read: () => Promise<RuntimeStatusSnapshot> = readRuntimeStatus) {}

  readonly getSnapshot = (): RuntimeStatusSnapshot => this.snapshot

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    if (this.listeners.size === 1) void this.refresh()
    return () => {
      this.listeners.delete(listener)
      if (this.listeners.size === 0 && this.timer !== undefined) {
        clearTimeout(this.timer)
        this.timer = undefined
      }
    }
  }

  readonly refresh = (): Promise<void> => {
    if (this.disposed) return Promise.resolve()
    if (this.task !== undefined) return this.task
    this.task = this.pull().finally(() => {
      this.task = undefined
      this.schedule()
    })
    return this.task
  }

  dispose(): void {
    this.disposed = true
    this.listeners.clear()
    if (this.timer !== undefined) clearTimeout(this.timer)
    this.timer = undefined
  }

  private async pull(): Promise<void> {
    let next: RuntimeStatusSnapshot
    try {
      next = await this.read()
      this.consecutiveFailures = 0
      this.hasSuccessfulRead = true
    } catch {
      // Tunnel replacement can briefly interrupt the route used by a public
      // browser. Keep the last confirmed/committed state instead of flashing
      // an unavailable badge after every single failed poll.
      this.consecutiveFailures += 1
      if (this.hasSuccessfulRead && this.consecutiveFailures <= RUNTIME_STATUS_FAILURE_TOLERANCE) return
      next = { phase: 'unavailable', running: false, revision: this.snapshot.revision }
    }
    this.publish(next)
  }

  private publish(next: RuntimeStatusSnapshot): void {
    if (sameRuntimeStatus(this.snapshot, next)) return
    this.snapshot = next
    for (const listener of this.listeners) listener()
  }

  private schedule(): void {
    if (this.disposed || this.listeners.size === 0) return
    if (this.timer !== undefined) clearTimeout(this.timer)
    const delay = this.snapshot.phase === 'applying' ? 500 : 3000
    this.timer = setTimeout(() => {
      this.timer = undefined
      void this.refresh()
    }, delay)
  }
}

/** Map one runtime snapshot to its localized summary label. */
export function runtimeStatusLocaleKey(status: RuntimeStatusSnapshot): LocaleKey {
  if (status.phase === 'running') return 'statusRunning'
  if (status.phase === 'stopped') return 'statusStopped'
  if (status.phase === 'applying') return 'statusApplying'
  if (status.phase === 'unavailable') return 'statusUnavailable'
  return status.running ? 'statusErrorRunning' : 'statusErrorStopped'
}

function owns(value: unknown, field: FieldKey): boolean {
  return Object.hasOwn(record(value), field)
}

function display(value: unknown): string {
  return value === undefined ? '' : String(value)
}

function inherited(snapshot: SettingsScopeSnapshot<AuthTunnelSettings>, field: FieldKey): unknown {
  const base = record(snapshot.base)
  return Object.hasOwn(base, field) ? base[field] : DEFAULT_VALUES[field]
}

function initialDraft(snapshot: SettingsScopeSnapshot<AuthTunnelSettings>): Draft {
  const resolved = record(snapshot.value)
  const values = {} as Record<FieldKey, string>
  for (const field of FIELD_KEYS) {
    values[field] = display(Object.hasOwn(resolved, field) ? resolved[field] : DEFAULT_VALUES[field])
  }
  return { values, edits: {}, password: '' }
}

function draftDirty(draft: Draft): boolean {
  return Object.keys(draft.edits).length !== 0 || draft.password !== ''
}

function numberDraft(text: string): number {
  return text.trim() === '' ? Number.NaN : Number(text)
}

export function parseDraft(draft: Draft): AuthTunnelSettings {
  const mode = draft.values.mode as TunnelMode
  const tokenRef = draft.values.tokenRef.trim()
  const publicHostname = draft.values.publicHostname.trim()
  return {
    enabled: draft.values.enabled === 'true',
    allowRemoteSettings: draft.values.allowRemoteSettings === 'true',
    passwordRef: draft.values.passwordRef.trim(),
    sessionTtlHours: numberDraft(draft.values.sessionTtlHours),
    mode,
    ...(tokenRef === '' ? {} : { tokenRef }),
    ...(publicHostname === '' ? {} : { publicHostname }),
    gatePort: numberDraft(draft.values.gatePort),
    executable: draft.values.executable.trim(),
    startupTimeoutMs: numberDraft(draft.values.startupTimeoutMs),
  }
}

/** Validate the staged card exactly where the user can correct it. */
export function validateSettingsValues(value: AuthTunnelSettings): Partial<Record<FieldKey, ValidationIssue>> {
  const errors: Partial<Record<FieldKey, ValidationIssue>> = {}
  if (value.passwordRef === '') errors.passwordRef = 'required'
  if (!Number.isFinite(value.sessionTtlHours)
    || value.sessionTtlHours < 0.01
    || value.sessionTtlHours > MAX_SESSION_TTL_HOURS) {
    errors.sessionTtlHours = 'invalidNumber'
  }
  if (value.mode !== 'quick' && value.mode !== 'token') errors.mode = 'required'
  if (value.mode === 'token'
    && value.publicHostname !== undefined
    && !PUBLIC_HOSTNAME_PATTERN.test(value.publicHostname)) {
    errors.publicHostname = 'invalidHostname'
  }
  if (!Number.isInteger(value.gatePort) || value.gatePort < 0 || value.gatePort > 65535) {
    errors.gatePort = 'invalidInteger'
  }
  if (value.executable === '') errors.executable = 'required'
  if (!Number.isInteger(value.startupTimeoutMs)
    || value.startupTimeoutMs < 1
    || value.startupTimeoutMs > MAX_TIMER_DELAY_MS) {
    errors.startupTimeoutMs = 'invalidInteger'
  }
  if (value.enabled && value.mode === 'token') {
    if (value.tokenRef === undefined) errors.tokenRef = 'tokenRefRequired'
    if (value.publicHostname === undefined) errors.publicHostname = 'hostnameRequired'
    if (value.gatePort === 0) errors.gatePort = 'fixedPortRequired'
  }
  return errors
}

/** Decode the plugin-owned remote settings document without trusting its JSON shape. */
export function parseRemoteSettingsDocument(input: unknown): RemoteSettingsDocument {
  const root = record(input)
  const section = record(root.settings)
  const raw = record(section.value)
  if (typeof raw.enabled !== 'boolean'
    || typeof raw.allowRemoteSettings !== 'boolean'
    || typeof raw.passwordRef !== 'string'
    || typeof raw.sessionTtlHours !== 'number'
    || (raw.mode !== 'quick' && raw.mode !== 'token')
    || (raw.tokenRef !== undefined && typeof raw.tokenRef !== 'string')
    || (raw.publicHostname !== undefined && typeof raw.publicHostname !== 'string')
    || typeof raw.gatePort !== 'number'
    || typeof raw.executable !== 'string'
    || typeof raw.startupTimeoutMs !== 'number') {
    throw new Error('invalid auth-tunnel settings document')
  }
  const value: AuthTunnelSettings = {
    enabled: raw.enabled,
    allowRemoteSettings: raw.allowRemoteSettings,
    passwordRef: raw.passwordRef,
    sessionTtlHours: raw.sessionTtlHours,
    mode: raw.mode,
    ...(raw.tokenRef === undefined ? {} : { tokenRef: raw.tokenRef }),
    ...(raw.publicHostname === undefined ? {} : { publicHostname: raw.publicHostname }),
    gatePort: raw.gatePort,
    executable: raw.executable,
    startupTimeoutMs: raw.startupTimeoutMs,
  }
  if (Object.keys(validateSettingsValues(value)).length !== 0
    || !Number.isSafeInteger(section.revision)
    || typeof section.writable !== 'boolean') {
    throw new Error('invalid auth-tunnel settings document')
  }
  if (root.locale !== undefined && root.locale !== 'zh' && root.locale !== 'en') {
    throw new Error('invalid auth-tunnel locale preference')
  }
  return {
    snapshot: {
      status: 'ready',
      value,
      base: section.base,
      user: section.user,
      revision: section.revision as number,
      writable: section.writable,
      mode: 'host',
    },
    ...(root.locale === 'zh' || root.locale === 'en' ? { locale: root.locale } : {}),
  }
}

async function readRemoteSettings(): Promise<RemoteSettingsDocument> {
  const response = await fetch(REMOTE_SETTINGS_PATH, {
    cache: 'no-store',
    headers: { accept: 'application/json' },
  })
  if (!response.ok) {
    throw Object.assign(new Error(`auth-tunnel settings returned ${String(response.status)}`), {
      status: response.status,
    })
  }
  return parseRemoteSettingsDocument(await response.json())
}

async function commitRemoteSettings(request: RemoteSettingsCommitRequest): Promise<RemoteSettingsDocument> {
  const response = await fetch(REMOTE_SETTINGS_PATH, {
    method: 'POST',
    cache: 'no-store',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!response.ok) throw new Error(`auth-tunnel settings returned ${String(response.status)}`)
  return parseRemoteSettingsDocument(await response.json())
}

export async function persistRemoteLocale(locale: 'zh' | 'en'): Promise<void> {
  const response = await fetch(REMOTE_LOCALE_PATH, {
    method: 'POST',
    cache: 'no-store',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify({ locale }),
  })
  if (!response.ok) throw new Error(`auth-tunnel locale returned ${String(response.status)}`)
}

const INITIAL_REMOTE_SETTINGS_SNAPSHOT: SettingsScopeSnapshot<AuthTunnelSettings> = {
  status: 'loading',
  value: undefined,
  base: undefined,
  user: undefined,
  revision: undefined,
  writable: false,
  mode: 'host',
}

interface RemoteSettingsTransport {
  read(): Promise<RemoteSettingsDocument>
  commit(request: RemoteSettingsCommitRequest): Promise<RemoteSettingsDocument>
}

/** Durable remote scope backed by the authenticated plugin endpoint, not Harness settings RPCs. */
export class RemoteSettingsStore {
  private snapshot = INITIAL_REMOTE_SETTINGS_SNAPSHOT
  private document: RemoteSettingsDocument | undefined
  private readonly listeners = new Set<() => void>()
  private task: Promise<RemoteSettingsDocument | undefined> | undefined
  private documentGeneration = 0
  private disposed = false

  constructor(private readonly transport: RemoteSettingsTransport = {
    read: readRemoteSettings,
    commit: commitRemoteSettings,
  }) {}

  readonly getSnapshot = (): SettingsScopeSnapshot<AuthTunnelSettings> => this.snapshot

  readonly getDocument = (): RemoteSettingsDocument | undefined => this.document

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    if (this.listeners.size === 1) void this.refresh()
    return () => { this.listeners.delete(listener) }
  }

  readonly refresh = (): Promise<RemoteSettingsDocument | undefined> => {
    if (this.disposed) return Promise.resolve(undefined)
    if (this.task !== undefined) return this.task
    const generation = this.documentGeneration
    this.task = this.transport.read().then((document) => {
      if (!this.disposed && generation === this.documentGeneration) {
        this.document = document
        this.publish(document.snapshot)
      }
      return document
    }, (error: unknown) => {
      if (!this.disposed && generation === this.documentGeneration) {
        const status = record(error).status
        if (status === 401 || status === 403) {
          if (this.snapshot.status === 'ready') {
            const snapshot = { ...this.snapshot, writable: false }
            if (this.document !== undefined) this.document = { ...this.document, snapshot }
            this.publish(snapshot)
          } else if (this.snapshot.status === 'loading') {
            this.publish({ ...INITIAL_REMOTE_SETTINGS_SNAPSHOT, status: 'unavailable' })
          }
        } else {
          if (this.snapshot.status !== 'unavailable') {
            const snapshot: SettingsScopeSnapshot<AuthTunnelSettings> = {
              ...this.snapshot,
              status: 'unavailable',
              writable: false,
            }
            if (this.document !== undefined) this.document = { ...this.document, snapshot }
            this.publish(snapshot)
          }
        }
      }
      return undefined
    }).finally(() => {
      this.task = undefined
    })
    return this.task
  }

  async commit(request: RemoteSettingsCommitRequest): Promise<void> {
    if (this.disposed) return
    try {
      const document = await this.transport.commit(request)
      if (!this.disposed) {
        this.documentGeneration += 1
        const committed = document.snapshot.value?.allowRemoteSettings === false
          ? { ...document, snapshot: { ...document.snapshot, writable: false } }
          : document
        this.document = committed
        this.publish(committed.snapshot)
      }
    } catch (error) {
      const current = this.task
      if (current !== undefined) await current
      await this.refresh()
      throw error
    }
  }

  dispose(): void {
    this.disposed = true
    this.listeners.clear()
  }

  private publish(snapshot: SettingsScopeSnapshot<AuthTunnelSettings>): void {
    if (Object.is(this.snapshot, snapshot)) return
    this.snapshot = snapshot
    for (const listener of this.listeners) listener()
  }
}

function savePlan(draft: Draft, target: AuthTunnelSettings): SettingsWrite[] {
  const writes: SettingsWrite[] = []
  for (const field of FIELD_KEYS) {
    const action = draft.edits[field]
    if (action === undefined) continue
    if (action === 'unset') {
      writes.push({ field, op: 'unset' })
      continue
    }
    const value = target[field]
    if (value === undefined) {
      writes.push({ field, op: 'unset' })
    } else {
      writes.push({ field, op: 'set', value })
    }
  }
  return writes
}

type CardApi = Pick<IApiClient, 'settings' | 'credentials'>
type CardCommit = (
  revision: number | undefined,
  writes: readonly SettingsWrite[],
  current: AuthTunnelSettings,
  target: AuthTunnelSettings,
  password: string,
) => Promise<void>

/** Write a secret in the credential plane; it never enters settings YAML or a response payload. */
export async function commitCredentialWrite(
  api: Pick<IApiClient, 'credentials'>,
  ref: string,
  value: string,
): Promise<void> {
  const response = await api.credentials.set({ ref, value })
  if (!response.result.ok) throw new Error(response.result.error.message)
}

/** Commit the whole edited form in one revision-fenced Host mutation. */
export async function commitSettingsWrites(
  api: Pick<IApiClient, 'settings'>,
  revision: number | undefined,
  writes: readonly SettingsWrite[],
): Promise<SettingsNamespaceView> {
  const ops: SettingsPathOpView[] = writes.map(write => write.op === 'set'
    ? { op: 'set', path: [write.field], value: write.value }
    : { op: 'unset', path: [write.field] })
  const response = await api.settings.mutate({
    ns: SETTINGS_NAMESPACE,
    ops,
    ...(revision === undefined ? {} : { expectedRevision: revision }),
  })
  if (!response.result.ok) throw new Error(response.result.error.message)
  return response.result.value
}

/** Commit either card settings or one password update; the two domains never share a transaction. */
export async function commitCardChanges(
  api: CardApi,
  revision: number | undefined,
  writes: readonly SettingsWrite[],
  current: AuthTunnelSettings,
  target: AuthTunnelSettings,
  password: string,
): Promise<void> {
  if (password !== '' && writes.length !== 0) {
    throw new Error('access password and plugin settings must be saved separately')
  }
  if (password !== '' && !fitsLoginForm(password)) {
    throw new RangeError('access password is too long for the login endpoint')
  }
  if ((current.mode === 'token' && target.passwordRef === current.tokenRef)
    || (target.mode === 'token' && target.passwordRef === target.tokenRef)) {
    throw new Error('access password credential conflicts with the tunnel token credential')
  }
  const changesPasswordRef = target.passwordRef !== current.passwordRef
  if (password !== '') {
    if (changesPasswordRef) throw new Error('save the password credential reference before updating its password')
    await commitCredentialWrite(api, current.passwordRef, password)
    return
  }
  if (changesPasswordRef) {
    const response = await api.credentials.describe({ refs: [target.passwordRef] })
    if (!response.result.ok) throw new Error(response.result.error.message)
    const configured = response.result.value.credentials[target.passwordRef]?.configured
    if (configured !== true) throw new Error('access password credential is not configured')
  }
  if (writes.length !== 0) await commitSettingsWrites(api, revision, writes)
}

const styles: Record<string, CSSProperties> = {
  card: {
    listStyle: 'none', border: '1px solid var(--dsw-alias-border-l2)', borderRadius: 12,
    background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)',
  },
  summary: {
    cursor: 'pointer', padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12,
  },
  heading: { flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 },
  title: { fontSize: 15, fontWeight: 600, lineHeight: 1.4 },
  description: { fontSize: 13, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary)' },
  badge: {
    borderRadius: 999, padding: '1px 8px', fontSize: 11, lineHeight: '17px', whiteSpace: 'nowrap',
    background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-secondary)',
  },
  body: { borderTop: '1px solid var(--dsw-alias-border-l2)', margin: '0 16px', paddingBottom: 8 },
  note: { margin: '12px 0 0', fontSize: 12, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary)' },
  runtime: {
    display: 'flex', flexDirection: 'column', gap: 6, margin: '12px 0 0', padding: '10px 12px',
    borderRadius: 8, background: 'var(--dsw-alias-bg-module-platform)', fontSize: 12, lineHeight: 1.5,
  },
  runtimeRow: { display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12 },
  runtimeLabel: { color: 'var(--dsw-alias-label-tertiary)' },
  runtimeValue: { color: 'var(--dsw-alias-label-primary)', fontWeight: 600, textAlign: 'right' },
  runtimeLink: { color: 'var(--dsw-alias-label-secondary)', overflowWrap: 'anywhere', textAlign: 'right' },
  runtimeError: { margin: 0, color: 'var(--dsw-alias-label-error)', overflowWrap: 'anywhere' },
  section: {
    margin: '14px 0 0', padding: '0 12px', border: '1px solid var(--dsw-alias-border-l2)',
    borderRadius: 10, background: 'var(--dsw-alias-bg-module-platform)',
  },
  sectionHead: { padding: '12px 0 2px' },
  sectionTitle: { margin: 0, fontSize: 13, fontWeight: 600, lineHeight: 1.5 },
  sectionHint: { margin: '3px 0 0', fontSize: 12, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary)' },
  requirements: {
    margin: '4px 0 0', padding: '9px 10px', borderRadius: 8,
    background: 'var(--dsw-alias-bg-layer-3)', fontSize: 12, lineHeight: 1.5,
    color: 'var(--dsw-alias-label-secondary)',
  },
  field: { display: 'flex', flexDirection: 'column', gap: 6, padding: '12px 0' },
  fieldHead: { display: 'flex', alignItems: 'center', gap: 8 },
  label: { flex: 1, minWidth: 0, fontSize: 13, fontWeight: 500, lineHeight: 1.5 },
  reset: {
    border: 0, background: 'none', padding: 0, font: 'inherit', fontSize: 12,
    color: 'var(--dsw-alias-label-secondary)', cursor: 'pointer',
  },
  input: {
    height: 34, boxSizing: 'border-box', padding: '0 12px',
    border: '1px solid var(--dsw-alias-border-l2)', borderRadius: 8,
    background: 'var(--dsw-alias-bg-layer-3)', color: 'var(--dsw-alias-label-primary)',
    font: 'inherit', fontSize: 13,
  },
  hint: { margin: 0, fontSize: 12, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary)' },
  toggle: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 },
  checkbox: { width: 18, height: 18, margin: 0, accentColor: 'var(--dsw-alias-label-primary)' },
  error: { margin: 0, fontSize: 12, lineHeight: 1.5, color: 'var(--dsw-alias-label-error)' },
  footer: {
    display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8,
    padding: '12px 0 4px', borderTop: '1px solid var(--dsw-alias-border-l2)',
  },
  failed: { flex: 1, margin: 0, fontSize: 12, color: 'var(--dsw-alias-label-error)' },
  button: {
    border: '1px solid var(--dsw-alias-border-l2)', borderRadius: 8, padding: '5px 14px',
    background: 'none', color: 'var(--dsw-alias-label-secondary)', font: 'inherit', fontSize: 13,
    cursor: 'pointer',
  },
  save: {
    border: '1px solid transparent', borderRadius: 8, padding: '5px 14px',
    background: 'var(--dsw-alias-label-primary)', color: 'var(--dsw-alias-bg-layer-3)',
    font: 'inherit', fontSize: 13, cursor: 'pointer',
  },
}

type CardProps = PropsRuntime<'settings.plugin.item'> & PropsLocale<typeof LOCALE_NAMESPACE>

interface FieldProps {
  t: CardProps['t']
  field: FieldKey
  label: LocaleKey
  hint: LocaleKey
  value: string
  error?: ValidationIssue
  overridden: boolean
  disabled: boolean
  inputMode?: 'decimal' | 'numeric'
  onEdit: (text: string) => void
  onReset: () => void
}

function Field(props: FieldProps) {
  return (
    <div style={styles.field}>
      <div style={styles.fieldHead}>
        <label style={styles.label} htmlFor={`auth-tunnel-${props.field}`}>{props.t(props.label)}</label>
        {props.overridden ? <span style={styles.badge}>{props.t('overridden')}</span> : null}
        {props.overridden
          ? <button type="button" style={styles.reset} disabled={props.disabled} onClick={props.onReset}>{props.t('reset')}</button>
          : null}
      </div>
      <input
        id={`auth-tunnel-${props.field}`}
        type="text"
        inputMode={props.inputMode}
        style={{ ...styles.input, ...(props.error === undefined ? {} : { borderColor: 'var(--dsw-alias-label-error)' }) }}
        aria-invalid={props.error === undefined ? undefined : true}
        value={props.value}
        disabled={props.disabled}
        onChange={(event) => { props.onEdit(event.target.value) }}
      />
      <p style={props.error === undefined ? styles.hint : styles.error}>
        {props.t(props.error ?? props.hint)}
      </p>
    </div>
  )
}

interface FormProps {
  t: CardProps['t']
  snapshot: SettingsScopeSnapshot<AuthTunnelSettings>
  dirty: boolean
  saving: SaveKind | undefined
  failed: SaveKind | undefined
  onDirty: (dirty: boolean) => void
  onSaveSettings: (draft: Draft) => void
  onSavePassword: (draft: Draft) => void
  onDiscard: () => void
}

type SaveKind = 'settings' | 'password'

function SettingsForm(props: FormProps) {
  const initial = initialDraft(props.snapshot)
  const [draft, setDraft] = useState(initial)
  const target = parseDraft(draft)
  const errors = validateSettingsValues(target)
  const disabled = !props.snapshot.writable || props.saving !== undefined
  const invalid = Object.keys(errors).length !== 0
  const settingsDirty = Object.keys(draft.edits).length !== 0
  const passwordDirty = draft.password !== ''
  const mixedChanges = settingsDirty && passwordDirty

  const edit = (field: FieldKey, text: string): void => {
    const edits = { ...draft.edits }
    if (text === initial.values[field]) delete edits[field]
    else edits[field] = 'set'
    const next = { ...draft, values: { ...draft.values, [field]: text }, edits }
    setDraft(next)
    props.onDirty(draftDirty(next))
  }

  const editPassword = (password: string): void => {
    const next = { ...draft, password }
    setDraft(next)
    props.onDirty(draftDirty(next))
  }

  const reset = (field: FieldKey): void => {
    const edits = { ...draft.edits }
    if (owns(props.snapshot.user, field)) edits[field] = 'unset'
    else delete edits[field]
    const next = {
      ...draft,
      values: { ...draft.values, [field]: display(inherited(props.snapshot, field)) },
      edits,
    }
    setDraft(next)
    props.onDirty(draftDirty(next))
  }

  const overridden = (field: FieldKey): boolean => {
    if (draft.edits[field] === 'unset') return false
    if (draft.edits[field] === 'set') {
      return target[field] !== undefined
    }
    return owns(props.snapshot.user, field)
  }

  const field = (
    key: FieldKey,
    label: LocaleKey,
    hint: LocaleKey,
    inputMode?: 'decimal' | 'numeric',
  ) => (
    <Field
      t={props.t}
      field={key}
      label={label}
      hint={hint}
      value={draft.values[key]}
      overridden={overridden(key)}
      disabled={disabled}
      {...errors[key] === undefined ? {} : { error: errors[key] }}
      {...inputMode === undefined ? {} : { inputMode }}
      onEdit={(text) => { edit(key, text) }}
      onReset={() => { reset(key) }}
    />
  )

  return (
    <>
      <div style={styles.field}>
        <div style={styles.fieldHead}>
          <label style={styles.label} htmlFor="auth-tunnel-enabled">{props.t('enabled')}</label>
          {overridden('enabled') ? <span style={styles.badge}>{props.t('overridden')}</span> : null}
          {overridden('enabled')
            ? <button type="button" style={styles.reset} disabled={disabled} onClick={() => { reset('enabled') }}>{props.t('reset')}</button>
            : null}
        </div>
        <label style={styles.toggle}>
          <input
            id="auth-tunnel-enabled"
            type="checkbox"
            role="switch"
            style={styles.checkbox}
            checked={target.enabled}
            disabled={disabled}
            onChange={(event) => { edit('enabled', String(event.target.checked)) }}
          />
          <span>{props.t(target.enabled ? 'enabledOn' : 'enabledOff')}</span>
        </label>
        <p style={styles.hint}>{props.t('enabledHint')}</p>
      </div>
      <section style={styles.section} aria-labelledby="auth-tunnel-access-section">
        <div style={styles.sectionHead}>
          <h3 id="auth-tunnel-access-section" style={styles.sectionTitle}>{props.t('accessSection')}</h3>
          <p style={styles.sectionHint}>{props.t('accessSectionHint')}</p>
        </div>
        <div style={styles.field}>
          <div style={styles.fieldHead}>
            <label style={styles.label} htmlFor="auth-tunnel-allow-remote-settings">{props.t('allowRemoteSettings')}</label>
            {overridden('allowRemoteSettings') ? <span style={styles.badge}>{props.t('overridden')}</span> : null}
            {overridden('allowRemoteSettings')
              ? <button type="button" style={styles.reset} disabled={disabled} onClick={() => { reset('allowRemoteSettings') }}>{props.t('reset')}</button>
              : null}
          </div>
          <label style={styles.toggle}>
            <input
              id="auth-tunnel-allow-remote-settings"
              type="checkbox"
              role="switch"
              style={styles.checkbox}
              checked={target.allowRemoteSettings}
              disabled={disabled}
              onChange={(event) => { edit('allowRemoteSettings', String(event.target.checked)) }}
            />
            <span>{props.t(target.allowRemoteSettings ? 'enabledOn' : 'enabledOff')}</span>
          </label>
          <p style={styles.hint}>{props.t('allowRemoteSettingsHint')}</p>
        </div>
        {field('passwordRef', 'passwordRef', 'passwordRefHint')}
        <div style={styles.field}>
          <div style={styles.fieldHead}>
            <label style={styles.label} htmlFor="auth-tunnel-password">{props.t('password')}</label>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              id="auth-tunnel-password"
              type="password"
              autoComplete="new-password"
              style={{ ...styles.input, flex: 1, minWidth: 0 }}
              value={draft.password}
              placeholder={props.t('passwordPlaceholder')}
              disabled={disabled}
              onChange={(event) => { editPassword(event.target.value) }}
            />
            <button
              type="button"
              style={{ ...styles.save, ...((!passwordDirty || settingsDirty || disabled) ? { opacity: 0.4, cursor: 'default' } : {}) }}
              disabled={!passwordDirty || settingsDirty || disabled}
              onClick={() => { props.onSavePassword(draft) }}
            >
              {props.t(props.saving === 'password' ? 'passwordUpdating' : 'passwordUpdate')}
            </button>
          </div>
          <p style={styles.hint}>{props.t('passwordHint')}</p>
          {mixedChanges ? <p role="status" style={styles.error}>{props.t('separateSaveHint')}</p> : null}
          {props.failed === 'password' ? <p role="status" style={styles.error}>{props.t('passwordSaveFailed')}</p> : null}
        </div>
        {field('sessionTtlHours', 'sessionTtlHours', 'sessionTtlHoursHint', 'decimal')}
      </section>
      <section style={styles.section} aria-labelledby="auth-tunnel-tunnel-section">
        <div style={styles.sectionHead}>
          <h3 id="auth-tunnel-tunnel-section" style={styles.sectionTitle}>{props.t('tunnelSection')}</h3>
        </div>
        <div style={styles.field}>
          <div style={styles.fieldHead}>
            <label style={styles.label} htmlFor="auth-tunnel-mode">{props.t('mode')}</label>
            {overridden('mode') ? <span style={styles.badge}>{props.t('overridden')}</span> : null}
            {overridden('mode')
              ? <button type="button" style={styles.reset} disabled={disabled} onClick={() => { reset('mode') }}>{props.t('reset')}</button>
              : null}
          </div>
          <select
            id="auth-tunnel-mode"
            style={styles.input}
            value={draft.values.mode}
            disabled={disabled}
            onChange={(event) => { edit('mode', event.target.value) }}
          >
            <option value="quick">{props.t('quick')}</option>
            <option value="token">{props.t('token')}</option>
          </select>
          <p style={styles.hint}>{props.t('modeHint')}</p>
          <p role="note" style={styles.requirements}>
            {props.t(target.mode === 'token' ? 'tokenRequirements' : 'quickRequirements')}
          </p>
        </div>
        {target.mode === 'token' ? field('tokenRef', 'tokenRef', 'tokenRefHint') : null}
        {target.mode === 'token' ? field('publicHostname', 'publicHostname', 'publicHostnameHint') : null}
        {field(
          'gatePort',
          target.mode === 'token' ? 'tokenGatePort' : 'quickGatePort',
          target.mode === 'token' ? 'tokenGatePortHint' : 'quickGatePortHint',
          'numeric',
        )}
      </section>
      <section style={styles.section} aria-labelledby="auth-tunnel-advanced-section">
        <div style={styles.sectionHead}>
          <h3 id="auth-tunnel-advanced-section" style={styles.sectionTitle}>{props.t('advancedSection')}</h3>
          <p style={styles.sectionHint}>{props.t('advancedSectionHint')}</p>
        </div>
        {field('executable', 'executable', 'executableHint')}
        {field('startupTimeoutMs', 'startupTimeoutMs', 'startupTimeoutMsHint', 'numeric')}
      </section>
      <div style={styles.footer}>
        {props.failed === 'settings' ? <p role="status" style={styles.failed}>{props.t('saveFailed')}</p> : null}
        <button
          type="button"
          style={{ ...styles.button, ...((!props.dirty || props.saving !== undefined) ? { opacity: 0.4, cursor: 'default' } : {}) }}
          disabled={!props.dirty || props.saving !== undefined}
          onClick={() => {
            setDraft(initial)
            props.onDirty(false)
            props.onDiscard()
          }}
        >
          {props.t('discard')}
        </button>
        <button
          type="button"
          style={{ ...styles.save, ...((!settingsDirty || passwordDirty || invalid || disabled) ? { opacity: 0.4, cursor: 'default' } : {}) }}
          disabled={!settingsDirty || passwordDirty || invalid || disabled}
          onClick={() => { props.onSaveSettings(draft) }}
        >
          {props.t(props.saving === 'settings' ? 'saving' : 'save')}
        </button>
      </div>
    </>
  )
}

interface ShellState {
  revision: number | undefined
  formVersion: number
  dirty: boolean
  saving: SaveKind | undefined
  failed: SaveKind | undefined
}

function AuthTunnelCard(props: CardProps & {
  scope: Pick<SettingsScope<AuthTunnelSettings>, 'getSnapshot' | 'subscribe'>
  commit: CardCommit
  runtime: RuntimeStatusStore
}) {
  const snapshot = useSyncExternalStore(props.scope.subscribe, props.scope.getSnapshot)
  const runtime = useSyncExternalStore(
    props.runtime.subscribe,
    props.runtime.getSnapshot,
    props.runtime.getSnapshot,
  )
  const [shell, setShell] = useState<ShellState>({
    revision: snapshot.revision,
    formVersion: 0,
    dirty: false,
    saving: undefined,
    failed: undefined,
  })

  // A new Host revision is a new form identity. Reset during render rather
  // than mirroring an external store through an Effect.
  if (shell.saving === undefined && shell.revision !== snapshot.revision) {
    setShell({ revision: snapshot.revision, formVersion: shell.formVersion + 1, dirty: false, saving: undefined, failed: undefined })
  }

  if (snapshot.status !== 'ready' || snapshot.value === undefined) return null
  const snapshotValue = snapshot.value

  const save = async (kind: SaveKind, draft: Draft): Promise<void> => {
    const target = parseDraft(draft)
    const writes = kind === 'settings' ? savePlan(draft, target) : []
    const password = kind === 'password' ? draft.password : ''
    const current = snapshotValue
    const startingRevision = snapshot.revision
    setShell(current => ({ ...current, saving: kind, failed: undefined }))
    let succeeded = false
    try {
      await props.commit(
        startingRevision,
        writes,
        current,
        kind === 'settings' ? target : current,
        password,
      )
      succeeded = true
    } catch {
      // The generic failure copy is intentional: credential references and
      // Host diagnostics must not be reflected into the settings page.
    }
    const latest = props.scope.getSnapshot()
    const failed = !succeeded
    const draftSurvived = latest.revision === startingRevision
    setShell(current => ({
      revision: latest.revision,
      formVersion: failed ? current.formVersion : current.formVersion + 1,
      dirty: failed && draftSurvived,
      saving: undefined,
      failed: failed ? kind : undefined,
    }))
    void props.runtime.refresh()
  }

  return (
    <li style={styles.card}>
      <details>
        <summary style={styles.summary}>
          <span style={styles.heading}>
            <span style={styles.title}>{props.t('title')}</span>
            <span style={styles.description}>{props.t('description')}</span>
          </span>
          <span style={styles.badge}>{props.t(runtimeStatusLocaleKey(runtime))}</span>
          {shell.dirty ? <span style={styles.badge}>{props.t('unsaved')}</span> : null}
        </summary>
        <div style={styles.body}>
          {!snapshot.writable ? <p role="status" style={styles.note}>{props.t('readOnly')}</p> : null}
          <div role="status" style={styles.runtime}>
            <div style={styles.runtimeRow}>
              <span style={styles.runtimeLabel}>{props.t('status')}</span>
              <span style={styles.runtimeValue}>{props.t(runtimeStatusLocaleKey(runtime))}</span>
            </div>
            {runtime.publicUrl === undefined ? null : (
              <div style={styles.runtimeRow}>
                <span style={styles.runtimeLabel}>{props.t('publicUrl')}</span>
                <a href={runtime.publicUrl} target="_blank" rel="noreferrer" style={styles.runtimeLink}>{runtime.publicUrl}</a>
              </div>
            )}
            {runtime.message === undefined ? null : <p style={styles.runtimeError}>{runtime.message}</p>}
          </div>
          <p role="note" style={styles.note}>{props.t('live')}</p>
          <SettingsForm
            key={`${String(snapshot.revision)}:${String(shell.formVersion)}`}
            t={props.t}
            snapshot={snapshot}
            dirty={shell.dirty}
            saving={shell.saving}
            failed={shell.failed}
            onDirty={(dirty) => {
              setShell(current => ({ ...current, dirty, failed: undefined }))
            }}
            onSaveSettings={(draft) => { void save('settings', draft) }}
            onSavePassword={(draft) => { void save('password', draft) }}
            onDiscard={() => {
              setShell(current => ({ ...current, dirty: false, failed: undefined }))
            }}
          />
        </div>
      </details>
    </li>
  )
}

/**
 * Promote the password-gated public surface before settings consumers
 * classify the connection. The Gate already authenticates every page request
 * and rewrites the proxied Host/Origin onto the loopback trust boundary; this
 * client-side flag only lets the stock UI use that authenticated route.
 * @param connection - the shared browser connection handle.
 * @param cookie - the current document cookie string (overridable by tests).
 * @returns whether this page arrived through the non-loopback tunnel surface.
 */
export function promoteTunnelConnection(
  connection: ConnectionHandle,
  cookie = typeof document === 'undefined' ? '' : document.cookie,
): boolean {
  const tunneled = cookie.split(';').some((segment) => {
    const [name, value] = segment.trim().split('=', 2)
    return name === TUNNEL_SURFACE_COOKIE && value === '1'
  })
  if (connection.isLoopback || !tunneled) return false
  // The shared handle owns connection classification. The tunnel publishes
  // its stronger transport boundary there
  // before settings scopes snapshot it during their own plugin activation.
  ;(connection as { isLoopback: boolean }).isLoopback = true
  return true
}

/** Start as soon as the connection exists; the settings UI mounts in a child fiber later. */
export const inject = ['connection']

/** Adopt the persisted language and attempt each later change once. */
export function installRemoteLocalePersistence(ctx: ClientContext, store: RemoteSettingsStore): () => void {
  let disposed = false
  let loaded = false
  let adopting = false
  let pending: 'zh' | 'en' | undefined
  const persist = (locale: 'zh' | 'en'): void => {
    if (disposed) return
    void persistRemoteLocale(locale).catch(() => {
      console.warn('auth-tunnel: language preference was not saved')
    })
  }
  const stop = ctx.on('locale/change', (snapshot) => {
    if (adopting) return
    if (!loaded) {
      pending = snapshot.active
      return
    }
    persist(snapshot.active)
  })
  const adoptLoadedDocument = (): void => {
    if (disposed) return
    const document = store.getDocument()
    if (document === undefined) return
    if (loaded) return
    loaded = true
    if (pending !== undefined) {
      persist(pending)
      pending = undefined
      return
    }
    if (document?.locale === undefined) return
    adopting = true
    try {
      ctx.locale.setLocale(document.locale)
    } finally {
      adopting = false
    }
  }
  const stopStore = store.subscribe(adoptLoadedDocument)
  adoptLoadedDocument()
  return () => {
    disposed = true
    stopStore?.()
    stop()
  }
}

/** Register the browser half under the Host namespace's key. */
export function apply(ctx: ClientContext): void {
  const connection = ctx.get('connection') as ConnectionHandle
  const remoteTunnel = promoteTunnelConnection(connection)
  ctx.inject(['slots', 'locale', 'remote', 'settingsScope'], (uiCtx: ClientContext) => {
    mountSettingsCard(uiCtx, connection, remoteTunnel)
  })
}

/** Mount the keyed card after its presentation and settings services activate. */
function mountSettingsCard(ctx: ClientContext, connection: ConnectionHandle, remoteTunnel: boolean): void {
  let scope: Pick<SettingsScope<AuthTunnelSettings>, 'getSnapshot' | 'subscribe'>
  let commit: CardCommit
  if (!remoteTunnel) {
    const source = ctx.settingsScope.bind<AuthTunnelSettings>({ namespace: SETTINGS_NAMESPACE })
    // Methods on the scope controller use `this`; stable wrappers are also the
    // stable subscribe/getSnapshot pair required by useSyncExternalStore.
    scope = {
      getSnapshot: () => source.getSnapshot(),
      subscribe: listener => source.subscribe(listener),
    }
    commit = (...args) => commitCardChanges(connection.api, ...args)
  } else {
    const remoteStore = new RemoteSettingsStore()
    scope = remoteStore
    commit = (revision, writes, _current, _target, password) => revision === undefined
      ? Promise.reject(new Error('settings revision is unavailable'))
      : remoteStore.commit({ expectedRevision: revision, writes, password })
    ctx.effect(() => installRemoteLocalePersistence(ctx, remoteStore), 'auth-tunnel: remote locale persistence')
    ctx.effect(() => () => { remoteStore.dispose() }, 'auth-tunnel: remote settings')
  }
  const runtime = new RuntimeStatusStore()
  ctx.effect(() => () => { runtime.dispose() }, 'auth-tunnel: runtime status')
  ctx.effect(() => ctx.locale.register(LOCALE_NAMESPACE, { zh, en }), 'auth-tunnel: settings dictionaries')
  const Card = (props: CardProps) => <AuthTunnelCard {...props} scope={scope} commit={commit} runtime={runtime} />
  ctx.slots.inject('settings.plugin.item', () => ctx.slots.register({
    name: 'settings.plugin.item',
    key: SETTINGS_NAMESPACE,
    locale: LOCALE_NAMESPACE,
  }, Card))
}
