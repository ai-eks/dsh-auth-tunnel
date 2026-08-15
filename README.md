# DSH Auth Tunnel

English | [中文](README.zh.md)

Expose the DeepSeek Harness Web GUI through a password-protected Cloudflare Tunnel without changing `deepseek-harness` itself.

## Usage

### Prerequisites

- The `dsh` CLI and pnpm are available on `PATH`; the plugin command creates the Web profile when it is missing.
- `cloudflared` available on `PATH`, or an absolute `executable` configured for the plugin.
- A long, random shared password stored as a DSH credential.

### Install

Install the bundle from Git:

```sh
dsh plugin --profile web add github:ai-eks/dsh-auth-tunnel
```

Git installs build the checked-out sources through `prepare`. pnpm 10 and later may first ask you to allow that build in the profile's `pnpm-workspace.yaml`; follow the path and exact package key printed by `dsh` and then rerun the command.

For a local checkout, build it before adding the path:

```sh
cd /path/to/dsh-auth-tunnel
pnpm install
dsh plugin --profile web add .
```

The bundle inserts and enables the `auth-tunnel` row in quick mode and replaces the Host-native directory picker with the in-app browser picker. No `deepseek-harness` source edit or extra profile row is required.

### Quick mode

Quick mode is the default. Store the shared password in `$DSH_HOME/.credentials.yaml` (`$DSH_HOME` defaults to `~/.dsh`):

```yaml
DSH_WEB_PASSWORD: 'replace-with-a-long-random-password'
```

Start the Web profile:

```sh
dsh web
```

After the tunnel is ready, the terminal prints:

```text
cloudflare tunnel: https://<random>.trycloudflare.com
```

Open that URL and enter `DSH_WEB_PASSWORD` on the login page. Share the URL, not the password. The active row also appears in Web Settings → Plugins.

### Named tunnel mode

Use token mode when the public hostname must remain stable. Create a named Cloudflare Tunnel, bind a hostname such as `gui.example.com`, and point its dashboard ingress at a fixed loopback gate such as `http://127.0.0.1:7677`.

Store both credentials in `$DSH_HOME/.credentials.yaml`:

```yaml
DSH_WEB_PASSWORD: 'replace-with-a-long-random-password'
DSH_TUNNEL_TOKEN: 'eyJhIjo...'
```

Override the bundle row in `$DSH_HOME/profiles/web/cordis.patch.yml`:

```yaml
- id: auth-tunnel
  disabled: false
  config:
    mode: token
    tokenRef: DSH_TUNNEL_TOKEN
    publicHostname: gui.example.com
    gatePort: 7677
```

`publicHostname` is only the DNS hostname: do not include `https://`, a port, or a path. The profile patch is applied after bundle layers and is watched by the launcher, so saving it reloads the row.

### Configuration reference

| Key | Type | Default | Effect |
|---|---|---|---|
| `passwordRef` | string (credential-ref) | `DSH_WEB_PASSWORD` | Credential reference resolving to the shared access password; unconfigured fails the boot. |
| `sessionTtlHours` | number ≥ 0.01 | `720` | Cookie lifetime in hours (30 days). |
| `mode` | `quick` \| `token` | `quick` | Ephemeral quick tunnel or named token tunnel. |
| `tokenRef` | string (credential-ref) | — | Tunnel Token reference; `token` mode only. |
| `publicHostname` | DNS hostname | — | Named-tunnel hostname without scheme, port, or path; `token` mode only. |
| `gatePort` | integer 0…65535 | `0` | Loopback gate port; `token` mode requires a fixed non-zero value. |
| `executable` | string | `cloudflared` | `cloudflared` PATH name or absolute path. |
| `startupTimeoutMs` | integer ≥ 1 | `15000` | How long activation waits for tunnel readiness. |

## Known limitations

- **Shared password, single-user trust**: every password holder receives the whole Web GUI, including its Host configuration plane. There is no rate limiting, lockout, per-user session, or server-side revocation list. Password rotation invalidates every session; stronger deployments should use Cloudflare Access or another identity-aware proxy.
- **Single tunnel, no automatic restart**: an unexpected `cloudflared` exit is logged, but the tunnel does not restart; restart `dsh`.
- **Quick URLs change on every start**: use token mode and a domain when a stable URL is required.
- **Loopback remains unauthenticated**: the password protects the tunnel path only. Local browsers and processes can still reach the original Web GUI directly.
- **Minimal child environment**: the child inherits only `PATH`, `HOME`, and `TMPDIR`. A corporate proxy must be configured for `cloudflared` outside this plugin.
- **Loopback HTTP is plaintext**: the gate and upstream WebServer communicate over same-host loopback HTTP; TLS terminates at Cloudflare.
- **One directory-picker interaction per boot**: enabling the bundle uses the in-app browser picker for local clients too because the Web app cannot select native and browser pickers per connection.

## How it works

```text
public client
  → Cloudflare edge (TLS)
  → cloudflared (this host)
  → password gate, loopback only
  → existing loopback WebServer
```

### Password gate and proxy

The plugin requires the `webServer` and `credentials` services. It starts its own loopback `node:http` gate, resolves the configured password reference, and points `cloudflared` at that gate. The original WebServer and every route contributed by other plugins remain unchanged behind it.

Unauthenticated browser navigation is redirected to `/dsh-auth-tunnel/login`; other unauthenticated requests receive a small 401 response. A successful login mints the `HttpOnly; SameSite=Strict` `dsh_auth_tunnel` cookie, signed with an HMAC key derived from the password. The credential is resolved on every request, so rotating it immediately invalidates existing sessions. `GET` or `POST /dsh-auth-tunnel/logout` clears the cookie.

The gate caps login bodies at 16 KiB and proxies authenticated HTTP and WebSocket traffic. It rewrites `Host` and a matching browser `Origin` to the loopback upstream authority so the WebServer's DNS-rebinding and same-origin checks continue to see their trusted address. Foreign or opaque origins remain unchanged. HTTP hop-by-hop headers are removed on both proxy legs and regenerated per connection; upgrade handshakes retain their required fields. Client disconnects cancel the corresponding upstream request.

The only unauthenticated upstream application route is read-only `GET`/`HEAD /manifest.webmanifest`. Browsers fetch this metadata without credentials unless the page opts into credentialed manifest requests, and the file contains only public application metadata.

### Directory picker

The bundle disables the boot-selected native directory picker and mounts the in-app directory browser. A public `host.pickDirectory` request cannot operate an OS dialog on the Host display and otherwise waits until Cloudflare returns 524. The browser picker works for both local and public clients without per-route hooks.

### Tunnel lifecycle

- **quick** runs `cloudflared tunnel --url http://127.0.0.1:<gate>` and reads the generated `*.trycloudflare.com` URL from child output.
- **token** passes the Tunnel Token through `TUNNEL_TOKEN` in the child environment, runs `cloudflared tunnel run`, and waits for the registered-connection marker. The token never appears in argv.

Activation completes only after the gate is listening and the tunnel reports readiness. Invalid credentials or mode fields, an occupied gate port, a missing executable, an early child exit, and readiness timeout all fail the plugin load before a public URL is announced. Disposal closes the gate, sends `SIGTERM` to `cloudflared`, escalates to `SIGKILL` after 2000 ms when necessary, and removes the shell and prompt contributions.

## Model experience

Once the tunnel is ready, the plugin publishes `DSH_PUBLIC_URL` through the optional shell-env service and adds the `app:public-access` system-prompt section through the optional system-prompt service. Without this row, neither contribution exists.

The rendered prompt section is:

```markdown
This instance is also reachable from the public internet at <publicUrl> through a Cloudflare Tunnel, protected by the instance's shared access password. Share that URL — never the password — when the user asks to open this GUI from another device or network. All sessions, tools, and files still run on this host.
```

The section is static for the life of the tunnel process, so it does not invalidate the KV cache across turns.
