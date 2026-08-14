# @deepseek-ai/dsh-auth-tunnel

English | [中文](README.zh.md)

This plugin publishes the existing DeepSeek Harness WebServer through Cloudflare Tunnel and contributes shared-password authentication to the Web bundle's global access service. It does not create a proxy or enumerate application routes.

```text
public browser
  -> Cloudflare edge (TLS)
  -> cloudflared on this host
  -> WebServer global access guard  <- login page and cookie authentication
  -> every HTTP, WebSocket, and future plugin route

loopback browser
  -> WebServer global access guard  <- classified local, no password prompt
```

The plugin injects `webServer`, `webAccess`, and `credentials`. A Harness version without the global `webAccess` service leaves the plugin pending instead of starting an unprotected tunnel. The core guard runs before route matching, so routes registered by other plugins after this plugin loads receive the same authentication automatically. Accepted requests keep their original public `Host` and `Origin`; the core connection layer trusts the server-authored authenticated grant while retaining its same-origin and DNS-rebinding checks.

The same request classification is projected into the browser. An authenticated public page can use the Host configuration plane, while native desktop actions remain local. The Web bundle can register native and in-app directory providers together: a loopback page uses the OS picker and a public page uses the in-app browser in the same process.

## Authentication

The login page is `/dsh-auth-tunnel/login`. A successful URL-encoded POST mints the `dsh_auth_tunnel` cookie with `HttpOnly`, `SameSite=Strict`, and `Secure` when Cloudflare reports HTTPS. The cookie contains an absolute expiry and an HMAC keyed by `SHA-256(password)`; the password itself is never stored in the cookie.

The password reference is resolved on every request. Rotating or deleting the referenced credential invalidates existing sessions immediately. `GET` or `POST /dsh-auth-tunnel/logout` clears the cookie. Login bodies are limited to 16 KiB and must use `application/x-www-form-urlencoded`.

Unauthenticated document navigations redirect to the login page. Other HTTP requests receive 401 JSON, and upgrade requests receive 401 before the socket closes. There are no public asset exceptions: the Web app manifest requests credentials with `crossorigin="use-credentials"`.

## Cloudflare modes

- `quick` runs `cloudflared tunnel --url http://127.0.0.1:<webserver-port> --no-autoupdate` and discovers the generated `*.trycloudflare.com` URL from process output.
- `token` runs `cloudflared tunnel run --no-autoupdate`, supplies the Tunnel Token through `TUNNEL_TOKEN`, and reports `https://<publicHostname>`. Configure the named tunnel's dashboard ingress to the WebServer address, normally `http://localhost:3080` or the port passed to `dsh web --port`.

Activation fails before exposing a URL when the password is missing, mode-specific settings conflict, the token is missing, cloudflared cannot start, cloudflared exits before readiness, or startup times out. Disposal removes the authenticator and terminates cloudflared; it does not own or close the WebServer.

## Configuration

| Key | Type | Default | Effect |
|---|---|---|---|
| `passwordRef` | credential reference | `DSH_WEB_PASSWORD` | Shared access password; an unresolved or empty value fails activation. |
| `sessionTtlHours` | number >= 0.01 | `720` | Absolute cookie lifetime in hours. |
| `mode` | `quick` \| `token` | `quick` | Tunnel mode. |
| `tokenRef` | credential reference | - | Tunnel Token reference; required in token mode. |
| `publicHostname` | string | - | Dashboard-bound hostname; required in token mode. |
| `executable` | string | `cloudflared` | PATH name or absolute cloudflared path. |
| `startupTimeoutMs` | integer >= 1 | `15000` | Readiness timeout. |

## Installation

Install this repository as a Web-profile bundle:

```sh
dsh plugin --profile web add <package>
```

`<package>` may be the npm name, Git URL, or a `file:` path. The bundled patch inserts the `auth-tunnel` row with quick-mode defaults. Store the password in the Harness credential provider, for example `$DSH_HOME/.credentials.yaml`:

```yaml
DSH_WEB_PASSWORD: 'pick-a-long-random-password'
```

For a named tunnel, override the row in `~/.dsh/profiles/web/cordis.patch.yml`:

```yaml
- id: auth-tunnel
  config:
    mode: token
    tokenRef: DSH_TUNNEL_TOKEN
    publicHostname: gui.example.com
```

Then configure `gui.example.com` in the Cloudflare dashboard to target the active Harness WebServer port and store both credential values:

```yaml
DSH_WEB_PASSWORD: 'pick-a-long-random-password'
DSH_TUNNEL_TOKEN: 'eyJhIjo...'
```

## Runtime facts

After readiness, the process prints `cloudflare tunnel: <public-url>`. When the optional services exist, the plugin contributes `DSH_PUBLIC_URL` to shell environments and an `app:public-access` system-prompt section instructing the model to share the URL but never the password.

## Limitations

- Every password holder receives the same authenticated Host access. There are no per-user identities, rate limits, lockouts, or server-side session revocation beyond password rotation.
- An unexpected cloudflared exit is logged but not restarted automatically.
- Quick-tunnel hostnames change on every run.
- Direct loopback access intentionally bypasses the password. This does not defend against hostile processes already running on the Host.
- Token mode relies on the dashboard ingress matching the WebServer port; changing `dsh web --port` requires updating that ingress.
