# ⚡ `vaelspire` (Single-Binary CLI + Server)

The opinionated, ultra-lightweight **Vaelspire Core** binary — combining a `clap` CLI and an Axum HTTP server in one zero-dependency executable (embedded SQLite via `neotales-dbapi`).

## 🚀 Quickstart

```bash
# 1. Generate a 256-bit hex key
export VAELSPIRE_AUTH_KEY=$(cargo run -p vaelspire -- keygen)

# 2. Optional: bootstrap an initial admin account on first boot
export VAELSPIRE_ADMIN_EMAIL="admin@example.test"
export VAELSPIRE_ADMIN_PASSWORD="correct horse battery staple"

# 3. Start locally over plain HTTP (use TLS + omit --insecure-http in production!)
cargo run -p vaelspire -- serve --bind 127.0.0.1:8080 --sqlite ./vaelspire.sqlite --insecure-http
```

## 🛠️ CLI Subcommands

| Command | Description |
| :--- | :--- |
| `vaelspire serve` | Start the HTTP server (Auth API, `/forward-auth`, `/metrics`, `/health`, `/ready`) |
| `vaelspire migrate` | Apply and verify database migrations, then exit |
| `vaelspire admin bootstrap` | Idempotently create the default tenant and initial `owner` admin user |
| `vaelspire keygen` | Output a cryptographically random 64-character hex digest key |

## 🔌 Reverse-Proxy `/forward-auth`

Point Caddy, Traefik, or Nginx at `GET /forward-auth`. Vaelspire verifies either:
1. The session cookie (`neotales.session` by default), or
2. `Authorization: Bearer <api-key>` / `X-API-Key: <api-key>`.

On `200 OK`, Vaelspire returns identity headers your upstream app can trust:
- `X-Vaelspire-User-Id`
- `X-Vaelspire-Tenant-Id`
- `X-Vaelspire-Email`
- `X-Vaelspire-Auth-Method` (`session` or `api_key`)
- `X-Vaelspire-Session-Id` or `X-Vaelspire-Api-Key-Id`

On failure, Vaelspire returns `401 Unauthorized` (or `302 Found` to `--forward-auth-login-url` when explicitly configured).
