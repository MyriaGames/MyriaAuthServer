# MyriaAuthServer

MyriaAuthServer is the authentication and account service for **Myria**. It owns exactly one job: registering accounts, verifying logins, handling username/password changes and account deletion, and issuing the JSON Web Tokens that every Myria realm server trusts. It holds **no character or game-state data** — that lives entirely on the realm servers (see [Architecture](#architecture)). On account deletion it also reaches out to every configured realm's internal admin API to cascade-delete that account's characters, since this service has no direct database access to them.

## API surface

All endpoints live under `/api/auth` (`Controllers/AuthController.cs`) except realm discovery, which lives under `/api/realms` (`Controllers/RealmsController.cs`). `register` and `login` (and, by extension, every route on the controller, since rate limiting is applied per-controller) are throttled to 5 requests/minute per client IP.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/register` | Create a new account (username + password) and return a signed JWT. |
| `POST` | `/api/auth/login` | Verify credentials and return a signed JWT. |
| `DELETE` | `/api/auth/account` | Re-verify the password, delete the account's characters on every configured realm, then delete the account (GDPR Art. 17 right to erasure). |
| `PUT` | `/api/auth/username` | Re-verify the password, rename the account on every configured realm plus locally, and return a freshly-minted token bound to the new username. |
| `PUT` | `/api/auth/password` | Re-verify the old password and set a new one, returning a freshly-minted token. |
| `PUT` | `/api/auth/admin/password` | Operator-only rescue path to force-reset a locked-out account's password. Requires the caller to be on loopback **and** present the shared `X-Internal-Secret` header — not called by any game client. |
| `GET` | `/api/realms` | Returns the static list of configured realms (id/name/URL) for client-side realm selection. This is discovery only, not a health check — each realm exposes its own status endpoint for online/character-count. |

`register` requires a username of 3–50 characters (letters/digits/underscore/hyphen) and a password of 8–128 characters. Successful register/login/username-change/password-change responses all share the same shape: `{ token, username, expiresAt }`.

## Architecture

Myria is split across several repositories under the [MyriaGames](https://github.com/MyriaGames) org:

- **MyriaAuthServer** (this repo) — the single account/identity service described here.
- [MyriaServer](https://github.com/MyriaGames/MyriaServer) — one or more realm servers, each owning its own characters/world-state database. Realms trust JWTs minted by this service purely via a shared signing key (`Jwt:Key`/`Issuer`/`Audience`) — no callback to this service is needed to validate a token. Realms also expose an internal admin API (`/api/admin/characters/...`) that this service calls, authenticated with a shared `X-Internal-Secret` header, to cascade-delete or rename a user's characters when an account is deleted or renamed here.
- [MyriaRPG](https://github.com/MyriaGames/MyriaRPG) — the WPF game client.
- [ConsoleWorldRPG](https://github.com/MyriaGames/ConsoleWorldRPG) — the console client.
- [MyriaWorld](https://github.com/MyriaGames/MyriaWorld) — a MonoGame client, currently in development.
- [MyriaLib](https://github.com/MyriaGames/MyriaLib) — shared library code used across the above.

All of the clients above call this service to register/log in/manage an account, then use the returned JWT to talk directly to a realm server for everything gameplay-related.

## Requirements

- .NET 8 SDK (targets `net8.0`, `Microsoft.NET.Sdk.Web`)
- No external database — accounts are stored in a local SQLite file.

## Getting started / local development

```
dotnet run
```

Even with a launch profile configured, Kestrel binds to the endpoint(s) defined in `appsettings.json` (`Kestrel:Endpoints`), overriding `Properties/launchSettings.json`'s URLs. In `Development`, that means the service listens on **http://localhost:5050**. Swagger UI is available at `/swagger` in Development.

The service boots fine in Development using the placeholder secrets and default `Realms` list already committed in `appsettings.json` — no extra setup is required to run and exercise the API locally. EF Core migrations are applied automatically on startup (`db.Database.Migrate()`), creating `Storage/auth.db` next to the executable on first run.

For a full walkthrough of deploying this to a real server — certificates, secrets, systemd, updates — see [SETUP.md](SETUP.md).

## Configuration for Production deployment

At startup, if `ASPNETCORE_ENVIRONMENT=Production`, `Program.cs` **refuses to start** unless all of the following are satisfied. Config keys use ASP.NET Core's double-underscore environment-variable binding (`Section:Key` → `Section__Key`); alternatively, provide a local, gitignored `appsettings.Production.json`.

| Config key | Env var | Requirement |
|---|---|---|
| `Jwt:Key` | `Jwt__Key` | Must be set and not the placeholder; must be **at least 32 bytes** (it signs every player's session token, HMAC-SHA256). Must stay byte-identical to the `Jwt` block on every realm, since realms trust tokens by shared key with no callback. |
| `Security:Pepper` | `Security__Pepper` | Must be set and not the placeholder. Mixed into every password hash (PBKDF2-SHA512, 200,000 iterations, per-user salt) server-wide. |
| `Admin:InternalSecret` | `Admin__InternalSecret` | Must be set and not the placeholder. Sent as the `X-Internal-Secret` header on every admin call to a realm, and required by the loopback-only `admin/password` endpoint. Must stay byte-identical to every realm's `Admin:InternalSecret`. |
| `Kestrel:Endpoints:Https:Url` | `Kestrel__Endpoints__Https__Url` | Must be set. Login/register submit a password, so Production refuses to serve them over plain HTTP. |
| `Kestrel:Endpoints:Https:Certificate:Path` | `Kestrel__Endpoints__Https__Certificate__Path` | Must be set and point to a file that exists. |
| `Kestrel:Endpoints:Https:Certificate:Password` | `Kestrel__Endpoints__Https__Certificate__Password` | Must be set (the certificate's password). |

Other configuration:

- `ConnectionStrings:DefaultConnection` — SQLite connection string (`Data Source=Storage/auth.db` by default), resolved relative to the executable's own directory regardless of the process's working directory.
- `Realms` — an array of `{ Id, Name, Url }` objects, one per realm server this account service should call for admin cascade-delete/rename operations and advertise via `GET /api/realms`.
- `Jwt:Issuer`, `Jwt:Audience`, `Jwt:ExpirationHours` — token issuer/audience/lifetime; must match what each realm expects.

**Plain-HTTP realms are allowed but loudly warned about.** A realm URL in `Realms` that isn't `localhost`/`127.0.0.1`/`::1` and uses `http://` instead of `https://` is treated as an intentional but risky choice, for operators who haven't put every realm behind TLS yet: `Admin:InternalSecret` transits that connection in the clear. This does **not** block startup, but it produces a structured `LogWarning` and a bright red console banner at boot, plus a structured warning on every individual admin call made to that realm at runtime.

Note also the rate limiter and the admin-loopback check both key off the real TCP peer address (`ctx.Connection.RemoteIpAddress`) — this service never trusts `X-Forwarded-For`. If you put a reverse proxy on the same host in front of Kestrel, either terminate TLS at Kestrel directly instead, or configure ASP.NET Core's forwarded-headers middleware with an explicit trusted-proxy allowlist; otherwise every request will appear to originate from `127.0.0.1`, collapsing the per-IP rate limit and the admin-endpoint loopback check.

## Legal / Privacy

This service is the account/PII data controller for Myria — it is where account data actually lives. Real, published legal documents (Austrian/GDPR) covering this project live in [`Legal/`](Legal/):

- [`Legal/Impressum.md`](Legal/Impressum.md) — legal notice / operator disclosure (Impressum).
- [`Legal/Datenschutzerklaerung.md`](Legal/Datenschutzerklaerung.md) — privacy policy, describing exactly what account data this service stores and why.
- [`Legal/Nutzungsbedingungen.md`](Legal/Nutzungsbedingungen.md) — terms of use.

## License

MIT — see [`LICENSE`](LICENSE).

## Status

Active alpha. This is a hobby project backend under ongoing development; expect breaking changes.
