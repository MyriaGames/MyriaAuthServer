# Setup & Deployment Guide — Myria.Server.Auth

`MyriaAuthServer` is normally deployed **bundled with a realm server** — the official release zip
packages it into an `auth/` subfolder alongside `MyriaServer`, and a single script
(`run-production.sh`, which lives in the `MyriaGames/MyriaServer` repo) starts both together. If
that's your situation, **use
[Myria.Server.Realm's SETUP.md](https://github.com/MyriaGames/MyriaServer/blob/master/SETUP.md)
instead** — it's the complete, combined production runbook (certificates, secrets, systemd,
updates) and covers this service's config as part of that.

This guide covers **local development** and **running this service on its own** — useful if
you're deploying it on a separate host from your realm(s), or just want to understand its
configuration in isolation.

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) for local development, or
  nothing beyond the OS for a published self-contained binary.
- No external database — accounts are stored in a local SQLite file.

## Local development

```bash
dotnet run
```

Boots fine with zero setup: the committed `appsettings.json` ships placeholder secrets and a
sample `Realms` list that are only rejected when `ASPNETCORE_ENVIRONMENT=Production`. In
Development it listens on **http://localhost:5050** (Swagger UI at `/swagger`), and creates
`Storage/auth.db` on first run via an automatic EF Core migration.

Try it:

```bash
curl -X POST http://localhost:5050/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'
# → { "token": "...", "username": "testuser", "expiresAt": "..." }

curl http://localhost:5050/api/realms
# → the sample Realms list from appsettings.json
```

## Standalone production setup

If you're running this service by itself (not via `Myria.Server.Realm`'s bundled
`run-production.sh`):

### 1. Publish

```bash
dotnet publish Myria.Server.Auth.csproj -c Release -r linux-x64 --self-contained true -o out
```

(swap `linux-x64` for `win-x64` on Windows, etc.)

### 2. Generate a TLS certificate

```bash
mkdir -p out/certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout /tmp/myria.key -out /tmp/myria.crt -subj "/CN=your-domain-or-ip"
openssl pkcs12 -export -out out/certs/myria.pfx \
  -inkey /tmp/myria.key -in /tmp/myria.crt -password pass:CHOOSE_A_PFX_PASSWORD
rm /tmp/myria.key /tmp/myria.crt
```

### 3. Configure secrets

Create `out/appsettings.Production.json` (never commit this — it's already gitignored):

```json
{
  "Jwt": {
    "Key": "<a random string, at least 32 bytes — e.g. `openssl rand -base64 48`>",
    "Issuer": "MyriaServer",
    "Audience": "MyriaClient",
    "ExpirationHours": 24
  },
  "Security": {
    "Pepper": "<another random string — e.g. `openssl rand -base64 32`>"
  },
  "Admin": {
    "InternalSecret": "<another random string — e.g. `openssl rand -base64 32`>"
  },
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "https://0.0.0.0:5050",
        "Certificate": {
          "Path": "certs/myria.pfx",
          "Password": "<the pfx password from step 2>"
        }
      }
    }
  },
  "Realms": [
    { "Id": "luria", "Name": "Luria", "Url": "https://your-realm-address:5001" }
  ]
}
```

**`Jwt:Key` and `Admin:InternalSecret` must be byte-identical to every realm's own config** — this
service and each realm trust each other purely by shared secret, with no other handshake. Copy
the exact value; don't retype it. `Security:Pepper` is only used here (realms don't hash
passwords). `Realms` lists every realm this service should know about — see [this service's
README](README.md#configuration-for-production-deployment) for the full config-key reference,
and [`Myria.Server.Realm`'s SETUP.md](https://github.com/MyriaGames/MyriaServer/blob/master/SETUP.md)
for how a realm's matching config looks.

Once this file is in place, Production serves **only** HTTPS — the plain-HTTP endpoint used for
local development is defined in `appsettings.Development.json`, which isn't loaded in Production,
so there's no plain-HTTP fallback to worry about.

### 4. Run

```bash
cd out
chmod +x MyriaAuthServer
ASPNETCORE_ENVIRONMENT=Production ./MyriaAuthServer
```

Verify:

```bash
curl -k https://your-domain-or-ip:5050/api/realms
```

### 5. Keep it running

Use a systemd unit (adjust `WorkingDirectory`/`ExecStart` to your actual path):

```ini
# /etc/systemd/system/myriaauthserver.service
[Unit]
Description=MyriaAuthServer (standalone)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/myria-auth
Environment=ASPNETCORE_ENVIRONMENT=Production
ExecStart=/opt/myria-auth/MyriaAuthServer
Restart=on-failure
RestartSec=5
User=myria-auth
Group=myria-auth

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home myria-auth
sudo chown -R myria-auth:myria-auth /opt/myria-auth
sudo systemctl daemon-reload
sudo systemctl enable --now myriaauthserver.service
```

(This is a different unit name than `myriarpg.service` — that name is specifically what
`Myria.Server.Realm`'s `update-production.sh` looks for in the bundled deployment. A standalone
setup like this one has no equivalent auto-update script; update by re-publishing and restarting
the service yourself.)

## Adding/changing realms later

Edit the `Realms` array in `appsettings.Production.json` and restart the service — there's no
hot-reload, and every connected client only sees the updated list on their next
`GET /api/realms` call (typically when they open the realm-selection screen).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `Jwt:Key is still the dev placeholder (or unset)...` at startup | `appsettings.Production.json` isn't in the working directory, or `ASPNETCORE_ENVIRONMENT` isn't set to `Production`. |
| `Jwt:Key is shorter than 32 bytes...` at startup | Your generated key is too short — use `openssl rand -base64 48` or similar. |
| Clients can register/login here but every realm rejects their token | `Jwt:Key`/`Issuer`/`Audience` mismatch between this service and the realm — copy-paste the exact value. |
| A realm never appears in `GET /api/realms` | It's missing from (or misspelled in) the `Realms` array, or the service wasn't restarted after editing it. |
| Red startup warning about a realm being reachable over plain HTTP | Intentional, not an error — see this repo's `README.md` Configuration section. Put that realm behind HTTPS when you can. |
