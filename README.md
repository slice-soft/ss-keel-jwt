<img src="https://cdn.slicesoft.dev/boat.svg" width="400" />

# ss-keel-jwt
Official JWT addon for Keel — token generation, validation, and route protection.

[![CI](https://github.com/slice-soft/ss-keel-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/slice-soft/ss-keel-jwt/actions)
[![Release](https://img.shields.io/github/v/release/slice-soft/ss-keel-jwt)](https://github.com/slice-soft/ss-keel-jwt/releases)
![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)
[![Go Report Card](https://goreportcard.com/badge/github.com/slice-soft/ss-keel-jwt)](https://goreportcard.com/report/github.com/slice-soft/ss-keel-jwt)
[![Go Reference](https://pkg.go.dev/badge/github.com/slice-soft/ss-keel-jwt.svg)](https://pkg.go.dev/github.com/slice-soft/ss-keel-jwt)
![License](https://img.shields.io/badge/License-MIT-green)
![Made in Colombia](https://img.shields.io/badge/Made%20in-Colombia-FCD116?labelColor=003893)


## JWT authentication addon for Keel

`ss-keel-jwt` adds JWT token generation, validation, and route protection to a [Keel](https://keel-go.dev) project.
It is the official authentication guard addon for JSON Web Tokens in the Keel ecosystem.

---

## 🚀 Installation

```bash
keel add jwt
```

The Keel CLI will:
1. Add `github.com/slice-soft/ss-keel-jwt` as a dependency.
2. Import the `jwt` package in `cmd/main.go` and inject initialization code.
3. Add `JWT_SECRET`, `JWT_ISSUER`, and `JWT_TOKEN_TTL_HOURS` environment variable examples to your `.env`.

---

## ⚙️ Bootstrap

```go
import (
    "strings"

    "github.com/slice-soft/ss-keel-core/config"
    "github.com/slice-soft/ss-keel-jwt/jwt"
)

issuer := strings.TrimSpace(config.GetEnvOrDefault("JWT_ISSUER", ""))
if issuer == "" {
    issuer = config.GetEnvOrDefault("SERVICE_NAME", "keel-app")
}

jwtProvider, err := jwt.New(jwt.Config{
    SecretKey:     config.GetEnvOrDefault("JWT_SECRET", "change-me-in-production"),
    Issuer:        issuer,
    TokenTTLHours: uint(config.GetEnvIntOrDefault("JWT_TOKEN_TTL_HOURS", 24)),
    Logger:        appLogger,
})
if err != nil {
    appLogger.Error("failed to initialize JWT: %v", err)
}
```

Defaults applied when not set:

| Field | Default |
|---|---|
| `Issuer` | `SERVICE_NAME` env var (fallback: `"keel-app"`) |
| `TokenTTLHours` | `24` |

---

## 🔑 Generate a token

```go
token, err := jwtProvider.GenerateToken(map[string]any{
    "userID": user.ID,
    "role":   user.Role,
})
```

The payload is stored in the `"data"` claim. All standard claims (`iss`, `iat`, `exp`) are set automatically.

---

## 🔒 Protect routes

`jwt.JWT` implements `contracts.Guard`. Use `Middleware()` to protect any route or group:

```go
// Per route
httpx.GET("/profile", profileHandler).
    Use(jwtProvider.Middleware()).
    WithSecured("bearerAuth")
```

The middleware reads the `Authorization` header (with or without `Bearer ` prefix), validates the token, and stores the claims in the request context for downstream handlers.

---

## 👤 Access the authenticated payload

```go
func profileHandler(c *httpx.Ctx) error {
    claims, ok := jwt.ClaimsFromCtx(c.Ctx)
    if !ok {
        return c.Status(401).JSON(fiber.Map{"error": "not authenticated"})
    }

    data := claims["data"].(map[string]any)
    return c.OK(fiber.Map{
        "userID": data["userID"],
        "role":   data["role"],
    })
}
```

---

## 🔄 Refresh tokens

```go
newToken, err := jwtProvider.RefreshToken(oldToken)
```

`RefreshToken` validates the given token and issues a new one with a fresh `iat` and `exp`. The `"data"` payload is preserved.

---

## ❤️ Health checker

JWT does not expose a health checker — there is no external connection to verify. The guard is stateless.

---

## ⚙️ Environment variables

| Variable | Example | Description |
|---|---|---|
| `JWT_SECRET` | `change-me-in-production` | HMAC secret used to sign and verify tokens |
| `JWT_ISSUER` | `my-app` | Token issuer claim (`iss`). The generated Keel setup falls back to `SERVICE_NAME` when empty |
| `JWT_TOKEN_TTL_HOURS` | `24` | Token time-to-live in hours. Defaults to `24` |

---

## 🤚 CI/CD and releases

- **CI** runs on every pull request targeting `main` via `.github/workflows/ci.yml`.
- **Releases** are created automatically on merge to `main` via `.github/workflows/release.yml` using Release Please.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup and repository-specific rules.
The base workflow, commit conventions, and community standards live in [ss-community](https://github.com/slice-soft/ss-community/blob/main/CONTRIBUTING.md).

## Community

| Document | |
|---|---|
| [CONTRIBUTING.md](https://github.com/slice-soft/ss-community/blob/main/CONTRIBUTING.md) | Workflow, commit conventions, and PR guidelines |
| [GOVERNANCE.md](https://github.com/slice-soft/ss-community/blob/main/GOVERNANCE.md) | Decision-making, roles, and release process |
| [CODE_OF_CONDUCT.md](https://github.com/slice-soft/ss-community/blob/main/CODE_OF_CONDUCT.md) | Community standards |
| [VERSIONING.md](https://github.com/slice-soft/ss-community/blob/main/VERSIONING.md) | SemVer policy and breaking changes |
| [SECURITY.md](https://github.com/slice-soft/ss-community/blob/main/SECURITY.md) | How to report vulnerabilities |
| [MAINTAINERS.md](https://github.com/slice-soft/ss-community/blob/main/MAINTAINERS.md) | Active maintainers |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- Website: [keel-go.dev](https://keel-go.dev)
- GitHub: [github.com/slice-soft/ss-keel-jwt](https://github.com/slice-soft/ss-keel-jwt)
- Documentation: [docs.keel-go.dev](https://docs.keel-go.dev)

---

Made by [SliceSoft](https://slicesoft.dev) — Colombia 💙
