package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/slice-soft/ss-keel-core/contracts"
)

const localsKey = "jwt_claims"

// JWT provides token generation, validation, and an authentication guard for Keel.
// It implements contracts.Guard and is safe for concurrent use.
type JWT struct {
	cfg    Config
	logger contracts.Logger
	events chan contracts.PanelEvent
}

var _ contracts.Guard = (*JWT)(nil)
var _ contracts.TokenSigner = (*JWT)(nil)

// New creates a JWT provider from the given config.
// Returns an error if Config.SecretKey is empty.
func New(cfg Config) (*JWT, error) {
	if err := cfg.withDefaults(); err != nil {
		return nil, err
	}
	return &JWT{cfg: cfg, logger: cfg.Logger, events: make(chan contracts.PanelEvent, 256)}, nil
}

// Sign creates a signed HS256 JWT with the given subject in the "sub" claim
// and the extra claims map stored in the "data" claim.
//
// This satisfies the TokenSigner interface expected by ss-keel-oauth:
//
//	oauth.Config{Signer: jwtProvider}
func (j *JWT) Sign(subject string, data map[string]any) (string, error) {
	claims := gojwt.MapClaims{
		"sub":  subject,
		"data": data,
		"iss":  j.cfg.Issuer,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour * time.Duration(j.cfg.TokenTTLHours)).Unix(),
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(j.cfg.SecretKey))
	level := "info"
	detail := map[string]any{
		"subject": subject,
		"issuer":  j.cfg.Issuer,
		"result":  "ok",
	}
	if err != nil {
		detail["result"] = "error"
		level = "error"
	}
	j.tryEmit(contracts.PanelEvent{
		Timestamp: time.Now(),
		AddonID:   "jwt",
		Label:     "sign",
		Level:     level,
		Detail:    detail,
	})
	if err != nil {
		return "", fmt.Errorf("jwt: sign token: %w", err)
	}
	return signed, nil
}

// GenerateToken creates a signed HS256 JWT containing the given payload
// stored in the "data" claim.
func (j *JWT) GenerateToken(data any) (string, error) {
	if j.logger != nil {
		j.logger.Info("jwt: generating token")
	}
	claims := gojwt.MapClaims{
		"data": data,
		"iss":  j.cfg.Issuer,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour * time.Duration(j.cfg.TokenTTLHours)).Unix(),
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(j.cfg.SecretKey))
	level := "info"
	detail := map[string]any{
		"issuer": j.cfg.Issuer,
		"result": "ok",
	}
	if err != nil {
		detail["result"] = "error"
		level = "error"
	}
	j.tryEmit(contracts.PanelEvent{
		Timestamp: time.Now(),
		AddonID:   "jwt",
		Label:     "generate_token",
		Level:     level,
		Detail:    detail,
	})
	if err != nil {
		return "", fmt.Errorf("jwt: sign token: %w", err)
	}
	return signed, nil
}

// ValidateToken parses and validates a token string (with or without the
// "Bearer " prefix). Returns the parsed claims map on success.
func (j *JWT) ValidateToken(tokenString string) (gojwt.MapClaims, error) {
	raw := stripBearer(tokenString)
	token, err := gojwt.Parse(raw, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwt: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(j.cfg.SecretKey), nil
	}, gojwt.WithExpirationRequired())
	if err != nil {
		j.tryEmit(contracts.PanelEvent{
			Timestamp: time.Now(),
			AddonID:   "jwt",
			Label:     "validate_token",
			Level:     "warn",
			Detail:    map[string]any{"issuer": j.cfg.Issuer, "result": "error"},
		})
		return nil, fmt.Errorf("jwt: %w", err)
	}
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok || !token.Valid {
		j.tryEmit(contracts.PanelEvent{
			Timestamp: time.Now(),
			AddonID:   "jwt",
			Label:     "validate_token",
			Level:     "warn",
			Detail:    map[string]any{"issuer": j.cfg.Issuer, "result": "error"},
		})
		return nil, errors.New("jwt: invalid claims")
	}
	j.tryEmit(contracts.PanelEvent{
		Timestamp: time.Now(),
		AddonID:   "jwt",
		Label:     "validate_token",
		Level:     "info",
		Detail:    map[string]any{"issuer": j.cfg.Issuer, "result": "ok"},
	})
	return claims, nil
}

// RefreshToken validates the given token and issues a new one with a fresh expiry.
// The payload ("data" claim) is preserved unchanged.
func (j *JWT) RefreshToken(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(j.cfg.TokenTTLHours)).Unix()
	token := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(j.cfg.SecretKey))
	if err != nil {
		return "", fmt.Errorf("jwt: sign refreshed token: %w", err)
	}
	return signed, nil
}

// Middleware returns a Fiber handler that validates the Bearer token from the
// Authorization header and stores the parsed claims in fiber.Ctx locals.
// Downstream handlers can retrieve the claims with ClaimsFromCtx.
//
// Implements contracts.Guard.
func (j *JWT) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" {
			return c.Status(fiber.StatusUnauthorized).
				JSON(fiber.Map{"error": "missing authorization header"})
		}
		claims, err := j.ValidateToken(header)
		if err != nil {
			if j.logger != nil {
				j.logger.Warn("jwt middleware: %v", err)
			}
			return c.Status(fiber.StatusUnauthorized).
				JSON(fiber.Map{"error": "invalid or expired token"})
		}
		c.Locals(localsKey, claims)
		return c.Next()
	}
}

// ClaimsFromCtx retrieves the JWT claims stored by the middleware.
// Returns (nil, false) if the route was not protected by the JWT guard.
func ClaimsFromCtx(c *fiber.Ctx) (gojwt.MapClaims, bool) {
	claims, ok := c.Locals(localsKey).(gojwt.MapClaims)
	return claims, ok
}

func stripBearer(s string) string {
	return strings.TrimPrefix(s, "Bearer ")
}

// tryEmit sends an event to the panel channel without blocking.
// If the channel is full the event is silently dropped.
func (j *JWT) tryEmit(e contracts.PanelEvent) {
	select {
	case j.events <- e:
	default:
	}
}
