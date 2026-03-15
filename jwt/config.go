package jwt

import (
	"errors"

	"github.com/slice-soft/ss-keel-core/contracts"
)

// Config holds the options required to create a JWT provider.
type Config struct {
	// SecretKey is the HMAC secret used to sign and verify tokens. Required.
	SecretKey string
	// Issuer is stored in the "iss" claim. Defaults to "keel".
	Issuer string
	// TokenTTLHours is the token lifetime in hours. Defaults to 24.
	TokenTTLHours uint
	// Logger is optional. When set, the middleware logs validation errors.
	Logger contracts.Logger
}

func (c *Config) withDefaults() error {
	if c.SecretKey == "" {
		return errors.New("ss-keel-jwt: SecretKey is required")
	}
	if c.Issuer == "" {
		c.Issuer = "keel"
	}
	if c.TokenTTLHours == 0 {
		c.TokenTTLHours = 24
	}
	return nil
}
