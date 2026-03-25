package jwt

import "github.com/slice-soft/ss-keel-core/contracts"

var (
	_ contracts.Addon        = (*JWT)(nil)
	_ contracts.Debuggable   = (*JWT)(nil)
	_ contracts.Manifestable = (*JWT)(nil)
)

// ID returns the unique identifier for this addon.
func (j *JWT) ID() string { return "jwt" }

// PanelID returns the identifier used by the dev panel to reference this addon.
func (j *JWT) PanelID() string { return "jwt" }

// PanelLabel returns the human-readable label shown in the dev panel.
func (j *JWT) PanelLabel() string { return "Auth (JWT)" }

// PanelEvents returns the read-only channel of observable events for the dev panel.
func (j *JWT) PanelEvents() <-chan contracts.PanelEvent { return j.events }

// Manifest returns the addon metadata consumed by the CLI and core.
func (j *JWT) Manifest() contracts.AddonManifest {
	return contracts.AddonManifest{
		ID:           "jwt",
		Version:      "1.0.0",
		Capabilities: []string{"auth"},
		Resources:    []string{},
		EnvVars: []contracts.EnvVar{
			{
				Key:         "JWT_SECRET",
				ConfigKey:   "jwt.secret",
				Description: "HMAC secret key used to sign tokens",
				Required:    false,
				Secret:      true,
				Default:     "change-me-in-production",
				Source:      "jwt",
			},
			{
				Key:         "JWT_ISSUER",
				ConfigKey:   "jwt.issuer",
				Description: "Issuer claim value (iss). Defaults to SERVICE_NAME.",
				Required:    false,
				Secret:      false,
				Default:     "",
				Source:      "jwt",
			},
			{
				Key:         "JWT_TOKEN_TTL_HOURS",
				ConfigKey:   "jwt.token-ttl-hours",
				Description: "Token time-to-live in hours",
				Required:    false,
				Secret:      false,
				Default:     "24",
				Source:      "jwt",
			},
		},
	}
}

// RegisterWithPanel registers this addon with the given PanelRegistry so the
// dev panel can consume its observable events.
func (j *JWT) RegisterWithPanel(r contracts.PanelRegistry) {
	r.RegisterAddon(j)
}
