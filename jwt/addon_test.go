package jwt_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/slice-soft/ss-keel-core/contracts"
	"github.com/slice-soft/ss-keel-jwt/jwt"
)

// compile-time assertions — these mirror the ones in addon.go but live in the
// test package so that a missing interface method causes a test-build failure.
var (
	_ contracts.Addon        = (*jwt.JWT)(nil)
	_ contracts.Debuggable   = (*jwt.JWT)(nil)
	_ contracts.Manifestable = (*jwt.JWT)(nil)
)

func newTestJWT(t *testing.T) *jwt.JWT {
	t.Helper()
	j, err := jwt.New(jwt.Config{
		SecretKey:     "test-secret-key",
		Issuer:        "test-issuer",
		TokenTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}
	return j
}

// --- Identity methods ---

func TestAddon_ID(t *testing.T) {
	j := newTestJWT(t)
	if got := j.ID(); got != "jwt" {
		t.Errorf("ID() = %q, want %q", got, "jwt")
	}
}

func TestAddon_PanelID(t *testing.T) {
	j := newTestJWT(t)
	if got := j.PanelID(); got != "jwt" {
		t.Errorf("PanelID() = %q, want %q", got, "jwt")
	}
}

func TestAddon_PanelLabel(t *testing.T) {
	j := newTestJWT(t)
	if got := j.PanelLabel(); got != "Auth (JWT)" {
		t.Errorf("PanelLabel() = %q, want %q", got, "Auth (JWT)")
	}
}

// --- Manifest ---

func TestAddon_Manifest_ID(t *testing.T) {
	j := newTestJWT(t)
	m := j.Manifest()
	if m.ID != "jwt" {
		t.Errorf("Manifest().ID = %q, want %q", m.ID, "jwt")
	}
}

func TestAddon_Manifest_Capabilities(t *testing.T) {
	j := newTestJWT(t)
	m := j.Manifest()
	if len(m.Capabilities) != 1 || m.Capabilities[0] != "auth" {
		t.Errorf("Manifest().Capabilities = %v, want [auth]", m.Capabilities)
	}
}

func TestAddon_Manifest_Resources(t *testing.T) {
	j := newTestJWT(t)
	m := j.Manifest()
	if len(m.Resources) != 0 {
		t.Errorf("Manifest().Resources = %v, want []", m.Resources)
	}
}

func TestAddon_Manifest_EnvVars(t *testing.T) {
	j := newTestJWT(t)
	m := j.Manifest()

	if len(m.EnvVars) != 3 {
		t.Fatalf("Manifest().EnvVars len = %d, want 3", len(m.EnvVars))
	}

	// JWT_SECRET — required, secret
	secret := m.EnvVars[0]
	if secret.Key != "JWT_SECRET" {
		t.Errorf("EnvVars[0].Key = %q, want JWT_SECRET", secret.Key)
	}
	if secret.ConfigKey != "jwt.secret" {
		t.Errorf("EnvVars[0].ConfigKey = %q, want jwt.secret", secret.ConfigKey)
	}
	if secret.Required {
		t.Error("EnvVars[0].Required should be false")
	}
	if !secret.Secret {
		t.Error("EnvVars[0].Secret should be true")
	}
	if secret.Default != "change-me-in-production" {
		t.Errorf("EnvVars[0].Default = %q, want %q", secret.Default, "change-me-in-production")
	}

	// JWT_ISSUER — not required, not secret
	issuer := m.EnvVars[1]
	if issuer.Key != "JWT_ISSUER" {
		t.Errorf("EnvVars[1].Key = %q, want JWT_ISSUER", issuer.Key)
	}
	if issuer.ConfigKey != "jwt.issuer" {
		t.Errorf("EnvVars[1].ConfigKey = %q, want jwt.issuer", issuer.ConfigKey)
	}
	if issuer.Required {
		t.Error("EnvVars[1].Required should be false")
	}
	if issuer.Secret {
		t.Error("EnvVars[1].Secret should be false")
	}

	// JWT_TOKEN_TTL_HOURS — default "24"
	ttl := m.EnvVars[2]
	if ttl.Key != "JWT_TOKEN_TTL_HOURS" {
		t.Errorf("EnvVars[2].Key = %q, want JWT_TOKEN_TTL_HOURS", ttl.Key)
	}
	if ttl.ConfigKey != "jwt.token-ttl-hours" {
		t.Errorf("EnvVars[2].ConfigKey = %q, want jwt.token-ttl-hours", ttl.ConfigKey)
	}
	if ttl.Default != "24" {
		t.Errorf("EnvVars[2].Default = %q, want 24", ttl.Default)
	}
}

// --- PanelEvents channel ---

func TestAddon_PanelEvents_ReturnsChannel(t *testing.T) {
	j := newTestJWT(t)
	ch := j.PanelEvents()
	if ch == nil {
		t.Fatal("PanelEvents() returned nil channel")
	}
}

// --- tryEmit via PanelEvents ---

func TestAddon_TryEmit_EventReadable(t *testing.T) {
	j := newTestJWT(t)

	// Trigger an emission via Sign.
	_, _ = j.Sign("user:1", map[string]any{})

	ch := j.PanelEvents()
	select {
	case e := <-ch:
		if e.AddonID != "jwt" {
			t.Errorf("event.AddonID = %q, want %q", e.AddonID, "jwt")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event on PanelEvents channel")
	}
}

func TestAddon_TryEmit_DoesNotBlockWhenFull(t *testing.T) {
	// Create a JWT instance and fill its 256-slot buffer via Sign calls,
	// then trigger one more — this must not block.
	j := newTestJWT(t)

	// Fill the buffer (256 slots).
	for i := 0; i < 256; i++ {
		_, _ = j.Sign(fmt.Sprintf("user:%d", i), map[string]any{})
	}

	// One more call must return promptly — no deadlock, no block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = j.Sign("user:overflow", map[string]any{})
	}()

	select {
	case <-done:
		// pass
	case <-time.After(time.Second):
		t.Fatal("tryEmit blocked on a full channel")
	}
}

// --- Integration: Sign ---

func TestIntegration_Sign_EmitsInfoEvent(t *testing.T) {
	j := newTestJWT(t)

	_, err := j.Sign("user:42", map[string]any{"role": "admin"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	e := drainFirst(t, j.PanelEvents())

	if e.Label != "sign" {
		t.Errorf("event.Label = %q, want %q", e.Label, "sign")
	}
	if e.Level != "info" {
		t.Errorf("event.Level = %q, want %q", e.Level, "info")
	}
	if e.Detail["result"] != "ok" {
		t.Errorf("event.Detail[result] = %v, want ok", e.Detail["result"])
	}
	if e.Detail["subject"] != "user:42" {
		t.Errorf("event.Detail[subject] = %v, want user:42", e.Detail["subject"])
	}
}

// --- Integration: ValidateToken success ---

func TestIntegration_ValidateToken_ValidEmitsInfoOk(t *testing.T) {
	j := newTestJWT(t)

	token, err := j.Sign("user:99", map[string]any{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Drain the Sign event.
	drainFirst(t, j.PanelEvents())

	_, err = j.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	e := drainFirst(t, j.PanelEvents())

	if e.Label != "validate_token" {
		t.Errorf("event.Label = %q, want %q", e.Label, "validate_token")
	}
	if e.Level != "info" {
		t.Errorf("event.Level = %q, want %q", e.Level, "info")
	}
	if e.Detail["result"] != "ok" {
		t.Errorf("event.Detail[result] = %v, want ok", e.Detail["result"])
	}
}

// --- Integration: ValidateToken failure ---

func TestIntegration_ValidateToken_InvalidEmitsWarn(t *testing.T) {
	j := newTestJWT(t)

	_, err := j.ValidateToken("not-a-valid-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}

	e := drainFirst(t, j.PanelEvents())

	if e.Label != "validate_token" {
		t.Errorf("event.Label = %q, want %q", e.Label, "validate_token")
	}
	if e.Level != "warn" {
		t.Errorf("event.Level = %q, want %q", e.Level, "warn")
	}
	if e.Detail["result"] != "error" {
		t.Errorf("event.Detail[result] = %v, want error", e.Detail["result"])
	}
}

// --- Security: no token string or secret in emitted events ---

func TestIntegration_NoSecretInEvents(t *testing.T) {
	const secret = "super-secret-key-must-not-leak"
	j, err := jwt.New(jwt.Config{
		SecretKey:     secret,
		Issuer:        "security-test",
		TokenTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}

	token, _ := j.Sign("user:1", map[string]any{})
	_, _ = j.ValidateToken(token)
	_, _ = j.ValidateToken("bad-token")
	_, _ = j.GenerateToken(map[string]any{"x": 1})

	ch := j.PanelEvents()
	// Drain all buffered events.
	for {
		select {
		case e := <-ch:
			assertEventSafe(t, e, secret, token)
		default:
			return
		}
	}
}

// assertEventSafe verifies that neither the secret nor the token string appears
// in any string-typed field or detail value of the event.
func assertEventSafe(t *testing.T, e contracts.PanelEvent, secret, token string) {
	t.Helper()
	fields := []string{e.AddonID, e.Label, e.Level}
	for _, f := range fields {
		if strings.Contains(f, secret) {
			t.Errorf("event field contains secret: %q", f)
		}
		if token != "" && strings.Contains(f, token) {
			t.Errorf("event field contains token string: %q", f)
		}
	}
	for k, v := range e.Detail {
		vs := fmt.Sprintf("%v", v)
		if strings.Contains(vs, secret) {
			t.Errorf("event.Detail[%q] contains secret: %q", k, vs)
		}
		if token != "" && strings.Contains(vs, token) {
			t.Errorf("event.Detail[%q] contains token string: %q", k, vs)
		}
	}
}

// drainFirst reads the next event from the channel or fails the test if none
// arrives within 100 ms.
func drainFirst(t *testing.T, ch <-chan contracts.PanelEvent) contracts.PanelEvent {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event on PanelEvents channel")
		return contracts.PanelEvent{} // unreachable
	}
}
