package jwt_test

import (
	"testing"

	"github.com/slice-soft/ss-keel-jwt/jwt"
)

func TestNew_MissingSecretKey(t *testing.T) {
	_, err := jwt.New(jwt.Config{})
	if err == nil {
		t.Fatal("expected error for missing SecretKey, got nil")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	j, err := jwt.New(jwt.Config{SecretKey: "secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if j == nil {
		t.Fatal("expected non-nil JWT")
	}
}

func TestGenerateAndValidateToken(t *testing.T) {
	j, err := jwt.New(jwt.Config{
		SecretKey:     "test-secret",
		Issuer:        "test",
		TokenTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token, err := j.GenerateToken(map[string]any{"userID": "123"})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	claims, err := j.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	data, ok := claims["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'data' claim to be map[string]any, got %T", claims["data"])
	}
	if data["userID"] != "123" {
		t.Errorf("expected userID=123, got %v", data["userID"])
	}
}

func TestValidateToken_WithBearerPrefix(t *testing.T) {
	j, _ := jwt.New(jwt.Config{SecretKey: "test-secret", TokenTTLHours: 1})
	token, _ := j.GenerateToken("payload")

	_, err := j.ValidateToken("Bearer " + token)
	if err != nil {
		t.Fatalf("ValidateToken with Bearer prefix: %v", err)
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	j1, _ := jwt.New(jwt.Config{SecretKey: "secret-1", TokenTTLHours: 1})
	j2, _ := jwt.New(jwt.Config{SecretKey: "secret-2", TokenTTLHours: 1})

	token, _ := j1.GenerateToken("data")
	_, err := j2.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
}

func TestRefreshToken(t *testing.T) {
	j, _ := jwt.New(jwt.Config{SecretKey: "test-secret", TokenTTLHours: 1})
	token, _ := j.GenerateToken("user-data")

	newToken, err := j.RefreshToken(token)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	_, err = j.ValidateToken(newToken)
	if err != nil {
		t.Fatalf("ValidateToken on refreshed token: %v", err)
	}
}

func TestRefreshToken_InvalidToken(t *testing.T) {
	j, _ := jwt.New(jwt.Config{SecretKey: "test-secret", TokenTTLHours: 1})

	_, err := j.RefreshToken("not-a-valid-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

func TestSign_SatisfiesOAuthTokenSigner(t *testing.T) {
	j, err := jwt.New(jwt.Config{SecretKey: "test-secret", Issuer: "test", TokenTTLHours: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token, err := j.Sign("google:123", map[string]any{
		"email": "user@example.com",
		"name":  "Test User",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := j.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims["sub"] != "google:123" {
		t.Errorf("expected sub=google:123, got %v", claims["sub"])
	}
	data, ok := claims["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'data' claim to be map[string]any, got %T", claims["data"])
	}
	if data["email"] != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %v", data["email"])
	}
}
