package auth

import (
	"strings"
	"testing"
)

func TestLoginEmailKey(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{name: "simple email", email: "alice@example.com"},
		{name: "whitespace email", email: " Alice@Example.com "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := LoginEmailKey(tt.email)
			if !strings.HasPrefix(key, "login:email:") {
				t.Errorf("key must start with login:email:, got %q", key)
			}
			if strings.Contains(key, tt.email) {
				t.Error("key must not contain raw email")
			}
		})
	}
}

func TestLoginEmailKeySameForEquivalentEmails(t *testing.T) {
	k1 := LoginEmailKey("Alice@Example.com")
	k2 := LoginEmailKey(" alice@example.com ")

	if k1 != k2 {
		t.Errorf("equivalent emails must produce same key: %q vs %q", k1, k2)
	}
}

func TestLoginEmailKeyDifferentForDifferentEmails(t *testing.T) {
	k1 := LoginEmailKey("alice@example.com")
	k2 := LoginEmailKey("bob@example.com")

	if k1 == k2 {
		t.Error("different emails must produce different keys")
	}
}

func TestLoginIPKey(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{name: "simple ip", ip: "127.0.0.1"},
		{name: "whitespace ip", ip: " 192.168.1.1 "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := LoginIPKey(tt.ip)
			if !strings.HasPrefix(key, "login:ip:") {
				t.Errorf("key must start with login:ip:, got %q", key)
			}
			if strings.Contains(key, tt.ip) {
				t.Error("key must not contain raw IP")
			}
		})
	}
}

func TestLoginIPKeySameForEquivalentIPs(t *testing.T) {
	k1 := LoginIPKey("  192.168.1.1  ")
	k2 := LoginIPKey("192.168.1.1")

	if k1 != k2 {
		t.Errorf("equivalent IPs must produce same key: %q vs %q", k1, k2)
	}
}

func TestLoginIPKeyDifferentForDifferentIPs(t *testing.T) {
	k1 := LoginIPKey("192.168.1.1")
	k2 := LoginIPKey("10.0.0.1")

	if k1 == k2 {
		t.Error("different IPs must produce different keys")
	}
}

func TestLoginEmailIPKey(t *testing.T) {
	key := LoginEmailIPKey(" Alice@Example.com ", " 127.0.0.1 ")
	if !strings.HasPrefix(key, "login:email_ip:") {
		t.Errorf("key must start with login:email_ip:, got %q", key)
	}
	if strings.Contains(key, "alice@example.com") {
		t.Error("key must not contain raw email")
	}
	if strings.Contains(key, "127.0.0.1") {
		t.Error("key must not contain raw IP")
	}
}

func TestLoginEmailIPKeySameForEquivalentInputs(t *testing.T) {
	k1 := LoginEmailIPKey("Alice@Example.com", " 127.0.0.1 ")
	k2 := LoginEmailIPKey(" alice@example.com ", "127.0.0.1")

	if k1 != k2 {
		t.Errorf("equivalent inputs must produce same key: %q vs %q", k1, k2)
	}
}

func TestLoginEmailIPKeyDifferentForDifferentInputs(t *testing.T) {
	k1 := LoginEmailIPKey("alice@example.com", "127.0.0.1")
	k2 := LoginEmailIPKey("bob@example.com", "127.0.0.1")
	k3 := LoginEmailIPKey("alice@example.com", "192.168.1.1")

	if k1 == k2 {
		t.Error("different emails must produce different keys")
	}
	if k1 == k3 {
		t.Error("different IPs must produce different keys")
	}
}

func TestLoginEmailIPKeyDifferentFromEmailAndIPKeys(t *testing.T) {
	kEmail := LoginEmailKey("alice@example.com")
	kIP := LoginIPKey("192.168.1.1")
	kEmailIP := LoginEmailIPKey("alice@example.com", "192.168.1.1")

	if kEmail == kEmailIP {
		t.Error("email key must differ from email+IP key")
	}
	if kIP == kEmailIP {
		t.Error("IP key must differ from email+IP key")
	}
	if kEmail == kIP {
		t.Error("email key must differ from IP key")
	}
}
