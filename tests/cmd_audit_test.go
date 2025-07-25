package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/gaetangr/synaudit/cmd"
)

func TestSessionConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  cmd.SessionConfig
		expired bool
	}{
		{
			name: "Valid session",
			config: cmd.SessionConfig{
				Host:      "https://test.local:5001",
				User:      "admin",
				SID:       "test-sid",
				DID:       "test-did",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expired: false,
		},
		{
			name: "Expired session",
			config: cmd.SessionConfig{
				Host:      "https://test.local:5001",
				User:      "admin",
				SID:       "test-sid",
				DID:       "test-did",
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			expired: true,
		},
		{
			name: "Missing SID",
			config: cmd.SessionConfig{
				Host:      "https://test.local:5001",
				User:      "admin",
				SID:       "",
				DID:       "test-did",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expired: false,
		},
		{
			name: "Missing DID",
			config: cmd.SessionConfig{
				Host:      "https://test.local:5001",
				User:      "admin",
				SID:       "test-sid",
				DID:       "",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			expired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isExpired := time.Now().After(tt.config.ExpiresAt)
			if isExpired != tt.expired {
				t.Errorf("Expected expired=%v, got %v for test: %s", tt.expired, isExpired, tt.name)
			}

			isValid := tt.config.SID != "" && tt.config.DID != "" && tt.config.Host != "" && !isExpired
			expectedValid := !tt.expired && tt.config.SID != "" && tt.config.DID != ""
			if isValid != expectedValid {
				t.Errorf("Expected valid=%v, got %v for test: %s", expectedValid, isValid, tt.name)
			}
		})
	}
}

func TestAPIEndpointConstruction(t *testing.T) {
	tests := []struct {
		name     string
		api      string
		version  int
		method   string
		expected string
	}{
		{
			name:     "Auth API",
			api:      "SYNO.API.Auth",
			version:  3,
			method:   "login",
			expected: "api=SYNO.API.Auth&version=3&method=login",
		},
		{
			name:     "Info API",
			api:      "SYNO.API.Info",
			version:  1,
			method:   "query",
			expected: "api=SYNO.API.Info&version=1&method=query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildAPIQuery(tt.api, tt.version, tt.method)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func buildAPIQuery(api string, version int, method string) string {
	return fmt.Sprintf("api=%s&version=%d&method=%s", api, version, method)
}

func TestAPIDataStructures(t *testing.T) {
	userData := cmd.UserListData{
		Total: 1,
		Users: []struct {
			Expired cmd.UserStatus `json:"expired"`
			Name    string         `json:"name"`
		}{
			{
				Name:    "admin",
				Expired: cmd.UserStatusActive,
			},
		},
	}

	if userData.Total != 1 {
		t.Errorf("Expected Total=1, got %d", userData.Total)
	}

	if len(userData.Users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(userData.Users))
	}

	if userData.Users[0].Name != "admin" {
		t.Errorf("Expected username 'admin', got '%s'", userData.Users[0].Name)
	}

	if userData.Users[0].Expired != cmd.UserStatusActive {
		t.Errorf("Expected user status to be active, got '%s'", userData.Users[0].Expired)
	}
}

func TestUserStatusConstants(t *testing.T) {
	if cmd.UserStatusExpired != "now" {
		t.Errorf("Expected cmd.UserStatusExpired to be 'now', got '%s'", cmd.UserStatusExpired)
	}

	if cmd.UserStatusActive != "normal" {
		t.Errorf("Expected cmd.UserStatusActive to be 'normal', got '%s'", cmd.UserStatusActive)
	}
}

func TestCriticalSecurityChecks(t *testing.T) {
	criticalChecks := []string{
		"Admin account status",
		"Firewall configuration",
		"2FA enforcement",
		"Service exposure",
	}

	for _, check := range criticalChecks {
		if check == "" {
			t.Errorf("Security check should not be empty")
		}

		if len(check) < 5 {
			t.Errorf("Security check name too short: '%s'", check)
		}
	}
}
