package auth

import (
	"time"
)

type LoginData struct {
	DID          string `json:"did"`
	IsPortalPort bool   `json:"is_portal_port"`
	SID          string `json:"sid"`
}

type LoginResponse struct {
	Data    LoginData `json:"data"`
	Success bool      `json:"success"`
	Error   *struct {
		Code int `json:"code"`
	} `json:"error,omitempty"`
}

type SessionConfig struct {
	SID       string    `json:"sid"`
	DID       string    `json:"did"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}
