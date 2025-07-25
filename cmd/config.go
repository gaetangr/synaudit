package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type SessionConfig struct {
	SID       string    `json:"sid"`
	DID       string    `json:"did"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

func getConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(homeDir, ".synaudit")

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}

	return filepath.Join(configDir, "session.json"), nil
}

func saveSessionToFile(loginData *LoginData, host, user string) error {
	configPath, err := getConfigPath()
	if err != nil {
		return fmt.Errorf("getting config path: %w", err)
	}

	session := SessionConfig{
		SID:       loginData.SID,
		DID:       loginData.DID,
		Host:      host,
		User:      user,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("writing session file: %w", err)
	}

	return nil
}

func loadSessionFromFile() (*SessionConfig, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, fmt.Errorf("getting config path: %w", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no session found. Please run 'synaudit login' first")
		}
		return nil, fmt.Errorf("reading session file: %w", err)
	}

	var session SessionConfig
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("parsing session file: %w", err)
	}

	if time.Now().After(session.ExpiresAt) {
		os.Remove(configPath)
		return nil, fmt.Errorf("session expired. Please run 'synaudit login' again")
	}

	return &session, nil
}

func clearSessionFile() error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	return os.Remove(configPath)
}
