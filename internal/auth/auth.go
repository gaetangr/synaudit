// internal/auth/auth.go - Version améliorée avec support 2FA

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gaetangr/synaudit/internal/api"
)

func AuthenticateUser(host, username, password string) (*LoginData, error) {
	return authenticateWithRetry(host, username, password, "")
}

func AuthenticateWith2FA(host, username, password, otpCode string) (*LoginData, error) {
	return authenticateWithRetry(host, username, password, otpCode)
}

func authenticateWithRetry(host, username, password, otpCode string) (*LoginData, error) {
	client := api.NewInsecureHTTPClient()

	data := url.Values{}
	data.Set("api", "SYNO.API.Auth")
	data.Set("version", "6")
	data.Set("method", "login")
	data.Set("account", username)
	data.Set("passwd", password)
	data.Set("session", "Synaudit")
	data.Set("format", "cookie")

	if otpCode != "" {
		data.Set("otp_code", otpCode)
	}

	apiURL := fmt.Sprintf("https://%s/webapi/auth.cgi", host)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var loginResponse LoginResponse
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON response: %w", err)
	}

	if !loginResponse.Success {
		if loginResponse.Error != nil {
			description := api.GetSynologyErrorDescription(loginResponse.Error.Code)

			switch loginResponse.Error.Code {
			case 403:
				return nil, &TwoFactorRequiredError{
					Code:        loginResponse.Error.Code,
					Description: description,
				}
			case 404:
				return nil, fmt.Errorf("invalid 2FA code: %s", description)
			case 406:
				return nil, &TwoFactorRequiredError{
					Code:        loginResponse.Error.Code,
					Description: description,
				}
			default:
				return nil, fmt.Errorf("%s (code: %d)", description, loginResponse.Error.Code)
			}
		}
		return nil, fmt.Errorf("login failed")
	}

	return &loginResponse.Data, nil
}

func LogoutAPI(host, sid string) error {
	client := api.NewInsecureHTTPClient()

	data := url.Values{}
	data.Set("api", "SYNO.API.Auth")
	data.Set("version", "6")
	data.Set("method", "logout")
	data.Set("session", "Synaudit")

	apiURL := fmt.Sprintf("https://%s/webapi/auth.cgi", host)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("creating logout request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", fmt.Sprintf("id=%s", sid))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("executing logout request: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

type TwoFactorRequiredError struct {
	Code        int
	Description string
}

func (e *TwoFactorRequiredError) Error() string {
	return fmt.Sprintf("2FA required: %s (code: %d)", e.Description, e.Code)
}

func (e *TwoFactorRequiredError) Is2FARequired() bool {
	return true
}
