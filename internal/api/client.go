package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func NewInsecureHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

type SessionConfig struct {
	SID  string `json:"sid"`
	DID  string `json:"did"`
	Host string `json:"host"`
	User string `json:"user"`
}

func FetchSynologyData(url string) (*SynologyResponse, error) {
	payload := strings.NewReader(BuildCompoundPayload())

	client := NewInsecureHTTPClient()

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", os.Getenv("SYNOLOGY_COOKIE"))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	var response SynologyResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	if response.Data.HasFail {
		var failedAPIs []string
		for _, result := range response.Data.Result {
			if !result.Success && result.Error != nil {
				description := GetSynologyErrorDescription(result.Error.Code)
				failedAPIs = append(failedAPIs, fmt.Sprintf("%s: %s (code: %d)", result.API, description, result.Error.Code))
			}
		}
		if len(failedAPIs) > 0 {
			return nil, fmt.Errorf("synology API errors:\n%s", strings.Join(failedAPIs, "\n"))
		}
		return nil, fmt.Errorf("synology API returned errors - some endpoints failed")
	}

	return &response, nil
}

func FetchSynologyDataWithSession(session *SessionConfig) (*SynologyResponse, error) {
	payload := strings.NewReader(BuildCompoundPayload())

	client := NewInsecureHTTPClient()

	url := fmt.Sprintf("https://%s/webapi/entry.cgi", session.Host)
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", fmt.Sprintf("did=%s; id=%s", session.DID, session.SID))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	var response SynologyResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	if response.Data.HasFail {
		var failedAPIs []string
		for _, result := range response.Data.Result {
			if !result.Success && result.Error != nil {
				description := GetSynologyErrorDescription(result.Error.Code)
				failedAPIs = append(failedAPIs, fmt.Sprintf("%s: %s (code: %d)", result.API, description, result.Error.Code))
			}
		}
		if len(failedAPIs) > 0 {
			return nil, fmt.Errorf("synology API errors:\n%s", strings.Join(failedAPIs, "\n"))
		}
		return nil, fmt.Errorf("synology API returned errors - some endpoints failed")
	}

	return &response, nil
}

func getData[T any](endpoint string, response SynologyResponse) (T, error) {
	var data T
	for _, result := range response.Data.Result {
		if !response.Success {
			return data, fmt.Errorf("API %s failed", endpoint)
		}
		if result.API == endpoint {
			jsonBytes, err := json.Marshal(result.Data)
			if err != nil {
				return data, err
			}

			err = json.Unmarshal(jsonBytes, &data)
			if err != nil {
				return data, err
			}
			return data, nil
		}
	}
	return data, fmt.Errorf("API %s not found", endpoint)
}

func GetUserData(response SynologyResponse) (UserListData, error) {
	return getData[UserListData]("SYNO.Core.User", response)
}

func GetFirewallData(response SynologyResponse) (FirewallData, error) {
	return getData[FirewallData]("SYNO.Core.Security.Firewall", response)
}

func GetOptData(response SynologyResponse) (EnforcePolicyOptData, error) {
	return getData[EnforcePolicyOptData]("SYNO.Core.OTP.EnforcePolicy", response)
}

func GetTerminalData(response SynologyResponse) (TerminalData, error) {
	return getData[TerminalData]("SYNO.Core.Terminal", response)
}

func GetFTPData(response SynologyResponse) (FTPData, error) {
	return getData[FTPData]("SYNO.Core.FileServ.FTP", response)
}

func GetPasswordPolicyData(response SynologyResponse) (PasswordPolicyData, error) {
	return getData[PasswordPolicyData]("SYNO.Core.User.PasswordPolicy", response)
}

func GetPackageData(response SynologyResponse) (PackageData, error) {
	return getData[PackageData]("SYNO.Core.Package", response)
}

func GetQuickConnectData(response SynologyResponse) (QuickConnectData, error) {
	return getData[QuickConnectData]("SYNO.Core.QuickConnect", response)
}

func GetAutoBlockData(response SynologyResponse) (AutoBlockData, error) {
	return getData[AutoBlockData]("SYNO.Core.Security.AutoBlock", response)
}

func GetLogData(response SynologyResponse) (LogList, error) {
	return getData[LogList]("SYNO.Core.SyslogClient.Log", response)
}
