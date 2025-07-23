package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func fetchSynologyData(url string) (*SynologyResponse, error) {
	payload := strings.NewReader(buildCompoundPayload())

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

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

func getUserData(response SynologyResponse) (UserListData, error) {
	return getData[UserListData]("SYNO.Core.User", response)

}

func getFirewallData(response SynologyResponse) (FirewallData, error) {
	return getData[FirewallData]("SYNO.Core.Security.Firewall", response)
}

func getOptData(response SynologyResponse) (EnforcePolicyOptData, error) {
	return getData[EnforcePolicyOptData]("SYNO.Core.OTP.EnforcePolicy", response)
}
