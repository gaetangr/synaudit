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

func getUserData(response SynologyResponse) (UserListData, error) {
	endpoint := "SYNO.Core.User"
	var userData UserListData
	for _, result := range response.Data.Result {
		if !response.Success {
			return UserListData{}, fmt.Errorf("API %s failed ",
				endpoint)
		}
		if result.API == endpoint {

			jsonBytes, err := json.Marshal(result.Data)
			if err != nil {
				return UserListData{}, err
			}

			err = json.Unmarshal(jsonBytes, &userData)
			if err != nil {
				return UserListData{}, err
			}
			return userData, nil
		}
	}
	return UserListData{}, fmt.Errorf("API %s not found", endpoint)
}

func getFirewallData(response SynologyResponse) (FirewallData, error) {
	endpoint := "SYNO.Core.Security.Firewall"
	var firewallData FirewallData
	for _, result := range response.Data.Result {
		if endpoint == result.API {
			if !response.Success {
				return FirewallData{}, fmt.Errorf("API %s failed ",
					endpoint)
			}
			jsonBytes, err := json.Marshal(result.Data)
			if err != nil {
				return FirewallData{}, err
			}

			err = json.Unmarshal(jsonBytes, &firewallData)
			if err != nil {
				return FirewallData{}, err
			}
			return firewallData, nil
		}

	}
	return FirewallData{}, fmt.Errorf("not found")
}

func getOptData(response SynologyResponse) (EnforcePolicyOptData, error) {
	endpoint := "SYNO.Core.OTP.EnforcePolicy"
	var optData EnforcePolicyOptData
	for _, result := range response.Data.Result {
		if endpoint == result.API {
			if !response.Success {
				return EnforcePolicyOptData{}, fmt.Errorf("API %s failed ",
					endpoint)
			}
			jsonBytes, err := json.Marshal(result.Data)
			if err != nil {
				return EnforcePolicyOptData{}, err
			}

			err = json.Unmarshal(jsonBytes, &optData)
			if err != nil {
				return EnforcePolicyOptData{}, err
			}
			return optData, nil
		}

	}
	return EnforcePolicyOptData{}, fmt.Errorf("not found")
}
