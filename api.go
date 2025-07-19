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
	payload := strings.NewReader("api=SYNO.Entry.Request&method=request&version=1&stop_when_error=false&mode=%22sequential%22&compound=%5B%7B%22api%22%3A%22SYNO.Core.Security.DSM%22%2C%22method%22%3A%22get%22%2C%22version%22%3A5%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.DSM.Embed%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.OTP.EnforcePolicy%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.SecureSignIn.AMFA.Policy%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.SmartBlock%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.Firewall.Conf%22%2C%22method%22%3A%22get%22%2C%22version%22%3A%221%22%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.AutoBlock%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.DoS%22%2C%22method%22%3A%22get%22%2C%22version%22%3A2%2C%22configs%22%3A%5B%7B%22adapter%22%3A%22eth0%22%7D%2C%7B%22adapter%22%3A%22eth1%22%7D%2C%7B%22adapter%22%3A%22pppoe%22%7D%5D%7D%2C%7B%22api%22%3A%22SYNO.Core.Web.Security.HTTPCompression%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Web.Security.TLSProfile%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Hardware.SpectreMeltdown%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Storage.CGI.KMIP%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.Firewall%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.User%22%2C%22method%22%3A%22list%22%2C%22version%22%3A1%2C%22type%22%3A%22local%22%2C%22additional%22%3A%5B%22expired%22%5D%7D%2C%7B%22api%22%3A%22SYNO.Core.System%22%2C%22method%22%3A%22info%22%2C%22version%22%3A3%7D%2C%7B%22api%22%3A%22SYNO.Core.QuickConnect%22%2C%22method%22%3A%22get%22%2C%22version%22%3A2%7D%2C%7B%22api%22%3A%22SYNO.Core.Upgrade.Server%22%2C%22method%22%3A%22check%22%2C%22version%22%3A3%2C%22user_reading%22%3Atrue%2C%22need_auto_smallupdate%22%3Atrue%2C%22need_promotion%22%3Atrue%7D%5D")

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

	if !response.Success {
		return nil, fmt.Errorf("synology API returned success=false")
	}

	return &response, nil
}

func getUserData(response SynologyResponse) (UserListData, error) {
	endpoint := "SYNO.Core.User"
	for _, result := range response.Data.Result {
		if result.API == endpoint {
			jsonBytes, err := json.Marshal(result.Data)
			if err != nil {
				return UserListData{}, err
			}
			var userData UserListData
			err = json.Unmarshal(jsonBytes, &userData)
			if err != nil {
				return UserListData{}, err
			}
			return userData, nil
		}
	}
	return UserListData{}, fmt.Errorf("API %s not found", endpoint)
}
