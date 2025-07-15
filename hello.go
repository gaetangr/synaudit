package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Security-related API endpoints
const (
	APIDSMSecurity      = "SYNO.Core.Security.DSM"
	APIDSMSecurityEmbed = "SYNO.Core.Security.DSM.Embed"
	APISmartBlock       = "SYNO.Core.SmartBlock"
	APIFirewall         = "SYNO.Core.Security.Firewall"
	APIFirewallConf     = "SYNO.Core.Security.Firewall.Conf"
	APIAutoBlock        = "SYNO.Core.Security.AutoBlock"
	APIDoSProtection    = "SYNO.Core.Security.DoS"
	APITLSProfile       = "SYNO.Core.Web.Security.TLSProfile"
	APIHTTPCompression  = "SYNO.Core.Web.Security.HTTPCompression"
	APISpectreMeltdown  = "SYNO.Core.Hardware.SpectreMeltdown"
)

// Authentication and access control
const (
	APIOTPEnforcePolicy = "SYNO.Core.OTP.EnforcePolicy"
	APISecureSignInAMFA = "SYNO.SecureSignIn.AMFA.Policy"
)

// User and system management
const (
	APIUserList = "SYNO.Core.User"
)

type SynauditConfig struct {
	host string
}

type SynauditUser struct {
	username string
	password string
	opt      string
}

type SynologyPorts struct {
	name     string
	ports    []int
	protocol string
}

type SynologyErrorCode struct {
	Code        int
	Description string
}

// Liste des codes d'erreur Synology
var SynologyErrorCodes = []SynologyErrorCode{
	{400, "No such account or incorrect password."},
	{401, "Disabled account."},
	{402, "Denied permission."},
	{403, "2-factor authentication code required."},
	{404, "Failed to authenticate 2-factor authentication code."},
	{406, "Enforce to authenticate with 2-factor authentication code."},
	{407, "Blocked IP source."},
	{408, "Expired password cannot change."},
	{409, "Expired password."},
	{410, "Password must be changed."},
	{100, "Unknown error."},
	{101, "No parameter of API, method or version."},
	{102, "The requested API does not exist."},
	{103, "The requested method does not exist."},
	{104, "The requested version does not support the functionality."},
	{105, "The logged in session does not have permission."},
	{106, "Session timeout."},
	{107, "Session interrupted by duplicated login."},
	{108, "Failed to upload the file."},
	{109, "The network connection is unstable or the system is busy."},
	{110, "The network connection is unstable or the system is busy."},
	{111, "The network connection is unstable or the system is busy."},
	{112, "Preserve for other purpose."},
	{113, "Preserve for other purpose."},
	{114, "Lost parameters for this API."},
	{115, "Not allowed to upload a file."},
	{116, "Not allowed to perform for a demo site."},
	{117, "The network connection is unstable or the system is busy."},
	{118, "The network connection is unstable or the system is busy."},
	{119, "Invalid session."},
	{150, "Request source IP does not match the login IP."},
}

type SynologyLoginResponse struct {
	Data struct {
		SID string `json:"sid"`
	} `json:"data"`
	Success bool `json:"success"`
	Error   struct {
		Code int `json:"code"`
	} `json:"error"`
}

type UserListData struct {
	Offset int `json:"offset"`
	Total  int `json:"total"`
	Users  []struct {
		Expired string `json:"expired"`
		Name    string `json:"name"`
	} `json:"users"`
}

func getErrorDescription(error int) string {
	for _, errorCode := range SynologyErrorCodes {
		if error == errorCode.Code {
			return errorCode.Description
		}
	}
	return "Unknown error"
}

type SecurityAuditResponse struct {
	Data struct {
		HasFail bool `json:"has_fail"`
		Result  []struct {
			API     string      `json:"api"`
			Data    interface{} `json:"data"`
			Method  string      `json:"method"`
			Success bool        `json:"success"`
			Version int         `json:"version"`
		} `json:"result"`
	} `json:"data"`
	Success bool `json:"success"`
}

func login(user *SynauditUser) (string, error) {
	config := SynauditConfig{
		host: "https://192.168.1.198:8443",
	}

	url := fmt.Sprintf("%s/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=login&account=%s&passwd=%s&format=sid", config.host, user.username, user.password)
	var loginResp SynologyLoginResponse
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Since a lot of Synology Nas have self signed certificat...
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("HTTP request failed: %v\n", err)
		return "", err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	if err != nil {
		fmt.Printf("Error decoding JSON response: %v\n", err)
		return "", err
	}
	if !loginResp.Success {
		fmt.Printf("Erreur Synology (code %d): %s\n", loginResp.Error.Code, getErrorDescription(loginResp.Error.Code))
	} else {
		fmt.Printf("SID: %s\n", loginResp.Data.SID)
	}
	return loginResp.Data.SID, nil
}

type SecurityAuditDecoder struct {
	response SecurityAuditResponse
}

func NewSecurityAuditDecoder(jsonData []byte) (*SecurityAuditDecoder, error) {
	var response SecurityAuditResponse
	if err := json.Unmarshal(jsonData, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &SecurityAuditDecoder{response: response}, nil
}

func (d *SecurityAuditDecoder) GetUserListData() (*UserListData, error) {
	result, err := d.getTypedData("SYNO.Core.User", &UserListData{})
	if err != nil {
		return nil, err
	}
	return result.(*UserListData), nil
}

// Generic method to extract and unmarshal specific API data
func (d *SecurityAuditDecoder) getTypedData(apiName string, target interface{}) (interface{}, error) {
	for _, result := range d.response.Data.Result {
		if result.API == apiName {
			dataBytes, err := json.Marshal(result.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal data for %s: %w", apiName, err)
			}

			if err := json.Unmarshal(dataBytes, target); err != nil {
				return nil, fmt.Errorf("failed to unmarshal %s data: %w", apiName, err)
			}

			return target, nil
		}
	}
	return nil, fmt.Errorf("API %s not found in response", apiName)
}

func main() {
	//login(&SynauditUser{username: "webdav", password: "Whinny1-Disperser8-Frolic9-Ranged5-Situation5s"})

	// https://kb.synology.com/en-us/DSM/tutorial/What_network_ports_are_used_by_Synology_services
	// services := []SynologyPorts{
	// 	{
	// 		name:     "DSM HTTP",
	// 		ports:    []int{5000},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "DSM HTTPS",
	// 		ports:    []int{5001},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "FTP",
	// 		ports:    []int{21, 20},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "SSH",
	// 		ports:    []int{22},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "SMB",
	// 		ports:    []int{445, 139},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "AFP",
	// 		ports:    []int{548},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "WebDAV",
	// 		ports:    []int{5005, 5006},
	// 		protocol: "tcp",
	// 	},
	// 	{
	// 		name:     "rsync",
	// 		ports:    []int{873},
	// 		protocol: "tcp",
	// 	},
	// }

	// for _, service := range services {
	// 	address := fmt.Sprintf("%s:%d", host, service.ports[0])
	// 	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	// 	if err != nil {
	// 		fmt.Printf("%s on port %d: closed or unreachable\n", service.name, service.ports[0])
	// 	} else {
	// 		fmt.Printf("%s on port %d: open : check it out \n", service.name, service.ports[0])

	// 		conn.Close()
	// 	}
	// }

	url := "https://192.168.1.198:8443/webapi/entry.cgi"
	method := "POST"
	payload := strings.NewReader("api=SYNO.Entry.Request&method=request&version=1&stop_when_error=false&mode=%22sequential%22&compound=%5B%7B%22api%22%3A%22SYNO.Core.Security.DSM%22%2C%22method%22%3A%22get%22%2C%22version%22%3A5%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.DSM.Embed%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.OTP.EnforcePolicy%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.SecureSignIn.AMFA.Policy%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.SmartBlock%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.Firewall.Conf%22%2C%22method%22%3A%22get%22%2C%22version%22%3A%221%22%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.AutoBlock%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.DoS%22%2C%22method%22%3A%22get%22%2C%22version%22%3A2%2C%22configs%22%3A%5B%7B%22adapter%22%3A%22eth0%22%7D%2C%7B%22adapter%22%3A%22eth1%22%7D%2C%7B%22adapter%22%3A%22pppoe%22%7D%5D%7D%2C%7B%22api%22%3A%22SYNO.Core.Web.Security.HTTPCompression%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Web.Security.TLSProfile%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Hardware.SpectreMeltdown%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Storage.CGI.KMIP%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.Firewall%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.User%22%2C%22method%22%3A%22list%22%2C%22version%22%3A1%2C%22type%22%3A%22local%22%2C%22additional%22%3A%5B%22expired%22%5D%7D%2C%7B%22api%22%3A%22SYNO.Core.System%22%2C%22method%22%3A%22info%22%2C%22version%22%3A3%7D%2C%7B%22api%22%3A%22SYNO.Core.QuickConnect%22%2C%22method%22%3A%22get%22%2C%22version%22%3A2%7D%2C%7B%22api%22%3A%22SYNO.Core.Upgrade.Server%22%2C%22method%22%3A%22check%22%2C%22version%22%3A3%2C%22user_reading%22%3Atrue%2C%22need_auto_smallupdate%22%3Atrue%2C%22need_promotion%22%3Atrue%7D%5D")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Since a lot of Synology Nas have self signed certificat...
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", "id=uLbrFS4jTqElQmCf9MvKGuHNEWrW5s08j-g_8t4NR7MlWqlu3IzwUWOUS_jv_E9iZwoPgzotsskTiYLdb17eKA; did=cos6gbAOdIBofOExp1JzMdjnnQMkJHc_TdE9JfbNPF1UWRLAnkq0LhxWCxQrGZ4DrG6xDeUNlm8EG_5McVh8Qg; id=uLbrFS4jTqElQmCf9MvKGuHNEWrW5s08j-g_8t4NR7MlWqlu3IzwUWOUS_jv_E9iZwoPgzotsskTiYLdb17eKA")

	res, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	decoder, err := NewSecurityAuditDecoder([]byte(body))
	users, _ := decoder.GetUserListData()
	fmt.Printf("%v", users)

}
