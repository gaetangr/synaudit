package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt" // Ajoute ceci pour lire le corps
	"net/http"
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

// SynologyErrorCode représente un code d'erreur et sa signification
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

// Structure pour la réponse JSON attendue
type SynologyLoginResponse struct {
	Data struct {
		SID string `json:"sid"`
	} `json:"data"`
	Success bool `json:"success"`
	Error   struct {
		Code int `json:"code"`
	} `json:"error"`
}

func getErrorDescription(error int) string {
	for _, errorCode := range SynologyErrorCodes {
		if error == errorCode.Code {
			return errorCode.Description
		}
	}
	return "Unknown error"
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

func main() {
	//login(&SynauditUser{username: "webdav", password: "Whinny1-Disperser8-Frolic9-Ranged5-Situation5s"})
	fmt.Printf(getErrorDescription(107))
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
}
