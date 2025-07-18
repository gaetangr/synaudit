package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type UserListData struct {
	Total int `json:"total"`
	Users []struct {
		Expired string `json:"expired"`
		Name    string `json:"name"`
	} `json:"users"`
}

type APIResult struct {
	API  string      `json:"api"`
	Data interface{} `json:"data"`
}
type SynologyResponseData struct {
	Result []APIResult `json:"result"`
}

type SynologyResponse struct {
	Success bool                 `json:"success"`
	Data    SynologyResponseData `json:"data"`
}

func getUserData(response SynologyResponse) (UserListData, error) {
	endpoint := "SYNO.Core.User"
	for _, result := range response.Data.Result {
		if result.API == endpoint {
			jsonBytes, err := json.Marshal(result.Data)
			var userData UserListData
			err = json.Unmarshal(jsonBytes, &userData)
			if err != nil {
				return UserListData{}, err
			}
			return userData, nil
		}
	}
	return UserListData{}, fmt.Errorf("API %s non trouvée", endpoint)
}

func main() {

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
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Erreur HTTP: %v\n", err) // ✅ Message clair
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Erreur lecture: %v\n", err)
		return
	}

	var response SynologyResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Printf("Erreur JSON: %v\n", err)
		return
	}

	if !response.Success {
		fmt.Println("❌ La requête Synology a échoué")
		return
	}

	userData, err := getUserData(response)
	if err != nil {
		fmt.Printf("Erreur getUserData: %v\n", err)
		return
	}

	fmt.Printf("📊 Total users: %d\n", userData.Total)

	// Vérifier admin
	adminFound := false
	for _, user := range userData.Users {
		if user.Name == "admin" {
			adminFound = true
			if user.Expired == "now" {
				fmt.Println("⚠️  Admin est DISABLED!")
			} else {
				fmt.Println("✅ Admin est ENABLED")
			}
			break
		}
	}

	if !adminFound {
		fmt.Println("❓ User admin non trouvé")
	}

}
