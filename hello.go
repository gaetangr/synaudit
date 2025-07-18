package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	UserStatusExpired = "now"
	UserStatusActive  = "normal"
	AdminUsername     = "admin"
)

type UserListData struct {
	Total int `json:"total"`
	Users []struct {
		Expired string `json:"expired"`
		Name    string `json:"name"`
	} `json:"users"`
}

// Structure pour une trouvaille/problème
type Finding struct {
	Title       string
	Description string
	Remediation string
}

// Structure pour le rapport complet
type SecurityReport struct {
	Findings  []Finding
	CheckedAt time.Time
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
func IsAdminDisabled(userListData UserListData) (bool, error) {
	for _, user := range userListData.Users {
		if user.Name == AdminUsername {

			if user.Expired == UserStatusExpired {
				return true, nil
			}
			return false, nil
		}
	}

	return false, fmt.Errorf("utilisateur admin non trouvé")
}

func checkAdminStatus(userData UserListData) []Finding {
	var findings []Finding

	disabled, err := IsAdminDisabled(userData)
	if err != nil {
		findings = append(findings, Finding{
			Title:       "Admin User Not Found",
			Description: "The admin account does not exist in the system",
			Remediation: "Investigate why the admin account is missing",
		})
		return findings
	}

	if disabled {
		findings = append(findings, Finding{
			Title:       "Admin Account Disabled",
			Description: "The admin account is currently disabled (expired status: 'now')",
			Remediation: "Re-enable the admin account if this was not intentional",
		})
	}

	return findings // Peut être vide si admin est actif
}
func generateReport(response SynologyResponse) (*SecurityReport, error) {
	report := &SecurityReport{
		CheckedAt: time.Now(),
		Findings:  []Finding{},
	}

	userData, err := getUserData(response)

	if err != nil {
		return report, err
	}

	report.Findings = append(report.Findings, checkAdminStatus(userData)...)

	return report, nil
}
func displayReport(report *SecurityReport) {
	fmt.Println("\n=== SECURITY AUDIT REPORT ===")
	fmt.Printf("Checked at: %s\n", report.CheckedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Total issues: %d\n\n", len(report.Findings))

	if len(report.Findings) == 0 {
		fmt.Println("✅ No security issues found!")
		return
	}

	// Afficher chaque finding
	for i, finding := range report.Findings {
		fmt.Printf("%d. %s\n", i+1, finding.Title)
		fmt.Printf("   Problem: %s\n", finding.Description)
		fmt.Printf("   Solution: %s\n\n", finding.Remediation)
	}
}

func fetchSynologyData(url string) (*SynologyResponse, error) {
	payload := strings.NewReader("api=SYNO.Entry.Request&method=request&version=1&stop_when_error=false&mode=%22sequential%22&compound=%5B%7B%22api%22%3A%22SYNO.Core.Security.DSM%22%2C%22method%22%3A%22get%22%2C%22version%22%3A5%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.DSM.Embed%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.OTP.EnforcePolicy%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.SecureSignIn.AMFA.Policy%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.SmartBlock%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.Firewall.Conf%22%2C%22method%22%3A%22get%22%2C%22version%22%3A%221%22%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.AutoBlock%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.DoS%22%2C%22method%22%3A%22get%22%2C%22version%22%3A2%2C%22configs%22%3A%5B%7B%22adapter%22%3A%22eth0%22%7D%2C%7B%22adapter%22%3A%22eth1%22%7D%2C%7B%22adapter%22%3A%22pppoe%22%7D%5D%7D%2C%7B%22api%22%3A%22SYNO.Core.Web.Security.HTTPCompression%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Web.Security.TLSProfile%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Hardware.SpectreMeltdown%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Storage.CGI.KMIP%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.Security.Firewall%22%2C%22method%22%3A%22get%22%2C%22version%22%3A1%7D%2C%7B%22api%22%3A%22SYNO.Core.User%22%2C%22method%22%3A%22list%22%2C%22version%22%3A1%2C%22type%22%3A%22local%22%2C%22additional%22%3A%5B%22expired%22%5D%7D%2C%7B%22api%22%3A%22SYNO.Core.System%22%2C%22method%22%3A%22info%22%2C%22version%22%3A3%7D%2C%7B%22api%22%3A%22SYNO.Core.QuickConnect%22%2C%22method%22%3A%22get%22%2C%22version%22%3A2%7D%2C%7B%22api%22%3A%22SYNO.Core.Upgrade.Server%22%2C%22method%22%3A%22check%22%2C%22version%22%3A3%2C%22user_reading%22%3Atrue%2C%22need_auto_smallupdate%22%3Atrue%2C%22need_promotion%22%3Atrue%7D%5D")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, fmt.Errorf("création requête: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", "id=uLbrFS4jTqElQmCf9MvKGuHNEWrW5s08j-g_8t4NR7MlWqlu3IzwUWOUS_jv_E9iZwoPgzotsskTiYLdb17eKA; did=cos6gbAOdIBofOExp1JzMdjnnQMkJHc_TdE9JfbNPF1UWRLAnkq0LhxWCxQrGZ4DrG6xDeUNlm8EG_5McVh8Qg")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requête HTTP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("lecture body: %w", err)
	}

	var response SynologyResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API Synology a retourné success=false")
	}

	return &response, nil
}
func main() {
	url := "https://192.168.1.198:8443/webapi/entry.cgi"

	// Récupérer les données
	response, err := fetchSynologyData(url)
	if err != nil {
		fmt.Printf("❌ Erreur: %v\n", err)
		return
	}

	// Générer le rapport
	report, err := generateReport(*response)
	if err != nil {
		fmt.Printf("❌ Erreur génération rapport: %v\n", err)
		return
	}

	// Afficher le rapport
	displayReport(report)
}
