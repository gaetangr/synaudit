package main

import (
	"testing"
)

func Test_getUserData(t *testing.T) {
	mockResponse := SynologyResponse{
		Success: true,
		Data: SynologyResponseData{
			HasFail: false,
			Result: []APIResult{
				{
					API: "SYNO.Core.User",
					Data: map[string]interface{}{
						"total": 2,
						"users": []map[string]interface{}{
							{"name": "admin", "expired": "now"},
							{"name": "user1", "expired": "normal"},
						},
					},
				},
			},
		},
	}

	userData, err := getUserData(mockResponse)
	if err != nil {
		t.Errorf("getUserData() error = %v", err)
		return
	}

	if userData.Total != 2 {
		t.Errorf("getUserData() total = %v, want %v", userData.Total, 2)
	}

	if len(userData.Users) != 2 {
		t.Errorf("getUserData() users count = %v, want %v", len(userData.Users), 2)
	}
}

func Test_getFirewallData(t *testing.T) {
	mockResponse := SynologyResponse{
		Success: true,
		Data: SynologyResponseData{
			HasFail: false,
			Result: []APIResult{
				{
					API: "SYNO.Core.Security.Firewall",
					Data: map[string]interface{}{
						"enable_firewall": true,
					},
				},
			},
		},
	}

	firewallData, err := getFirewallData(mockResponse)
	if err != nil {
		t.Errorf("getFirewallData() error = %v", err)
		return
	}

	if !firewallData.Enable_firewall {
		t.Errorf("getFirewallData() enable_firewall = %v, want %v", firewallData.Enable_firewall, true)
	}
}

func Test_getData_APINotFound(t *testing.T) {
	mockResponse := SynologyResponse{
		Success: true,
		Data: SynologyResponseData{
			HasFail: false,
			Result: []APIResult{
				{
					API:  "SYNO.Other.API",
					Data: map[string]interface{}{},
				},
			},
		},
	}

	_, err := getUserData(mockResponse)
	if err == nil {
		t.Errorf("getUserData() should return error when API not found")
	}
}
