package main

import "time"

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

type Finding struct {
	Title       string
	Description string
	Remediation string
}

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
