package api

import (
	"encoding/json"
	"net/url"
)

type APIEndpoint struct {
	API                 string                 `json:"api"`
	Method              string                 `json:"method"`
	Version             int                    `json:"version"`
	Type                string                 `json:"type,omitempty"`
	Additional          []string               `json:"additional,omitempty"`
	Configs             []map[string]string    `json:"configs,omitempty"`
	UserReading         bool                   `json:"user_reading,omitempty"`
	Params              map[string]interface{} `json:"params,omitempty"`
	NeedAutoSmallupdate bool                   `json:"need_auto_smallupdate,omitempty"`
	NeedPromotion       bool                   `json:"need_promotion,omitempty"`
}

// Endpoints can be retrieve by sending a GET request to https://<NAS IP>:<PORT>/webapi/query.cgi?api=SYNO.API.Info&version=1&query=all
var SecurityAPIs = []APIEndpoint{
	{API: "SYNO.Core.Security.DSM", Method: "get", Version: 5},
	{API: "SYNO.Core.Security.DSM.Embed", Method: "get", Version: 1},
	{API: "SYNO.Core.OTP.EnforcePolicy", Method: "get", Version: 1},
	{API: "SYNO.SecureSignIn.AMFA.Policy", Method: "get", Version: 1},
	{API: "SYNO.Core.SmartBlock", Method: "get", Version: 1},
	{API: "SYNO.Core.Security.Firewall.Conf", Method: "get", Version: 1},
	{API: "SYNO.Core.Security.AutoBlock", Method: "get", Version: 1},
	{API: "SYNO.Core.Security.DoS", Method: "get", Version: 2, Configs: []map[string]string{
		{"adapter": "eth0"},
		{"adapter": "eth1"},
		{"adapter": "pppoe"},
	}},
	{API: "SYNO.Core.Web.Security.HTTPCompression", Method: "get", Version: 1},
	{API: "SYNO.Core.Web.Security.TLSProfile", Method: "get", Version: 1},
	{API: "SYNO.Core.Hardware.SpectreMeltdown", Method: "get", Version: 1},
	{API: "SYNO.Storage.CGI.KMIP", Method: "get", Version: 1},
	{API: "SYNO.Core.Security.Firewall", Method: "get", Version: 1},
	{API: "SYNO.Core.User", Method: "list", Version: 1, Type: "local", Additional: []string{"expired"}},
	{API: "SYNO.Core.System", Method: "info", Version: 3},
	{API: "SYNO.Core.QuickConnect", Method: "get", Version: 2},
	{API: "SYNO.Core.Upgrade.Server", Method: "check", Version: 3, UserReading: true, NeedAutoSmallupdate: true, NeedPromotion: true},

	{API: "SYNO.Core.User.PasswordPolicy", Method: "get", Version: 1},

	{API: "SYNO.Core.Network.PPPoE", Method: "list", Version: 1},

	{API: "SYNO.Core.Terminal", Method: "get", Version: 3}, // SSH/Telnet
	{API: "SYNO.Core.FileServ.FTP", Method: "get", Version: 3},
	{API: "SYNO.Core.FileServ.SMB", Method: "get", Version: 3},
	{API: "SYNO.Core.FileServ.NFS", Method: "get", Version: 2},
	{API: "SYNO.Core.FileServ.AFP", Method: "get", Version: 1},

	{API: "SYNO.Core.Certificate.CRT", Method: "list", Version: 1},

	{API: "SYNO.Core.Upgrade.Setting", Method: "get", Version: 1},
	{API: "SYNO.Core.Package", Method: "list", Version: 2},

	{API: "SYNO.Backup.Task", Method: "list", Version: 1},
	{API: "SYNO.Core.Share", Method: "list", Version: 1, Additional: []string{"recycle_bin"}},

	{API: "SYNO.Core.Notification.SMS.Conf", Method: "get", Version: 1},
	{API: "SYNO.Core.Notification.Mail.Conf", Method: "get", Version: 1},
	{API: "SYNO.Core.SyslogClient.Log", Method: "list", Version: 1, Params: map[string]interface{}{
		"offset":  0,
		"limit":   50,
		"target":  "LOCAL",
		"logtype": "connection",
		"level":   "warning",
	}}}

func BuildCompoundPayload() string {
	var endpoints []map[string]interface{}
	for _, ep := range SecurityAPIs {
		endpoint := map[string]interface{}{
			"api":     ep.API,
			"method":  ep.Method,
			"version": ep.Version,
		}
		if ep.Type != "" {
			endpoint["type"] = ep.Type
		}
		if len(ep.Additional) > 0 {
			endpoint["additional"] = ep.Additional
		}
		if len(ep.Configs) > 0 {
			endpoint["configs"] = ep.Configs
		}
		if ep.UserReading {
			endpoint["user_reading"] = ep.UserReading
		}
		if ep.NeedAutoSmallupdate {
			endpoint["need_auto_smallupdate"] = ep.NeedAutoSmallupdate
		}
		if ep.NeedPromotion {
			endpoint["need_promotion"] = ep.NeedPromotion
		}
		if ep.Params != nil {
			for k, v := range ep.Params {
				endpoint[k] = v
			}
		}
		endpoints = append(endpoints, endpoint)
	}

	compoundJSON, _ := json.Marshal(endpoints)

	params := url.Values{}
	params.Set("api", "SYNO.Entry.Request")
	params.Set("method", "request")
	params.Set("version", "1")
	params.Set("stop_when_error", "false")
	params.Set("mode", "sequential")
	params.Set("compound", string(compoundJSON))

	return params.Encode()
}
