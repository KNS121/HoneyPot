// parser/parser_nginx.go
package parser

import (
	"encoding/json"
	"net/url"
	"strings"
)

type NginxLog struct {
	TimeLocal     string `json:"time_local"`
	RemoteAddr    string `json:"remote_addr"`
	Request       string `json:"request"`
	RequestBody   string `json:"request_body"`
	Username      string `json:"username"`
	IsLogin       bool   `json:"is_login"`
}

func ParseNginxLine(line string) (NginxLog, error) {
	var log NginxLog
	err := json.Unmarshal([]byte(line), &log)
	if err != nil {
		return NginxLog{}, err
	}

	log.TimeLocal, _, _ = strings.Cut(log.TimeLocal, " ")

	log.IsLogin = strings.HasPrefix(log.Request, "POST") && 
	              strings.Contains(log.Request, "/login")
	
	if log.IsLogin {
		values, err := url.ParseQuery(log.RequestBody)
		if err == nil {
			log.Username = values.Get("username")
		}
	}
	return log, nil
}