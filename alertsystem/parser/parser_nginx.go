package parser

import (
	"encoding/json"
	"net/url"
	"strings"
	//"time"
)

type NginxLog struct {
	TimeLocal     string `json:"time_local"`
	RemoteAddr    string `json:"remote_addr"`
	Request       string `json:"request"`
	RequestBody   string `json:"request_body"`
	Username      string `json:"username"`
}

func (l NginxLog) IsLogin() bool {
	return strings.HasPrefix(l.Request, "POST") && 
	       strings.Contains(l.Request, "/login")
}

func (l NginxLog) GetUsername() string {
	return l.Username
}

func (l NginxLog) GetTime() string {
	t, _, _ := strings.Cut(l.TimeLocal, " ")
	return t
}

func ParseNginxLine(line string) (NginxLog, error) {
	var log NginxLog
	err := json.Unmarshal([]byte(line), &log)
	if err != nil {
		return NginxLog{}, err
	}

	if log.IsLogin() {
		values, err := url.ParseQuery(log.RequestBody)
		if err == nil {
			log.Username = values.Get("username")
		}
	}
	return log, nil
}