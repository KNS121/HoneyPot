package parser

import (
	"encoding/json"
)

type WebServiceLog struct {
	TimeLocal string `json:"time_local"`
	Level     string `json:"level"`
	Status    string `json:"status"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	IsLogin   bool   `json:"is_login"`  
}

func ParseWebServiceLine(line string) (WebServiceLog, error) {
	var log WebServiceLog
	log.IsLogin = true
	err := json.Unmarshal([]byte(line), &log)
	if err != nil {
		return WebServiceLog{}, err
	}
	return log, nil
}
