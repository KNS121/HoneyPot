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
}

func (l WebServiceLog) IsLogin() bool {
	return true // Все записи в этом логе считаем попытками входа
}

func (l WebServiceLog) GetUsername() string {
	return l.Username
}

func (l WebServiceLog) GetTime() string {
	return l.TimeLocal
}

func ParseWebServiceLine(line string) (WebServiceLog, error) {
	var log WebServiceLog
	err := json.Unmarshal([]byte(line), &log)
	if err != nil {
		return WebServiceLog{}, err
	}
	return log, nil
}