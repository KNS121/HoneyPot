package aggregator

import (
	"alertsystem/parser"
	"bufio"
	"encoding/json"
	"os"
	"time"
)

type Aggregator struct {
	alertsFile   *os.File
	writer       *bufio.Writer
	failedLogins map[string][]time.Time // username -> []attempt times
}

func New(alertsPath string) (*Aggregator, error) {
	file, err := os.OpenFile(alertsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Aggregator{
		alertsFile:   file,
		writer:       bufio.NewWriter(file),
		failedLogins: make(map[string][]time.Time),
	}, nil
}

func (a *Aggregator) Close() {
	a.writer.Flush()
	a.alertsFile.Close()
}

func (a *Aggregator) ProcessLog(entry parser.LogEntry) {
	switch log := entry.(type) {
	case parser.WebServiceLog:
		a.processWebLog(log)
	}
}

func (a *Aggregator) processWebLog(log parser.WebServiceLog) {
	// Проверяем брутфорс
	if log.Status == "failure" {
		a.checkBruteforce(log)
	}

	// Записываем обычный алерт
	alert := parser.Alert{
		Type:     "alert",
		Date:     log.TimeLocal,
		Action:   "login",
		Status:   log.Status,
		Username: log.Username,
		Password: log.Password,
	}

	a.writeAlert(alert)
}

func (a *Aggregator) checkBruteforce(log parser.WebServiceLog) {
	now := time.Now()
	attempts := a.failedLogins[log.Username]

	// Добавляем текущую попытку
	attempts = append(attempts, now)
	a.failedLogins[log.Username] = attempts

	// Удаляем старые попытки (>5 минут назад)
	var recentAttempts []time.Time
	for _, t := range attempts {
		if now.Sub(t) <= 5*time.Minute {
			recentAttempts = append(recentAttempts, t)
		}
	}
	a.failedLogins[log.Username] = recentAttempts

	// Если больше 5 попыток - алерт
	if len(recentAttempts) > 5 {
		alert := parser.Alert{
			Type:     "bruteforce",
			Date:     log.TimeLocal,
			Action:   "login",
			Username: log.Username,
			Count:    len(recentAttempts),
		}
		a.writeAlert(alert)
	}
}

func (a *Aggregator) writeAlert(alert parser.Alert) {
	jsonData, _ := json.Marshal(alert)
	a.writer.Write(jsonData)
	a.writer.WriteString("\n")
	a.writer.Flush()
}