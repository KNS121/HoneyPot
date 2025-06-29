package aggregator

import (
	"alertsystem/parser"
	"alertsystem/rules"
	"bufio"
	"encoding/json"
	"os"
	"time"
)

type Aggregator struct {
	alertsFile  *os.File
	writer      *bufio.Writer
	bruteRule   *rules.BruteforceRule
	sprayRule   *rules.PasswordSprayRule
	sqlInjRule  *rules.SQLInjectionRule
	lastCleanup time.Time
}

func New(alertsPath string) (*Aggregator, error) {
	file, err := os.OpenFile(alertsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Aggregator{
		alertsFile:  file,
		writer:      bufio.NewWriter(file),
		bruteRule:   rules.NewBruteforceRule(),
		sprayRule:   rules.NewPasswordSprayRule(),
		sqlInjRule:  rules.NewSQLInjectionRule(),
		lastCleanup: time.Now(),
	}, nil
}

func (a *Aggregator) Close() {
	a.writer.Flush()
	a.alertsFile.Close()
}

func (a *Aggregator) ProcessLog(entry parser.LogEntry) {
	switch log := entry.(type) {
	case parser.NginxLog:
		a.processNginxLog(log)
	}
}

func (a *Aggregator) processNginxLog(log parser.NginxLog) {
	now := time.Now()
	
	// Периодическая очистка
	if now.Sub(a.lastCleanup) > 2*time.Minute {
		a.lastCleanup = now
	}
	
	// Проверяем только логины
	if !log.IsLogin() {
		return
	}
	
	// Проверка правил
	if alert := a.sqlInjRule.Check(log, now); alert != nil {
		a.writeAlert(*alert)
	}
	
	if alert := a.bruteRule.Check(log, now); alert != nil {
		a.writeAlert(*alert)
	}
	
	if alert := a.sprayRule.Check(log, now); alert != nil {
		a.writeAlert(*alert)
	}
	
	// Запись обычного алерта
	a.writeAlert(parser.Alert{
		Type:       "alert",
		Date:       log.TimeLocal,
		RemoteAddr: log.RemoteAddr,
		Action:     "login",
		Username:   log.Username,
		Password:   log.Password,
		Status:     log.Status,
	})
}

func (a *Aggregator) writeAlert(alert parser.Alert) {
	jsonData, _ := json.Marshal(alert)
	a.writer.Write(jsonData)
	a.writer.WriteString("\n")
	a.writer.Flush()
}