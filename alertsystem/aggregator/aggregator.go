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
		lastCleanup: time.Now(),
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
	now := time.Now()
	
	// Периодическая очистка
	if now.Sub(a.lastCleanup) > 5*time.Minute {
		a.lastCleanup = now
	}
	
	// Проверка правил
	if alert := a.bruteRule.Check(log, now); alert != nil {
		a.writeAlert(*alert)
	}
	
	if alert := a.sprayRule.Check(log, now); alert != nil {
		a.writeAlert(*alert)
	}
	
	// Запись обычного алерта
	a.writeAlert(parser.Alert{
		Type:     "alert",
		Date:     log.TimeLocal,
		Action:   "login",
		Username: log.Username,
		Password: log.Password,
		Status:   log.Status,
	})
}

func (a *Aggregator) writeAlert(alert parser.Alert) {
	jsonData, _ := json.Marshal(alert)
	a.writer.Write(jsonData)
	a.writer.WriteString("\n")
	a.writer.Flush()
}