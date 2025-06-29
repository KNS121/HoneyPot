package rules

import (
	"alertsystem/parser"
	"strings"
	"time"
)

var sqlPatterns = []string{
	"' OR '1'='1",
	"' OR 1=1 --",
	"\" OR \"\"=\"",
	" UNION SELECT ",
	" UNION ALL SELECT ",
	"; DROP TABLE ",
	"; SELECT ",
	" OR 1=1",
	" AND 1=1",
	" EXEC ",
	" EXECUTE ",
	" DECLARE ",
	" WAITFOR DELAY ",
	" XP_",
	"/*",
	"*/",
	"--",
	";",
}

type SQLInjectionRule struct {
	alerts map[string]time.Time // Для отслеживания последних алертов по IP
}

func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{
		alerts: make(map[string]time.Time),
	}
}

func (r *SQLInjectionRule) Check(log parser.NginxLog, now time.Time) *parser.Alert {
	// Проверяем только логины
	if !log.IsLogin() {
		return nil
	}

	// Проверяем username и password на SQL-инъекции
	if containsSQLInjection(log.Username) || containsSQLInjection(log.Password) {
		// Проверяем, не отправляли ли мы уже алерт для этого IP в последние 30 минут
		if lastAlert, exists := r.alerts[log.RemoteAddr]; !exists || now.Sub(lastAlert) > 1*time.Minute {
			r.alerts[log.RemoteAddr] = now
			
			return &parser.Alert{
				Type:       "sql_injection",
				Date:       log.TimeLocal,
				RemoteAddr: log.RemoteAddr,
				Action:     "login",
				Username:   log.Username,
				Status:     "attempt",
			}
		}
	}
	return nil
}

func containsSQLInjection(input string) bool {
	if input == "" {
		return false
	}
	
	input = strings.ToUpper(input)
	for _, pattern := range sqlPatterns {
		if strings.Contains(input, strings.ToUpper(pattern)) {
			return true
		}
	}
	return false
}