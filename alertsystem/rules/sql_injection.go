package rules

import (
	"alertsystem/parser"
	"strings"
	"time"
)

// SQL ключевые слова и опасные паттерны для обнаружения
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

func (r *SQLInjectionRule) Check(log parser.WebServiceLog, now time.Time) *parser.Alert {
	// Проверяем username и password на SQL-инъекции
	if containsSQLInjection(log.Username) || containsSQLInjection(log.Password) {
		// Проверяем, не отправляли ли мы уже алерт для этого IP в последние 30 минут
		if lastAlert, exists := r.alerts[log.Username]; !exists || now.Sub(lastAlert) > 5*time.Second {
			r.alerts[log.Username] = now
			
			return &parser.Alert{
				Type:     "sql_injection",
				Date:     log.TimeLocal,
				Action:   "login",
				Username: log.Username,
				Status:   "attempt",
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