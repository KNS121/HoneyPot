package aggregator

import (
	"alertsystem/parser"
	"bufio"
	"encoding/json"
	"os"
	"time"
)

type passwordAttempt struct {
	username string
	time     time.Time
}

type Aggregator struct {
	alertsFile    *os.File
	writer        *bufio.Writer
	failedLogins  map[string][]time.Time       // Для брутфорса (username -> attempts)
	passwordSpray map[string][]passwordAttempt // Для spraying (password -> attempts)
	sprayAlerts   map[string]time.Time         // Отправленные spraying алерты
	bruteAlerts   map[string]time.Time         // Отправленные brute алерты
}

func New(alertsPath string) (*Aggregator, error) {
	file, err := os.OpenFile(alertsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Aggregator{
		alertsFile:    file,
		writer:        bufio.NewWriter(file),
		failedLogins:  make(map[string][]time.Time),
		passwordSpray: make(map[string][]passwordAttempt),
		sprayAlerts:   make(map[string]time.Time),
		bruteAlerts:   make(map[string]time.Time),
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
	
	// Очищаем старые данные перед обработкой
	a.cleanupOldData(now)
	
	// 1. Проверка брутфорса (только для неудачных попыток)
	if log.Status == "failure" {
		a.checkBruteforce(log, now)
	}
	
	// 2. Проверка password spraying (только для неудачных попыток)
	if log.Status == "failure" {
		a.checkPasswordSpraying(log, now)
	}
	
	// 3. Запись обычного алерта
	alert := parser.Alert{
		Type:     "alert",
		Date:     log.TimeLocal,
		Action:   "login",
		Username: log.Username,
		Password: log.Password,
		Status:   log.Status,
	}
	a.writeAlert(alert)
}

func (a *Aggregator) cleanupOldData(now time.Time) {
	// Очистка данных для брутфорса
	for username, attempts := range a.failedLogins {
		var recentAttempts []time.Time
		for _, t := range attempts {
			if now.Sub(t) <= 5*time.Minute {
				recentAttempts = append(recentAttempts, t)
			}
		}
		if len(recentAttempts) > 0 {
			a.failedLogins[username] = recentAttempts
		} else {
			delete(a.failedLogins, username)
		}
	}

	// Очистка данных для spraying
	for password, attempts := range a.passwordSpray {
		var recentAttempts []passwordAttempt
		for _, attempt := range attempts {
			if now.Sub(attempt.time) <= 2*time.Minute {
				recentAttempts = append(recentAttempts, attempt)
			}
		}
		if len(recentAttempts) > 0 {
			a.passwordSpray[password] = recentAttempts
		} else {
			delete(a.passwordSpray, password)
		}
	}

	// Очистка старых spraying алертов (>30 минут)
	for password, alertTime := range a.sprayAlerts {
		if now.Sub(alertTime) > 2*time.Minute {
			delete(a.sprayAlerts, password)
		}
	}

	// Очистка старых brute алертов (>30 минут)
	for username, alertTime := range a.bruteAlerts {
		if now.Sub(alertTime) > 2*time.Minute {
			delete(a.bruteAlerts, username)
		}
	}
}

func (a *Aggregator) checkBruteforce(log parser.WebServiceLog, now time.Time) {
	username := log.Username
	
	// Добавляем текущую попытку
	a.failedLogins[username] = append(a.failedLogins[username], now)
	
	// Проверяем условия для алерта
	if len(a.failedLogins[username]) >= 5 { // Порог = 5 попыток
		// Проверяем, не отправляли ли мы уже алерт для этого пользователя
		if lastAlert, exists := a.bruteAlerts[username]; !exists || now.Sub(lastAlert) > 2*time.Minute {
			alert := parser.Alert{
				Type:     "bruteforce",
				Date:     log.TimeLocal,
				Action:   "login",
				Username: username,
				Count:    len(a.failedLogins[username]),
			}
			a.writeAlert(alert)
			a.bruteAlerts[username] = now
			
			// Сбрасываем счетчик после алерта
			delete(a.failedLogins, username)
		}
	}
}

func (a *Aggregator) checkPasswordSpraying(log parser.WebServiceLog, now time.Time) {
	password := log.Password
	username := log.Username

	// Добавляем текущую попытку
	a.passwordSpray[password] = append(a.passwordSpray[password], passwordAttempt{
		username: username,
		time:     now,
	})

	// Проверяем условия для алерта
	if len(a.passwordSpray[password]) >= 2 { // Порог = 3 разные учетки
		// Проверяем уникальных пользователей
		uniqueUsers := make(map[string]bool)
		for _, attempt := range a.passwordSpray[password] {
			uniqueUsers[attempt.username] = true
		}

		if len(uniqueUsers) >= 2 {
			// Проверяем, не отправляли ли мы уже алерт для этого пароля
			if lastAlert, exists := a.sprayAlerts[password]; !exists || now.Sub(lastAlert) > 30*time.Minute {
				alert := parser.Alert{
					Type:           "password_spraying",
					Date:           log.TimeLocal,
					Action:         "login",
					Count:          len(uniqueUsers),
					CommonPassword: password,
				}
				a.writeAlert(alert)
				a.sprayAlerts[password] = now
				
				// Сбрасываем счетчик после алерта
				delete(a.passwordSpray, password)
			}
		}
	}
}

func (a *Aggregator) writeAlert(alert parser.Alert) {
	jsonData, _ := json.Marshal(alert)
	a.writer.Write(jsonData)
	a.writer.WriteString("\n")
	a.writer.Flush()
}