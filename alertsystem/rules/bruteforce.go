package rules

import (
	"alertsystem/parser"
	"time"
)

const (
	bruteForceAttemptsThreshold = 5
	bruteForceWindow            = 1 * time.Minute
	bruteForceAlertCooldown     = 1 * time.Minute
)

type BruteforceRule struct {
	failedLogins map[string][]time.Time
	alerts       map[string]time.Time
}

func NewBruteforceRule() *BruteforceRule {
	return &BruteforceRule{
		failedLogins: make(map[string][]time.Time),
		alerts:       make(map[string]time.Time),
	}
}

func (r *BruteforceRule) Check(log parser.NginxLog, now time.Time) *parser.Alert {
	// Проверяем только логины с неудачным статусом (200)
	if !log.IsLogin() || log.Status != "200" {
		return nil
	}

	username := log.Username
	r.failedLogins[username] = append(r.failedLogins[username], now)

	// Очистка старых попыток
	var recentAttempts []time.Time
	for _, t := range r.failedLogins[username] {
		if now.Sub(t) <= bruteForceWindow {
			recentAttempts = append(recentAttempts, t)
		}
	}
	r.failedLogins[username] = recentAttempts

	// Проверка условий для алерта
	if len(r.failedLogins[username]) >= bruteForceAttemptsThreshold {
		if lastAlert, exists := r.alerts[username]; !exists || now.Sub(lastAlert) > bruteForceAlertCooldown {
			r.alerts[username] = now
			delete(r.failedLogins, username)
			
			return &parser.Alert{
				Type:       "bruteforce",
				Date:       log.TimeLocal,
				RemoteAddr: log.RemoteAddr,
				Action:     "login",
				Username:   username,
				Count:      len(r.failedLogins[username]),
			}
		}
	}
	return nil
}