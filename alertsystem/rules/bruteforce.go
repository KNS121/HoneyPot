package rules

import (
	"alertsystem/parser"
	"time"
)

const (
	bruteForceAttemptsThreshold = 5
	bruteForceWindow            = 5 * time.Minute
	bruteForceAlertCooldown     = 2 * time.Minute
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

func (r *BruteforceRule) Check(log parser.WebServiceLog, now time.Time) *parser.Alert {
	if log.Status != "failure" {
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
				Type:     "bruteforce",
				Date:     log.TimeLocal,
				Action:   "login",
				Username: username,
				Count:    len(r.failedLogins[username]),
			}
		}
	}
	return nil
}