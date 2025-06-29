package rules

import (
	"alertsystem/parser"
	"time"
)

const (
	sprayAttemptsThreshold = 2
	sprayWindow            = 2 * time.Minute
	sprayAlertCooldown     = 2 * time.Minute
)

type passwordAttempt struct {
	username string
	time     time.Time
}

type PasswordSprayRule struct {
	attempts map[string][]passwordAttempt
	alerts   map[string]time.Time
}

func NewPasswordSprayRule() *PasswordSprayRule {
	return &PasswordSprayRule{
		attempts: make(map[string][]passwordAttempt),
		alerts:   make(map[string]time.Time),
	}
}

func (r *PasswordSprayRule) Check(log parser.WebServiceLog, now time.Time) *parser.Alert {
	if log.Status != "failure" {
		return nil
	}

	password := log.Password
	r.attempts[password] = append(r.attempts[password], passwordAttempt{
		username: log.Username,
		time:     now,
	})

	// Очистка старых попыток
	var recentAttempts []passwordAttempt
	for _, attempt := range r.attempts[password] {
		if now.Sub(attempt.time) <= sprayWindow {
			recentAttempts = append(recentAttempts, attempt)
		}
	}
	r.attempts[password] = recentAttempts

	// Проверка уникальных пользователей
	uniqueUsers := make(map[string]bool)
	for _, attempt := range r.attempts[password] {
		uniqueUsers[attempt.username] = true
	}

	if len(uniqueUsers) >= sprayAttemptsThreshold {
		if lastAlert, exists := r.alerts[password]; !exists || now.Sub(lastAlert) > sprayAlertCooldown {
			r.alerts[password] = now
			delete(r.attempts, password)
			
			return &parser.Alert{
				Type:           "password_spraying",
				Date:           log.TimeLocal,
				Action:         "login",
				Count:          len(uniqueUsers),
				CommonPassword: password,
			}
		}
	}
	return nil
}