package rules

import (
	"alertsystem/parser"
	"time"
)

const (
	sprayAttemptsThreshold = 2
	sprayWindow            = 1 * time.Minute
	sprayAlertCooldown     = 1 * time.Minute
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

func (r *PasswordSprayRule) Check(log parser.NginxLog, now time.Time) *parser.Alert {
	// Проверяем только логины с неудачным статусом (200)
	if !log.IsLogin() || log.Status != "200" {
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
				RemoteAddr:     log.RemoteAddr,
				Action:         "login",
				Count:          len(uniqueUsers),
				CommonPassword: password,
			}
		}
	}
	return nil
}