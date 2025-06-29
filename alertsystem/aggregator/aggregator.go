// aggregator/aggregator.go
package aggregator

import (
	"alertsystem/clickhouse"
	"alertsystem/parser"
	"alertsystem/rules"
	"context"
	"time"
	"log"
)

type Aggregator struct {
	chClient    *clickhouse.Client
	bruteRule   *rules.BruteforceRule
	sprayRule   *rules.PasswordSprayRule
	sqlInjRule  *rules.SQLInjectionRule
	lastCleanup time.Time
	ctx         context.Context
}

func New(ctx context.Context, chClient *clickhouse.Client) (*Aggregator, error) {
	return &Aggregator{
		chClient:    chClient,
		bruteRule:   rules.NewBruteforceRule(),
		sprayRule:   rules.NewPasswordSprayRule(),
		sqlInjRule:  rules.NewSQLInjectionRule(),
		lastCleanup: time.Now(),
		ctx:         ctx,
	}, nil
}

func (a *Aggregator) Close() {
	// Теперь файл не нужен, закрываем ClickHouse клиент
	if a.chClient != nil {
		a.chClient.Close()
	}
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

	authStatus := "failure"
	if log.Status == "303" {
		authStatus = "success"
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
		Type:       "alert_login",
		Date:       log.TimeLocal,
		RemoteAddr: log.RemoteAddr,
		Action:     "login",
		Username:   log.Username,
		Password:   log.Password,
		AuthStatus: authStatus,
	})
}

func (a *Aggregator) writeAlert(alert parser.Alert) {
	chAlert := clickhouse.Alert{
		Type:           alert.Type,
		Date:           alert.Date,
		RemoteAddr:     alert.RemoteAddr,
		Action:         alert.Action,
		Username:       alert.Username,
		Password:       alert.Password,
		AuthStatus:     alert.AuthStatus,
		Count:          alert.Count,
		CommonPassword: alert.CommonPassword,
	}

	if err := a.chClient.InsertAlert(a.ctx, chAlert); err != nil {
		// Логируем ошибку, но продолжаем работу
		log.Printf("Failed to insert alert into ClickHouse: %v", err)
	}
}