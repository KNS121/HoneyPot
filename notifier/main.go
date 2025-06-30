package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type Alert struct {
	Type           string
	Date           time.Time
	RemoteAddr     string
	Action         string
	Username       string
	Password       string
	AuthStatus     string
	Count          uint32
	CommonPassword string
}

func main() {
	// Получаем переменные окружения
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN is required")
	}

	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if chatID == "" {
		log.Fatal("TELEGRAM_CHAT_ID is required")
	}

	clickhouseDSN := os.Getenv("CLICKHOUSE_DSN")
	if clickhouseDSN == "" {
		clickhouseDSN = "clickhouse://alerts_user:alerts_password@clickhouse:9000/alerts_db"
	}

	// Инициализация Telegram бота
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatalf("Failed to create Telegram bot: %v", err)
	}
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// Инициализация ClickHouse клиента
	chConn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"clickhouse:9000"},
		Auth: clickhouse.Auth{
			Database: "alerts_db",
			Username: "alerts_user",
			Password: "alerts_password",
		},
	})
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}
	defer chConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Запускаем обработчик алертов
	go watchAlerts(ctx, chConn, bot, chatID)

	log.Println("Notifier service started. Press Ctrl+C to stop.")

	// Ожидание сигнала завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down...")
}

func watchAlerts(ctx context.Context, conn driver.Conn, bot *tgbotapi.BotAPI, chatID string) {
	// Сначала получаем максимальную дату, чтобы не обрабатывать старые алерты
	var lastAlertTime time.Time
	if err := conn.QueryRow(ctx, "SELECT MAX(date) FROM alerts").Scan(&lastAlertTime); err != nil {
		log.Printf("Failed to get last alert time: %v", err)
		lastAlertTime = time.Now().Add(-1 * time.Hour)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Получаем новые алерты
			rows, err := conn.Query(ctx, `
				SELECT type, date, remote_addr, action, username, password, auth_status, count, common_password
				FROM alerts
				WHERE date > ?
				ORDER BY date DESC
				LIMIT 100
			`, lastAlertTime)
			if err != nil {
				log.Printf("Failed to query alerts: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			var alerts []Alert
			for rows.Next() {
				var alert Alert
				if err := rows.Scan(
					&alert.Type,
					&alert.Date,
					&alert.RemoteAddr,
					&alert.Action,
					&alert.Username,
					&alert.Password,
					&alert.AuthStatus,
					&alert.Count,
					&alert.CommonPassword,
				); err != nil {
					log.Printf("Failed to scan alert: %v", err)
					continue
				}
				alerts = append(alerts, alert)
			}
			rows.Close()

			// Обрабатываем новые алерты
			for _, alert := range alerts {
				if alert.Date.After(lastAlertTime) {
					lastAlertTime = alert.Date
				}

				msg := formatAlertMessage(alert)
				if _, err := bot.Send(tgbotapi.NewMessageToChannel(chatID, msg)); err != nil {
					log.Printf("Failed to send Telegram message: %v", err)
				}
			}

			time.Sleep(5 * time.Second)
		}
	}
}

func formatAlertMessage(alert Alert) string {
	switch alert.Type {
	case "sql_injection":
		return fmt.Sprintf("🚨 SQL Injection Attempt\n\n"+
			"⏰ Time: %s\n"+
			"🌐 IP: %s\n"+
			"👤 Username: %s\n"+
			"🔒 Status: %s",
			alert.Date.Format("2006-01-02 15:04:05"),
			alert.RemoteAddr,
			alert.Username,
			alert.AuthStatus)

	case "bruteforce":
		return fmt.Sprintf("🚨 Bruteforce Attempt\n\n"+
			"⏰ Time: %s\n"+
			"🌐 IP: %s\n"+
			"👤 Username: %s\n",
			alert.Date.Format("2006-01-02 15:04:05"),
			alert.RemoteAddr,
			alert.Username)

	case "password_spraying":
		return fmt.Sprintf("🚨 Password Spraying Attempt\n\n"+
			"⏰ Time: %s\n"+
			"🌐 IP: %s\n"+
			"🔑 Common Password: %s\n"+
			"👥 Affected Users: %d",
			alert.Date.Format("2006-01-02 15:04:05"),
			alert.RemoteAddr,
			alert.CommonPassword,
			alert.Count)

	default:
		return fmt.Sprintf("⚠️ New Alert\n\n"+
			"⏰ Time: %s\n"+
			"🌐 IP: %s\n"+
			"👤 Username: %s\n"+
			"🔒 Status: %s",
			alert.Date.Format("2006-01-02 15:04:05"),
			alert.RemoteAddr,
			alert.Username,
			alert.AuthStatus)
	}
}