package clickhouse

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type Client struct {
	conn driver.Conn
}

func New(ctx context.Context) (*Client, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"localhost:9000"},
		Auth: clickhouse.Auth{
			Database: "alerts_db",
			Username: "alerts_user",
			Password: "alerts_password",
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	// Создаем таблицу, если она не существует
	if err := createTables(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &Client{conn: conn}, nil
}

func createTables(ctx context.Context, conn driver.Conn) error {
	// Таблица для хранения всех алертов
	if err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS alerts (
			type String,
			date DateTime,
			remote_addr String,
			action String,
			username Nullable(String),
			password Nullable(String),
			auth_status Nullable(String),
			count Nullable(UInt32),
			common_password Nullable(String)
		) ENGINE = MergeTree()
		ORDER BY (date, type)
	`); err != nil {
		return fmt.Errorf("failed to create alerts table: %w", err)
	}

	// Можно создать дополнительные таблицы для каждого типа алертов, если нужно
	return nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) InsertAlert(ctx context.Context, alert Alert) error {
	query := `
		INSERT INTO alerts (
			type, date, remote_addr, action, username, password, 
			auth_status, count, common_password
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	batch, err := c.conn.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch: %w", err)
	}

	if err := batch.Append(
		alert.Type,
		parseTime(alert.Date),
		alert.RemoteAddr,
		alert.Action,
		alert.Username,
		alert.Password,
		alert.AuthStatus,
		alert.Count,
		alert.CommonPassword,
	); err != nil {
		return fmt.Errorf("failed to append alert to batch: %w", err)
	}

	return batch.Send()
}

// parseTime преобразует строку времени из логов в time.Time
func parseTime(timeStr string) time.Time {
	// Формат времени должен соответствовать тому, что приходит в логах
	// Пример: "02/Jan/2006:15:04:05 -0700"
	t, err := time.Parse("02/Jan/2006:15:04:05", timeStr)
	if err != nil {
		log.Printf("Failed to parse time %q: %v", timeStr, err)
		return time.Now()
	}
	return t
}