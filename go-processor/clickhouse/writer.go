package clickhouse

import (
    "context"
    "fmt"
    "log"
    "processor/config"
    "time"

    "github.com/ClickHouse/clickhouse-go/v2"
    "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type Writer struct {
    conn driver.Conn
}

func NewWriter(cfg *config.Config) (*Writer, error) {
    conn, err := clickhouse.Open(&clickhouse.Options{
        Addr: []string{cfg.ClickhouseHost},
        Auth: clickhouse.Auth{
            Database: cfg.ClickhouseDB,
            Username: cfg.ClickhouseUser,
            Password: cfg.ClickhousePass,
        },
    })
    if err != nil {
        return nil, fmt.Errorf("clickhouse connect error: %w", err)
    }

    if err := createTables(conn); err != nil {
        return nil, fmt.Errorf("create tables error: %w", err)
    }

    return &Writer{conn: conn}, nil
}

func (w *Writer) Close() {
    w.conn.Close()
}

func createTables(conn driver.Conn) error {
    ctx := context.Background()
    return conn.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS events (
            timestamp DateTime,
            ip String,
            event_type String,
            details String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, ip)
    `)
}

func (w *Writer) WriteEvent(eventType, ip, details string) error {
    ctx := context.Background()
    return w.conn.AsyncInsert(ctx, `
        INSERT INTO events (
            timestamp,
            ip,
            event_type,
            details
        ) VALUES (?, ?, ?, ?)`,
        false,
        time.Now(),
        ip,
        eventType,
        details,
    )
}