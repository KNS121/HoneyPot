package main

import (
	"alertsystem/aggregator"
	"alertsystem/parser"
	"alertsystem/watcher"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Инициализация агрегатора
	agg, err := aggregator.New("../logs/alerts.log")
	if err != nil {
		log.Fatalf("Failed to create aggregator: %v", err)
	}
	defer agg.Close()

	// Обработчик для nginx логов
	nginxHandler := func(line string) {
		nginxLog, err := parser.ParseNginxLine(line)
		if err != nil {
			log.Printf("Failed to parse nginx log: %v", err)
			return
		}
		agg.ProcessLog(nginxLog)
	}

	// Запуск наблюдателя
	go watcher.New("../logs/nginx/access.log", nginxHandler).Watch()

	log.Println("Alert system started. Press Ctrl+C to stop.")

	// Ожидание сигнала завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down...")
}