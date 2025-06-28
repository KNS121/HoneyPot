package main

import (
	"alertsystem/parser"
	"bufio"
	"encoding/json"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
)

func main() {
	inputPath := "../logs/nginx/access.log"
	outputPath := "../logs/nginx/parsed_login.log"

	// Создаем watcher для отслеживания изменений в файле
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Добавляем файл в watcher
	err = watcher.Add(inputPath)
	if err != nil {
		log.Fatal(err)
	}

	// Открываем входной файл
	inputFile, err := os.Open(inputPath)
	if err != nil {
		log.Fatalf("Ошибка открытия файла: %v", err)
	}
	defer inputFile.Close()

	// Перемещаем указатель в конец файла
	_, err = inputFile.Seek(0, 2)
	if err != nil {
		log.Fatalf("Ошибка перемещения указателя: %v", err)
	}

	// Создаем выходной файл (открываем в режиме append)
	outputFile, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Ошибка открытия файла: %v", err)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	reader := bufio.NewReader(inputFile)

	// Функция для обработки новых данных
	processNewData := func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				// Если ошибка "EOF", то выходим из функции
				if err.Error() == "EOF" {
					return
				}
				log.Printf("Ошибка чтения строки: %v", err)
				return
			}

			// Обрабатываем строку
			nginxLog, err := parser.ParseNginxLine(line)
			if err != nil {
				log.Printf("Ошибка парсинга строки: %v", err)
				continue
			}
			if !nginxLog.IsLogin {
				continue
			}

			jsonData, err := json.Marshal(nginxLog)
			if err != nil {
				log.Printf("Ошибка сериализации: %v", err)
				continue
			}

			if _, err := writer.Write(jsonData); err != nil {
				log.Printf("Ошибка записи: %v", err)
				continue
			}
			writer.WriteString("\n")
			writer.Flush()
		}
	}

	// Обрабатываем начальные данные, если они есть
	processNewData()

	// Основной цикл
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				// Файл был изменен, читаем новые данные
				processNewData()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Ошибка watcher: %v", err)
		}
	}
}