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
	// Обработка Nginx логов
	inputPathNginx := "../logs/nginx/access.log"
	outputPathNginx := "../logs/nginx/parsed_login.log"

	// Обработка WebService логов
	inputPathWebService := "../logs/web/auth.log"
	outputPathWebService := "../logs/web/parsed_logins.log"

	// Функция для обработки новых данных в файле
	processFile := func(inputPath, outputPath string, parseFunc func(string) (interface{}, error)) {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer watcher.Close()

		err = watcher.Add(inputPath)
		if err != nil {
			log.Fatal(err)
		}

		inputFile, err := os.Open(inputPath)
		if err != nil {
			log.Fatalf("Ошибка открытия файла: %v", err)
		}
		defer inputFile.Close()

		_, err = inputFile.Seek(0, 2)
		if err != nil {
			log.Fatalf("Ошибка перемещения указателя: %v", err)
		}

		outputFile, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Ошибка открытия файла: %v", err)
		}
		defer outputFile.Close()

		writer := bufio.NewWriter(outputFile)
		defer writer.Flush()

		reader := bufio.NewReader(inputFile)

		processNewData := func() {
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err.Error() == "EOF" {
						return
					}
					log.Printf("Ошибка чтения строки: %v", err)
					return
				}
				logEntry, err := parseFunc(line)
				if err != nil {
					log.Printf("Ошибка парсинга строки: %v", err)
					continue
				}


				switch v := logEntry.(type) {
					case parser.NginxLog:
						if !v.IsLogin {
							continue
						}
					case parser.WebServiceLog:
						if !v.IsLogin {
							continue
						}
					}

				jsonData, err := json.Marshal(logEntry)
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

		processNewData()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
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

	// Запуск обработки Nginx логов в отдельной горутине
	go processFile(inputPathNginx, outputPathNginx, func(line string) (interface{}, error) {
		return parser.ParseNginxLine(line)
	})

	// Запуск обработки WebService логов в отдельной горутине
	go processFile(inputPathWebService, outputPathWebService, func(line string) (interface{}, error) {
		return parser.ParseWebServiceLine(line)
	})

	// Ожидание завершения горутин (в реальном приложении можно использовать каналы для управления)
	select {}
}
