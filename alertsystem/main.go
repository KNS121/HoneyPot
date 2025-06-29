package main

import (
	"alertsystem/parser"
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

type fileState struct {
	pos     int64
	path    string
	modTime time.Time
}

func main() {
	// Обработка Nginx логов
	inputPathNginx := "../logs/nginx/access.log"
	outputPathNginx := "../logs/nginx/parsed_login.log"

	// Обработка WebService логов
	inputPathWebService := "../logs/web/auth.log"
	outputPathWebService := "../logs/web/parsed_logins.log"

	// Функция для обработки новых данных в файле
	processFile := func(inputPath, outputPath string, parseFunc func(string) (interface{}, error), logType string) {
		// Состояние файла
		state := &fileState{path: inputPath}
		
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer watcher.Close()

		err = watcher.Add(inputPath)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Начато отслеживание файла %s (%s)", inputPath, logType)

		// Открываем выходной файл для записи
		outputFile, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Ошибка открытия выходного файла: %v", err)
		}
		defer outputFile.Close()

		writer := bufio.NewWriter(outputFile)
		defer writer.Flush()

		// Функция для обработки новых данных
		processNewData := func() {
			// Проверяем, изменился ли файл
			fileInfo, err := os.Stat(inputPath)
			if err != nil {
				log.Printf("Ошибка получения информации о файле: %v", err)
				return
			}

			// Если файл не изменился, пропускаем обработку
			if !fileInfo.ModTime().After(state.modTime) {
				return
			}

			// Если файл уменьшился (например, при ротации), начинаем с начала
			if fileInfo.Size() < state.pos {
				state.pos = 0
			}

			inputFile, err := os.Open(inputPath)
			if err != nil {
				log.Printf("Ошибка открытия входного файла: %v", err)
				return
			}
			defer inputFile.Close()

			// Перемещаемся на последнюю известную позицию
			_, err = inputFile.Seek(state.pos, 0)
			if err != nil {
				log.Printf("Ошибка перемещения указателя: %v", err)
				return
			}

			reader := bufio.NewReader(inputFile)
			var linesProcessed int

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}

				logEntry, err := parseFunc(line)
				if err != nil {
					log.Printf("Ошибка парсинга строки: %v", err)
					continue
				}

				// Проверяем, является ли запись логином
				var isLogin bool
				switch v := logEntry.(type) {
				case parser.NginxLog:
					isLogin = v.IsLogin
					if !isLogin {
						continue
					}
					fmt.Printf("[NGINX] Обнаружена попытка входа: %s @ %s\n", v.Username, v.TimeLocal)
				case parser.WebServiceLog:
					isLogin = v.IsLogin
					if !isLogin {
						continue
					}
					fmt.Printf("[WEB] Обнаружена попытка входа: %s (статус: %s)\n", v.Username, v.Status)
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
				linesProcessed++
			}

			// Обновляем состояние файла
			newPos, err := inputFile.Seek(0, 1) // Получаем текущую позицию
			if err == nil {
				state.pos = newPos
				state.modTime = fileInfo.ModTime()
			}

			if linesProcessed > 0 {
				log.Printf("Обработано %d новых записей из %s", linesProcessed, inputPath)
			}
		}

		// Обрабатываем существующие данные при старте
		processNewData()

		// Таймер для периодической проверки файла
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Printf("Обнаружено изменение файла: %s", event.Name)
					processNewData()
				} else if event.Op&fsnotify.Create == fsnotify.Create {
					log.Printf("Файл создан/пересоздан: %s", event.Name)
					// При пересоздании файла начинаем с начала
					state.pos = 0
					processNewData()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Ошибка watcher: %v", err)
			case <-ticker.C:
				// Периодическая проверка
				processNewData()
			}
		}
	}

	// Запуск обработки Nginx логов
	go processFile(inputPathNginx, outputPathNginx, func(line string) (interface{}, error) {
		return parser.ParseNginxLine(line)
	}, "nginx logs")

	// Запуск обработки WebService логов
	go processFile(inputPathWebService, outputPathWebService, func(line string) (interface{}, error) {
		return parser.ParseWebServiceLine(line)
	}, "web service logs")

	// Информационное сообщение при старте
	log.Println("Сервис мониторинга логов запущен и работает...")
	fmt.Println("==============================================")
	fmt.Println("Ожидание событий входа в систему...")
	fmt.Println("==============================================")

	// Бесконечный цикл для работы приложения
	select {}
}