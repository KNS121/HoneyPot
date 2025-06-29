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

type Alert struct {
	Type       string `json:"type"`
	Date       string `json:"date"`
	RemoteAddr string `json:"remote_addr"`
	Action     string `json:"action"`
	Status	   string `json:"status"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type fileState struct {
	pos     int64
	path    string
	modTime time.Time
}

type LogProcessor struct {
	webLogs    map[string]parser.WebServiceLog // username -> log
	nginxLogs  map[string]parser.NginxLog      // username -> log
	alertsFile *os.File
	writer     *bufio.Writer
}

func NewLogProcessor(alertsPath string) (*LogProcessor, error) {
	alertsFile, err := os.OpenFile(alertsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &LogProcessor{
		webLogs:    make(map[string]parser.WebServiceLog),
		nginxLogs:  make(map[string]parser.NginxLog),
		alertsFile: alertsFile,
		writer:     bufio.NewWriter(alertsFile),
	}, nil
}

func (lp *LogProcessor) Close() {
	lp.writer.Flush()
	lp.alertsFile.Close()
}

func (lp *LogProcessor) ProcessWebLog(log parser.WebServiceLog) {
	// Сохраняем веб-лог для последующего сопоставления
	lp.webLogs[log.Username] = log
	lp.tryMatchAlerts(log.Username)
}

func (lp *LogProcessor) ProcessNginxLog(log parser.NginxLog) {
	// Сохраняем nginx-лог для последующего сопоставления
	lp.nginxLogs[log.Username] = log
	lp.tryMatchAlerts(log.Username)
}

func (lp *LogProcessor) tryMatchAlerts(username string) {
	webLog, webExists := lp.webLogs[username]
	nginxLog, nginxExists := lp.nginxLogs[username]

	if webExists && nginxExists {
		// Проверяем временной интервал (например, ±5 секунд)
		webTime, err1 := time.Parse("02/Jan/2006:15:04:05", webLog.TimeLocal)
		nginxTime, err2 := time.Parse("02/Jan/2006:15:04:05", nginxLog.TimeLocal)

		if err1 == nil && err2 == nil {
			timeDiff := webTime.Sub(nginxTime).Abs()

			if timeDiff <= time.Second {
				// Создаем алерт
				alert := Alert{
					Type:       "alert",
					Date:       webLog.TimeLocal,
					RemoteAddr: nginxLog.RemoteAddr,
					Action:     "login",
					Status: 	webLog.Status,
					Username:   username,
					Password:   webLog.Password,
				}

				// Записываем алерт в файл
				jsonData, err := json.Marshal(alert)
				if err != nil {
					log.Printf("Ошибка сериализации алерта: %v", err)
					return
				}

				if _, err := lp.writer.Write(jsonData); err != nil {
					log.Printf("Ошибка записи алерта: %v", err)
					return
				}
				lp.writer.WriteString("\n")
				lp.writer.Flush()

				fmt.Printf("[ALERT] Обнаружена попытка входа: %s с IP %s\n", username, nginxLog.RemoteAddr)

				// Удаляем обработанные логи
				delete(lp.webLogs, username)
				delete(lp.nginxLogs, username)
			}
		}
	}
}

func main() {
	// Пути к файлам логов
	inputPathNginx := "../logs/nginx/access.log"
	inputPathWebService := "../logs/web/auth.log"
	alertsPath := "../logs/alerts/alerts.log"

	// Инициализируем процессор логов
	logProcessor, err := NewLogProcessor(alertsPath)
	if err != nil {
		log.Fatalf("Ошибка инициализации процессора логов: %v", err)
	}
	defer logProcessor.Close()

	// Функция для обработки файлов
	processFile := func(inputPath string, parseFunc func(string) (interface{}, error), logType string) {
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

		processNewData := func() {
			fileInfo, err := os.Stat(inputPath)
			if err != nil {
				log.Printf("Ошибка получения информации о файле: %v", err)
				return
			}

			if !fileInfo.ModTime().After(state.modTime) {
				return
			}

			if fileInfo.Size() < state.pos {
				state.pos = 0
			}

			inputFile, err := os.Open(inputPath)
			if err != nil {
				log.Printf("Ошибка открытия входного файла: %v", err)
				return
			}
			defer inputFile.Close()

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

				switch v := logEntry.(type) {
				case parser.NginxLog:
					if v.IsLogin && v.Username != "" {
						logProcessor.ProcessNginxLog(v)
						fmt.Printf("[NGINX] Обнаружена попытка входа: %s @ %s\n", v.Username, v.TimeLocal)
					}
				case parser.WebServiceLog:
					if v.IsLogin && v.Username != "" {
						logProcessor.ProcessWebLog(v)
						fmt.Printf("[WEB] Обнаружена попытка входа: %s (статус: %s)\n", v.Username, v.Status)
					}
				}

				linesProcessed++
			}

			newPos, err := inputFile.Seek(0, 1)
			if err == nil {
				state.pos = newPos
				state.modTime = fileInfo.ModTime()
			}

			if linesProcessed > 0 {
				log.Printf("Обработано %d новых записей из %s", linesProcessed, inputPath)
			}
		}

		processNewData()

		ticker := time.NewTicker(time.Second)
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
					state.pos = 0
					processNewData()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Ошибка watcher: %v", err)
			case <-ticker.C:
				processNewData()
			}
		}
	}

	// Запуск обработки логов
	go processFile(inputPathNginx, func(line string) (interface{}, error) {
		return parser.ParseNginxLine(line)
	}, "nginx logs")

	go processFile(inputPathWebService, func(line string) (interface{}, error) {
		return parser.ParseWebServiceLine(line)
	}, "web service logs")

	log.Println("Сервис мониторинга логов запущен и работает...")
	fmt.Println("==============================================")
	fmt.Println("Ожидание событий входа в систему...")
	fmt.Println("==============================================")

	select {}
}