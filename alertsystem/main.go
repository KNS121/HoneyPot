// main.go
package main

import (
	"alertsystem/parser"
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func main() {
	inputPath := "../logs/nginx/access.log"
	outputPath := "../logs/nginx/parsed_login.log"

	// Открываем входной файл
	inputFile, err := os.Open(inputPath)
	if err != nil {
		log.Fatalf("Ошибка открытия файла: %v", err)
	}
	defer inputFile.Close()

	// Создаем выходной файл
	outputFile, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("Ошибка создания файла: %v", err)
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := scanner.Text()
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
		}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Ошибка чтения файла: %v", err)
	}

	fmt.Printf("Успешно обработано. Результат сохранен в %s\n", outputPath)
}