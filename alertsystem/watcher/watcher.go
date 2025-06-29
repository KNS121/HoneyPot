package watcher

import (
	"bufio"
	"log"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

type FileWatcher struct {
	Path     string
	OnChange func(string)
	state    struct {
		pos     int64
		modTime time.Time
	}
}

func New(path string, onChange func(string)) *FileWatcher {
	return &FileWatcher{
		Path:     path,
		OnChange: onChange,
	}
}

func (fw *FileWatcher) Watch() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(fw.Path)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Watching file: %s", fw.Path)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				fw.processChanges()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		case <-ticker.C:
			fw.processChanges()
		}
	}
}

func (fw *FileWatcher) processChanges() {
	fileInfo, err := os.Stat(fw.Path)
	if err != nil {
		log.Printf("File stat error: %v", err)
		return
	}

	if !fileInfo.ModTime().After(fw.state.modTime) {
		return
	}

	if fileInfo.Size() < fw.state.pos {
		fw.state.pos = 0
	}

	file, err := os.Open(fw.Path)
	if err != nil {
		log.Printf("File open error: %v", err)
		return
	}
	defer file.Close()

	_, err = file.Seek(fw.state.pos, 0)
	if err != nil {
		log.Printf("Seek error: %v", err)
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fw.OnChange(scanner.Text())
	}

	newPos, _ := file.Seek(0, 1)
	fw.state.pos = newPos
	fw.state.modTime = fileInfo.ModTime()
}