package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	file        *os.File
	mu          sync.Mutex
	logDir      string
	logName     string
	logExt      string
	currentDate string
)

type entry struct {
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	Message   string `json:"msg"`
	Error     string `json:"err,omitempty"`
}

func Init(path string) error {
	logDir = filepath.Dir(path)
	base := filepath.Base(path)
	_ = os.MkdirAll(logDir, 0755)
	ext := filepath.Ext(base)
	if ext == "" {
		ext = ".log"
	}
	name := strings.TrimSuffix(base, ext)
	logName = name
	logExt = ext
	currentDate = time.Now().Format("2006-01-02")
	full := filepath.Join(logDir, fmt.Sprintf("%s-%s%s", logName, currentDate, logExt))
	f, err := os.OpenFile(full, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	file = f
	return nil
}

func Close() {
	mu.Lock()
	defer mu.Unlock()
	if file != nil {
		_ = file.Close()
		file = nil
	}
}

func write(level string, msg string, err error) {
	mu.Lock()
	defer mu.Unlock()
	if file == nil {
		return
	}
	// 按日期切分日志文件
	today := time.Now().Format("2006-01-02")
	if today != currentDate {
		if file != nil {
			_ = file.Close()
		}
		currentDate = today
		full := filepath.Join(logDir, fmt.Sprintf("%s-%s%s", logName, currentDate, logExt))
		f, ferr := os.OpenFile(full, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if ferr == nil {
			file = f
		}
	}
	e := entry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   msg,
	}
	if err != nil {
		e.Error = err.Error()
	}
	if b, jerr := json.Marshal(e); jerr == nil {
		_, _ = file.Write(append(b, '\n'))
	}
}

func Info(msg string) {
	write("INFO", msg, nil)
}

func Error(msg string, err error) {
	write("ERROR", msg, err)
}
