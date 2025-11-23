package logging

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strings"
)

// LogLevel defines the logging level
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarning
	LevelError
)

func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarning:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Logger provides structured logging with configurable levels
type Logger struct {
	syslogWriter *syslog.Writer
	level        LogLevel
	showEmoji    bool
}

var defaultLogger *Logger

func init() {
	defaultLogger = NewLogger()
}

// NewLogger creates a new logger with default configuration
func NewLogger() *Logger {
	return NewLoggerWithLevel(getLogLevelFromEnv())
}

// NewLoggerWithLevel creates a logger with specified level
func NewLoggerWithLevel(level LogLevel) *Logger {
	l := &Logger{
		level:     level,
		showEmoji: os.Getenv("LOG_NO_EMOJI") != "true",
	}

	// Try to connect to syslog
	if writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "nannyagentv2"); err == nil {
		l.syslogWriter = writer
	}

	return l
}

// getLogLevelFromEnv parses log level from environment variable
func getLogLevelFromEnv() LogLevel {
	level := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch level {
	case "DEBUG":
		return LevelDebug
	case "INFO", "":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarning
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// logMessage handles the actual logging
func (l *Logger) logMessage(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	prefix := fmt.Sprintf("[%s]", level.String())

	// Add emoji prefix if enabled
	if l.showEmoji {
		switch level {
		case LevelDebug:
			prefix = "🔍 " + prefix
		case LevelInfo:
			prefix = "ℹ️  " + prefix
		case LevelWarning:
			prefix = "⚠️  " + prefix
		case LevelError:
			prefix = "❌ " + prefix
		}
	}

	// Log to syslog if available
	if l.syslogWriter != nil {
		switch level {
		case LevelDebug:
			l.syslogWriter.Debug(msg)
		case LevelInfo:
			l.syslogWriter.Info(msg)
		case LevelWarning:
			l.syslogWriter.Warning(msg)
		case LevelError:
			l.syslogWriter.Err(msg)
		}
	}

	// Print to stdout/stderr
	log.Printf("%s %s", prefix, msg)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.logMessage(LevelDebug, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.logMessage(LevelInfo, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.logMessage(LevelWarning, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.logMessage(LevelError, format, args...)
}

// SetLevel changes the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// GetLevel returns current logging level
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

func (l *Logger) Close() {
	if l.syslogWriter != nil {
		l.syslogWriter.Close()
	}
}

// Global logging functions
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

func Warning(format string, args ...interface{}) {
	defaultLogger.Warning(format, args...)
}

func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// SetLevel sets the global logger level
func SetLevel(level LogLevel) {
	defaultLogger.SetLevel(level)
}

// GetLevel gets the global logger level
func GetLevel() LogLevel {
	return defaultLogger.GetLevel()
}
