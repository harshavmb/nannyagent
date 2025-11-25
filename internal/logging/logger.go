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
	syslogOnly   bool // If true, only log to syslog (daemon mode)
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

	// Try to connect to syslog (use "nannyagent" identifier for consistency)
	if writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "nannyagent"); err == nil {
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

	// Set prefix based on showEmoji flag
	var prefix string
	if l.showEmoji {
		switch level {
		case LevelDebug:
			prefix = "[DEBUG]"
		case LevelInfo:
			prefix = "[INFO]"
		case LevelWarning:
			prefix = "[WARN]"
		case LevelError:
			prefix = "[ERROR]"
		default:
			prefix = fmt.Sprintf("[%s]", level.String())
		}
	} else {
		prefix = fmt.Sprintf("[%s]", level.String())
	}

	// Log to syslog if available
	if l.syslogWriter != nil {
		switch level {
		case LevelDebug:
			_ = l.syslogWriter.Debug(msg)
		case LevelInfo:
			_ = l.syslogWriter.Info(msg)
		case LevelWarning:
			_ = l.syslogWriter.Warning(msg)
		case LevelError:
			_ = l.syslogWriter.Err(msg)
		}
	}

	// Print to stdout/stderr (unless syslog-only mode)
	if !l.syslogOnly {
		log.Printf("%s %s", prefix, msg)
	}
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

// EnableSyslogOnly sets syslog-only mode (no stdout/stderr)
func EnableSyslogOnly() {
	defaultLogger.syslogOnly = true
}

// DisableSyslogOnly disables syslog-only mode (logs to both syslog and stdout/stderr)
func DisableSyslogOnly() {
	defaultLogger.syslogOnly = false
}
