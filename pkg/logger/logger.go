package logger

import (
	"context"
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

// Level represents logging levels
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// Format represents logging formats
type Format int

const (
	TextFormat Format = iota
	JSONFormat
)

// Logger interface for structured logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	WithContext(ctx context.Context) Logger
	WithFields(fields map[string]interface{}) Logger
}

// Config for logger configuration
type Config struct {
	Level  Level
	Format Format
	Output io.Writer
}

// logrusLogger wraps logrus for our interface
type logrusLogger struct {
	logger *logrus.Logger
	entry  *logrus.Entry
}

// New creates a new logger instance
func New(config Config) Logger {
	logger := logrus.New()

	// Set level
	switch config.Level {
	case DebugLevel:
		logger.SetLevel(logrus.DebugLevel)
	case InfoLevel:
		logger.SetLevel(logrus.InfoLevel)
	case WarnLevel:
		logger.SetLevel(logrus.WarnLevel)
	case ErrorLevel:
		logger.SetLevel(logrus.ErrorLevel)
	case FatalLevel:
		logger.SetLevel(logrus.FatalLevel)
	}

	// Set format
	switch config.Format {
	case JSONFormat:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	case TextFormat:
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	}

	// Set output
	if config.Output != nil {
		logger.SetOutput(config.Output)
	} else {
		logger.SetOutput(os.Stdout)
	}

	return &logrusLogger{
		logger: logger,
		entry:  logrus.NewEntry(logger),
	}
}

func (l *logrusLogger) Debug(msg string, fields ...interface{}) {
	l.entry.WithFields(l.parseFields(fields...)).Debug(msg)
}

func (l *logrusLogger) Info(msg string, fields ...interface{}) {
	l.entry.WithFields(l.parseFields(fields...)).Info(msg)
}

func (l *logrusLogger) Warn(msg string, fields ...interface{}) {
	l.entry.WithFields(l.parseFields(fields...)).Warn(msg)
}

func (l *logrusLogger) Error(msg string, fields ...interface{}) {
	l.entry.WithFields(l.parseFields(fields...)).Error(msg)
}

func (l *logrusLogger) Fatal(msg string, fields ...interface{}) {
	l.entry.WithFields(l.parseFields(fields...)).Fatal(msg)
}

func (l *logrusLogger) WithContext(ctx context.Context) Logger {
	return &logrusLogger{
		logger: l.logger,
		entry:  l.entry.WithContext(ctx),
	}
}

func (l *logrusLogger) WithFields(fields map[string]interface{}) Logger {
	return &logrusLogger{
		logger: l.logger,
		entry:  l.entry.WithFields(fields),
	}
}

// parseFields converts variadic key-value pairs to logrus.Fields
func (l *logrusLogger) parseFields(fields ...interface{}) logrus.Fields {
	result := make(logrus.Fields)

	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				result[key] = fields[i+1]
			}
		}
	}

	return result
}
