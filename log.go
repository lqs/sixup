package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// logLevel is the threshold shared by every log call; -log-level and -v set it at startup.
var logLevel = new(slog.LevelVar)

// plainHandler keeps the old one-line format: a timestamp, a level and the message. The messages
// already carry their own "[component]" prefix, so attributes are neither used nor printed.
// With color set, the level is highlighted with ANSI escapes.
type plainHandler struct {
	mu    sync.Mutex
	w     io.Writer
	color bool
}

var levelColors = map[slog.Level]string{
	slog.LevelDebug: "\x1b[90m", // gray
	slog.LevelInfo:  "\x1b[32m", // green
	slog.LevelWarn:  "\x1b[33m", // yellow
	slog.LevelError: "\x1b[31m", // red
}

func (h *plainHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= logLevel.Level()
}

func (h *plainHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	level := fmt.Sprintf("%-5s", r.Level)
	if c, ok := levelColors[r.Level]; ok && h.color {
		level = c + level + "\x1b[0m"
	}
	_, err := fmt.Fprintf(h.w, "%s %s %s\n", r.Time.Format("15:04:05.000000"), level, r.Message)
	return err
}

func (h *plainHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *plainHandler) WithGroup(string) slog.Handler      { return h }

// setupLogging installs the handler. An unknown name is a startup mistake worth reporting.
func setupLogging(level string) {
	slog.SetDefault(slog.New(&plainHandler{w: os.Stderr, color: isConsole(os.Stderr)}))
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		fatalf("-log-level must be debug / info / warn / error")
	}
	logLevel.Set(l)
}

// isConsole reports whether f is a terminal and the user has not opted out through NO_COLOR.
func isConsole(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func setDebug() { logLevel.Set(slog.LevelDebug) }

func debugEnabled() bool { return logLevel.Level() <= slog.LevelDebug }

func logf(level slog.Level, format string, args ...any) {
	if level < logLevel.Level() {
		return
	}
	slog.Default().Log(context.Background(), level, fmt.Sprintf(format, args...))
}

func debugf(format string, args ...any) { logf(slog.LevelDebug, format, args...) }
func infof(format string, args ...any)  { logf(slog.LevelInfo, format, args...) }
func warnf(format string, args ...any)  { logf(slog.LevelWarn, format, args...) }
func errorf(format string, args ...any) { logf(slog.LevelError, format, args...) }

func fatalf(format string, args ...any) {
	logf(slog.LevelError, format, args...)
	os.Exit(1)
}
