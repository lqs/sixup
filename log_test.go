package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlainHandler(t *testing.T) {
	var buf bytes.Buffer
	h := &plainHandler{w: &buf, color: true}
	// Attributes and groups are dropped: the messages carry their own prefix.
	l := slog.New(h.WithAttrs([]slog.Attr{slog.String("k", "v")}).WithGroup("g"))
	l.Warn("[x] careful", "k", "v")
	l.Log(t.Context(), slog.LevelWarn+1, "between")
	if got := buf.String(); !strings.Contains(got, " \x1b[33mWARN \x1b[0m [x] careful\n") || strings.Contains(got, "k=v") || !strings.Contains(got, " WARN+1 between\n") {
		t.Errorf("got %q", got)
	}
	buf.Reset()
	h.color = false
	l.Info("plain")
	if got := buf.String(); !strings.HasSuffix(got, " INFO  plain\n") || strings.Contains(got, "\x1b") {
		t.Errorf("got %q", got)
	}
}

func TestIsConsole(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isConsole(f) {
		t.Error("a regular file is not a console")
	}
	f.Close()
	if isConsole(f) {
		t.Error("a closed file is not a console")
	}
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer tty.Close()
		t.Setenv("NO_COLOR", "")
		if !isConsole(tty) {
			t.Error("/dev/tty is a console")
		}
		t.Setenv("NO_COLOR", "1")
		if isConsole(tty) {
			t.Error("NO_COLOR is set")
		}
	}
}
