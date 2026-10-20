package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CaptureLogger implements Vela's logger.Logger and keeps the guest log lines
// that the executor would forward to the host log server. Vela's default
// EXECUTOR_LOG_NETWORK_LEVEL is "info", so INF/WRN/ERR guest lines leave the
// enclave; DBG/TRC lines do not.
type CaptureLogger struct {
	mu    sync.Mutex
	lines []string
	level string
}

func NewCaptureLogger() *CaptureLogger { return &CaptureLogger{level: "info"} }

func (l *CaptureLogger) Reset() {
	l.mu.Lock()
	l.lines = nil
	l.mu.Unlock()
}

// Settle waits until no new guest line has arrived for a short quiet period.
// Vela forwards guest output through an OS pipe drained by a background
// goroutine, so a line written during a request can land just after the
// executor returns; without this, a step's log could be missed (or attributed
// to the next step).
func (l *CaptureLogger) Settle() {
	const quiet, max = 5 * time.Millisecond, 200 * time.Millisecond
	deadline := time.Now().Add(max)
	l.mu.Lock()
	n := len(l.lines)
	l.mu.Unlock()
	for time.Now().Before(deadline) {
		time.Sleep(quiet)
		l.mu.Lock()
		m := len(l.lines)
		l.mu.Unlock()
		if m == n {
			return
		}
		n = m
	}
}

// GuestLines returns guest lines at or above the network level.
func (l *CaptureLogger) GuestLines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *CaptureLogger) add(level, msg string, args ...any) {
	s := fmt.Sprintf(msg, args...)
	if !strings.Contains(s, "Wasm Guest [") {
		return
	}
	l.mu.Lock()
	l.lines = append(l.lines, level+" "+s)
	l.mu.Unlock()
}

func (l *CaptureLogger) Trace(string, ...any)              {}
func (l *CaptureLogger) Debug(string, ...any)              {}
func (l *CaptureLogger) Info(m string, a ...any)           { l.add("INF", m, a...) }
func (l *CaptureLogger) Warn(m string, a ...any)           { l.add("WRN", m, a...) }
func (l *CaptureLogger) Error(m string, a ...any)          { l.add("ERR", m, a...) }
func (l *CaptureLogger) Fatal(m string, a ...any)          { l.add("FTL", m, a...) }
func (l *CaptureLogger) Panic(m string, a ...any)          { l.add("PNC", m, a...) }
func (l *CaptureLogger) SetLevel(level string) error       { l.level = level; return nil }
func (l *CaptureLogger) GetLevel() string                  { return l.level }
func (l *CaptureLogger) Close() error                      { return nil }
