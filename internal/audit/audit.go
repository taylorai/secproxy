// Package audit writes one JSON line per decision. Lines carry enough to
// answer "what did the sandbox try to do with which secret, and did we let
// it" and nothing that could leak: no header values, no query strings, no
// bodies, no placeholders, no secret values. Events are built before any
// substitution happens so that invariant is structural, not a matter of
// care.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event is one audit line.
type Event struct {
	Time      string   `json:"ts"`
	RunID     string   `json:"run_id,omitempty"`
	Decision  string   `json:"decision"` // deny | passthrough | forward | inject | error
	Host      string   `json:"host,omitempty"`
	Method    string   `json:"method,omitempty"`
	Path      string   `json:"path,omitempty"` // path only, never the query string
	Reason    string   `json:"reason,omitempty"`
	Bindings  []string `json:"bindings,omitempty"`  // every binding that substituted a secret
	Automatic []string `json:"automatic,omitempty"` // those that did so without a placeholder (inject: always)
	Status    int      `json:"status,omitempty"`
	BytesIn   int64    `json:"bytes_in,omitempty"`
	BytesOut  int64    `json:"bytes_out,omitempty"`
	Millis    int64    `json:"ms,omitempty"`
	Listener  string   `json:"listener,omitempty"` // transparent | connect
}

// Logger serialises writes. Safe for concurrent use.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	runID string
}

// New returns a logger writing to w (normally stdout).
func New(w io.Writer, runID string) *Logger {
	return &Logger{w: w, runID: runID}
}

// Log writes e. Time and RunID are filled in if empty. Paths longer than
// 2048 bytes are truncated; a path that long is not information, it is
// exfiltration.
func (l *Logger) Log(e Event) {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.RunID == "" {
		e.RunID = l.runID
	}
	if len(e.Path) > 2048 {
		e.Path = e.Path[:2048] + "…"
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(line, '\n'))
}
