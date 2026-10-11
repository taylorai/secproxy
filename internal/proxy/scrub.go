package proxy

import (
	"bytes"
	"io"
	"net/http"
	"sort"
	"strings"
)

// Response scrubbing. An upstream that echoes a credential (an error message
// that quotes the Authorization header, a redirect that carries a token in
// Location, a debug endpoint) would otherwise hand the sandbox the real
// value. We replace every occurrence of each real value with its
// placeholder, in headers and in the streamed body, so the sandbox only
// ever sees what it already had.
//
// This is best-effort by nature: it catches literal occurrences in plaintext
// responses (we strip Accept-Encoding, and decompress gzip if the server
// sends it anyway; other encodings are refused). It cannot catch a value
// that the upstream transforms before echoing. The README says so.

// scrubHeaders replaces occurrences in every header value in place.
func scrubHeaders(h http.Header, replacements [][2]string) {
	replacer := newLiteralReplacer(replacements)
	if replacer == nil {
		return
	}
	for k, vs := range h {
		for i, v := range vs {
			vs[i] = replacer.Replace(v)
		}
		h[k] = vs
	}
}

// orderedReplacements returns a copy ordered longest-real-value first. This
// makes overlapping credentials deterministic: replacing "abc" must not hide
// the start of "abcdef" before the longer value gets a chance to match.
func orderedReplacements(in [][2]string) [][2]string {
	out := make([][2]string, 0, len(in))
	for _, replacement := range in {
		if replacement[0] != "" {
			out = append(out, replacement)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i][0]) > len(out[j][0]) })
	return out
}

// newLiteralReplacer performs one left-to-right replacement pass. Replacement
// text is not searched again, avoiding cascades when a placeholder happens to
// contain another secret value.
func newLiteralReplacer(replacements [][2]string) *strings.Replacer {
	ordered := orderedReplacements(replacements)
	if len(ordered) == 0 {
		return nil
	}
	pairs := make([]string, 0, 2*len(ordered))
	for _, replacement := range ordered {
		pairs = append(pairs, replacement[0], replacement[1])
	}
	return strings.NewReplacer(pairs...)
}

// newScrubWriter wraps w so that writes are scanned for any of the real
// values and rewritten before reaching the client. It must handle a value
// split across two Write calls, and must not hold back more bytes than the
// longest value minus one, so streaming latency stays negligible.
//
// The streaming multi-pattern replacer:
//   - keep a carry buffer of up to (maxLen-1) trailing bytes that could be
//     the prefix of a match
//   - on each Write: scan carry+chunk, emit everything that cannot be part
//     of a match, keep the rest
//   - Flush() emits nothing extra but forwards the flush; Close() emits the
//     carry
//   - with a handful of patterns a simple bytes.Index loop is fine; do not
//     add a dependency for Aho-Corasick
//   - the wrapper must expose http.Flusher so SSE keeps working
func newScrubWriter(w io.Writer, replacements [][2]string) io.WriteCloser {
	patterns := make([][2][]byte, 0, len(replacements))
	for _, replacement := range orderedReplacements(replacements) {
		patterns = append(patterns, [2][]byte{[]byte(replacement[0]), []byte(replacement[1])})
	}
	if len(patterns) == 0 {
		if f, ok := w.(http.Flusher); ok {
			return flushingNopCloser{Writer: w, flusher: f}
		}
		return nopCloser{w}
	}
	sw := &scrubWriter{w: w, patterns: patterns, maxLen: len(patterns[0][0])}
	if f, ok := w.(http.Flusher); ok {
		return &flushingScrubWriter{scrubWriter: sw, flusher: f}
	}
	return sw
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

type flushingNopCloser struct {
	io.Writer
	flusher http.Flusher
}

func (flushingNopCloser) Close() error { return nil }
func (w flushingNopCloser) Flush()     { w.flusher.Flush() }

type scrubWriter struct {
	w        io.Writer
	patterns [][2][]byte
	maxLen   int
	carry    []byte
	closed   bool
}

func (w *scrubWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	data := make([]byte, 0, len(w.carry)+len(p))
	data = append(data, w.carry...)
	data = append(data, p...)
	cutoff := w.carryStart(data)
	emit, keep := w.replaceBefore(data, cutoff)
	if len(emit) > 0 {
		if _, err := w.w.Write(emit); err != nil {
			return 0, err
		}
	}
	w.carry = append(w.carry[:0], keep...)
	return len(p), nil
}

func (w *scrubWriter) carryStart(data []byte) int {
	start := len(data)
	maxSuffix := w.maxLen - 1
	if maxSuffix > len(data) {
		maxSuffix = len(data)
	}
	for length := 1; length <= maxSuffix; length++ {
		suffix := data[len(data)-length:]
		for _, pattern := range w.patterns {
			if length < len(pattern[0]) && bytes.Equal(suffix, pattern[0][:length]) {
				start = len(data) - length
				break
			}
		}
	}
	return start
}

func (w *scrubWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	emit, _ := w.replaceBefore(w.carry, len(w.carry))
	w.carry = nil
	if len(emit) == 0 {
		return nil
	}
	_, err := w.w.Write(emit)
	return err
}

// replaceBefore consumes matches whose starting byte is before cutoff. The
// unconsumed suffix remains buffered because it may complete on the next call.
func (w *scrubWriter) replaceBefore(data []byte, cutoff int) ([]byte, []byte) {
	var out bytes.Buffer
	pos := 0
	for pos < cutoff {
		matched := false
		for _, pattern := range w.patterns {
			if bytes.HasPrefix(data[pos:], pattern[0]) {
				_, _ = out.Write(pattern[1])
				pos += len(pattern[0])
				matched = true
				break
			}
		}
		if !matched {
			_ = out.WriteByte(data[pos])
			pos++
		}
	}
	return out.Bytes(), data[pos:]
}

type flushingScrubWriter struct {
	*scrubWriter
	flusher http.Flusher
}

func (w *flushingScrubWriter) Flush() { w.flusher.Flush() }
