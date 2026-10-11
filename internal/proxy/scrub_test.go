package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"testing"
)

func TestScrubWriterSplitAtEveryOffset(t *testing.T) {
	const real = "real-secret-value"
	const placeholder = "placeholder"
	input := "before/" + real + "/after"
	for split := 0; split <= len(input); split++ {
		t.Run(strconv.Itoa(split), func(t *testing.T) {
			var got bytes.Buffer
			w := newScrubWriter(&got, [][2]string{{real, placeholder}})
			writeChunks(t, w, input[:split], input[split:])
			if want := "before/" + placeholder + "/after"; got.String() != want {
				t.Fatalf("split %d: got %q, want %q", split, got.String(), want)
			}
		})
	}
}

func TestScrubWriterStreamingCases(t *testing.T) {
	tests := []struct {
		name         string
		replacements [][2]string
		chunks       []string
		want         string
	}{
		{name: "adjacent", replacements: [][2]string{{"abc", "X"}}, chunks: []string{"abcabc"}, want: "XX"},
		{name: "at end", replacements: [][2]string{{"secret", "fake"}}, chunks: []string{"prefix secret"}, want: "prefix fake"},
		{name: "longest prefix wins", replacements: [][2]string{{"token", "short"}, {"token-long", "long"}}, chunks: []string{"token-long/token"}, want: "long/short"},
		{name: "empty writes", replacements: [][2]string{{"abc", "X"}}, chunks: []string{"", "a", "", "bc", ""}, want: "X"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got bytes.Buffer
			w := newScrubWriter(&got, test.replacements)
			writeChunks(t, w, test.chunks...)
			if got.String() != test.want {
				t.Fatalf("got %q, want %q", got.String(), test.want)
			}
		})
	}
}

func TestScrubHeadersUsesLongestMatchWithoutCascading(t *testing.T) {
	t.Parallel()
	headers := http.Header{"X-Echo": {"abcdef/cascade"}}
	scrubHeaders(headers, [][2]string{
		{"abc", "short"},
		{"abcdef", "abc"},
		{"cascade", "abc"},
	})
	if got, want := headers.Get("X-Echo"), "abc/abc"; got != want {
		t.Fatalf("scrubbed header = %q, want %q", got, want)
	}
}

func TestScrubWriterOneByteAtATime(t *testing.T) {
	const input = "one real-secret then another real-secret"
	var got bytes.Buffer
	w := newScrubWriter(&got, [][2]string{{"real-secret", "placeholder"}})
	for i := range len(input) {
		if _, err := w.Write([]byte{input[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if want := "one placeholder then another placeholder"; got.String() != want {
		t.Fatalf("got %q, want %q", got.String(), want)
	}
}

func TestScrubWriterFlusherPassThrough(t *testing.T) {
	underlying := &flushBuffer{}
	w := newScrubWriter(underlying, [][2]string{{"secret", "fake"}})
	f, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("writer does not expose http.Flusher")
	}
	f.Flush()
	if underlying.flushes != 1 {
		t.Fatalf("flush count = %d, want 1", underlying.flushes)
	}
}

func writeChunks(t *testing.T, w io.WriteCloser, chunks ...string) {
	t.Helper()
	for _, chunk := range chunks {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

type flushBuffer struct {
	bytes.Buffer
	flushes int
}

func (b *flushBuffer) Flush() { b.flushes++ }
