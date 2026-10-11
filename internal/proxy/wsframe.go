package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// Server-to-client WebSocket frames are relayed one frame at a time so the
// scrubber can work on a whole payload and the frame header stays truthful.
// Byte-stream scrubbing is wrong here for two reasons: a replacement of a
// different length would make the length field lie, and the scrubber's
// carry buffer would hold back the tail of a complete frame while waiting
// to see whether it starts a secret, stalling the client.
//
// Frame layout (RFC 6455 section 5.2): two header bytes (FIN/opcode,
// MASK/length), an optional 2- or 8-byte extended length, an optional 4-byte
// mask (never set by a compliant server), then the payload.
//
// Limits of this approach, stated rather than hidden: a value split across
// two fragments of one message is not caught, and payloads larger than
// maxScrubbedFrame are scrubbed chunk by chunk, so a value straddling a
// chunk boundary inside a huge frame is not caught either.

const maxScrubbedFrame = 16 << 20

// relayServerFrames copies frames from src to dst, rewriting each payload
// through the replacements. Replacements must be length-preserving. Returns
// the number of bytes written to dst.
func relayServerFrames(dst io.Writer, src io.Reader, replacements [][2]string) (int64, error) {
	var written int64
	var header [14]byte
	chunk := make([]byte, 32<<10)
	replacer := newLiteralReplacer(replacements)
	for {
		if _, err := io.ReadFull(src, header[:2]); err != nil {
			return written, err
		}
		headerLen := 2
		length := uint64(header[1] & 0x7f)
		switch length {
		case 126:
			if _, err := io.ReadFull(src, header[2:4]); err != nil {
				return written, err
			}
			length = uint64(binary.BigEndian.Uint16(header[2:4]))
			headerLen = 4
		case 127:
			if _, err := io.ReadFull(src, header[2:10]); err != nil {
				return written, err
			}
			length = binary.BigEndian.Uint64(header[2:10])
			headerLen = 10
		}
		if header[1]&0x80 != 0 {
			// A server must not mask. Treat it as a protocol error rather
			// than try to unmask and re-mask.
			return written, errors.New("websocket: masked frame from server")
		}
		n, err := dst.Write(header[:headerLen])
		written += int64(n)
		if err != nil {
			return written, err
		}

		if length <= maxScrubbedFrame {
			payload := make([]byte, length)
			if _, err := io.ReadFull(src, payload); err != nil {
				return written, err
			}
			payload = scrubBytes(payload, replacer)
			n, err := dst.Write(payload)
			written += int64(n)
			if err != nil {
				return written, err
			}
			continue
		}
		remaining := length
		for remaining > 0 {
			want := uint64(len(chunk))
			if remaining < want {
				want = remaining
			}
			if _, err := io.ReadFull(src, chunk[:want]); err != nil {
				return written, err
			}
			n, err := dst.Write(scrubBytes(chunk[:want], replacer))
			written += int64(n)
			if err != nil {
				return written, err
			}
			remaining -= want
		}
	}
}

// scrubBytes applies length-preserving replacements in one pass.
func scrubBytes(p []byte, replacer *strings.Replacer) []byte {
	if replacer == nil {
		return p
	}
	return []byte(replacer.Replace(string(p)))
}
