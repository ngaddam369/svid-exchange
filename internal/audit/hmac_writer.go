package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// hmacWriter wraps an io.Writer and injects tamper-evidence fields into every
// JSON log line that zerolog produces. Each Write call is expected to be one
// complete JSON object followed by a newline (zerolog guarantees this).
//
// Three fields are appended before the closing '}':
//
//   - "seq"       — monotonically increasing counter; gaps indicate deleted lines.
//   - "prev_hmac" — HMAC of the previous entry (all-zeros for the first entry);
//     chaining means any deletion or reordering breaks verification.
//   - "hmac"      — HMAC-SHA256(key, uint64_be(seq) || prev_hmac || payload)
//     where payload is the original line bytes without the trailing
//     newline. Because the HMAC covers the payload before injection,
//     a verifier can reconstruct it by stripping the three injected
//     fields and re-adding the closing '}'.
//
// When key is nil or empty, Write passes through to the underlying writer
// unchanged — no fields are injected and no performance cost is incurred.
type hmacWriter struct {
	w       io.Writer
	key     []byte
	mu      sync.Mutex
	seq     uint64
	prevMAC [32]byte // zero-value is the correct initial state
}

func newHMACWriter(w io.Writer, key []byte) *hmacWriter {
	return &hmacWriter{w: w, key: key}
}

// Write implements io.Writer. p must be a complete JSON line ending in '\n'.
func (h *hmacWriter) Write(p []byte) (int, error) {
	if len(h.key) == 0 {
		return h.w.Write(p)
	}

	// Locate the closing '}' (last byte before the newline).
	// If the line is not a JSON object, pass it through unchanged.
	n := len(p)
	end := n
	if end > 0 && p[end-1] == '\n' {
		end--
	}
	if end == 0 || p[end-1] != '}' {
		return h.w.Write(p)
	}

	payload := p[:end] // original bytes to sign (without newline)

	// Build output before acquiring the lock: uses only local variables.
	body := payload[:len(payload)-1]

	h.mu.Lock()
	h.seq++
	seq := h.seq
	prevMAC := h.prevMAC

	mac := hmac.New(sha256.New, h.key)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	mac.Write(seqBuf[:])
	mac.Write(prevMAC[:])
	mac.Write(payload)
	sum := mac.Sum(nil)
	copy(h.prevMAC[:], sum)

	// Build the final line while holding the lock and write before releasing.
	// Holding the lock through the write ensures the on-disk order matches the
	// sequence numbers: if two goroutines race here, the one that incremented
	// seq first also writes first, keeping seq/prev_hmac consistent for an
	// offline verifier.
	suffix := fmt.Sprintf(`,"seq":%d,"prev_hmac":"%x","hmac":"%x"}`, seq, prevMAC, sum)
	out := make([]byte, 0, len(body)+len(suffix)+1)
	out = append(out, body...)
	out = append(out, suffix...)
	out = append(out, '\n')

	_, err := h.w.Write(out)
	h.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return n, nil // report original length to the caller
}
