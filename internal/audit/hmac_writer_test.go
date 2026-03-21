package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// testKey is a fixed 32-byte key used across all HMAC tests.
var testKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}()

var testEvent = ExchangeEvent{
	Subject:         "spiffe://cluster.local/ns/default/sa/order",
	Target:          "spiffe://cluster.local/ns/default/sa/payment",
	ScopesRequested: []string{"payments:charge"},
	ScopesGranted:   []string{"payments:charge"},
	Granted:         true,
	TTL:             60,
	TokenID:         "test-jti-001",
}

// plainLine returns the raw JSON line that New() would write for testEvent,
// without a trailing newline. Used as the expected signing payload.
func plainLine(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	New(&buf).LogExchange(testEvent)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func parseJSON(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("invalid JSON: %v\nline: %s", err, line)
	}
	return m
}

func TestHMACWriterNoKey(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).LogExchange(testEvent)
	plain := buf.Bytes()

	buf.Reset()
	NewWithHMAC(&buf, nil).LogExchange(testEvent)
	signed := buf.Bytes()

	if !bytes.Equal(plain, signed) {
		t.Errorf("no-key output differs from plain output\nplain:  %s\nsigned: %s", plain, signed)
	}
}

func TestHMACWriterFieldsPresent(t *testing.T) {
	var buf bytes.Buffer
	NewWithHMAC(&buf, testKey).LogExchange(testEvent)

	entry := parseJSON(t, buf.Bytes())

	for _, field := range []string{"seq", "prev_hmac", "hmac"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("expected field %q to be present", field)
		}
	}
	if seq, ok := entry["seq"].(float64); !ok || seq != 1 {
		t.Errorf("seq = %v, want 1", entry["seq"])
	}
	if ph, ok := entry["prev_hmac"].(string); !ok || ph != fmt.Sprintf("%x", make([]byte, 32)) {
		t.Errorf("prev_hmac = %v, want all-zeros", entry["prev_hmac"])
	}
}

func TestHMACWriterCorrectMAC(t *testing.T) {
	payload := plainLine(t)

	var buf bytes.Buffer
	NewWithHMAC(&buf, testKey).LogExchange(testEvent)
	entry := parseJSON(t, buf.Bytes())

	// Recompute expected HMAC: HMAC(key, uint64_be(1) || zeroes(32) || payload)
	mac := hmac.New(sha256.New, testKey)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], 1)
	mac.Write(seqBuf[:])
	mac.Write(make([]byte, 32)) // prev_hmac is all zeros for first entry
	mac.Write(payload)
	want := hex.EncodeToString(mac.Sum(nil))

	got, _ := entry["hmac"].(string)
	if got != want {
		t.Errorf("hmac mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestHMACWriterChaining(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithHMAC(&buf, testKey)
	l.LogExchange(testEvent)
	l.LogExchange(testEvent)

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	e1 := parseJSON(t, lines[0])
	e2 := parseJSON(t, lines[1])

	// Sequence numbers must be 1 and 2.
	if e1["seq"].(float64) != 1 {
		t.Errorf("entry 1 seq = %v, want 1", e1["seq"])
	}
	if e2["seq"].(float64) != 2 {
		t.Errorf("entry 2 seq = %v, want 2", e2["seq"])
	}

	// prev_hmac of entry 2 must equal hmac of entry 1.
	if e2["prev_hmac"] != e1["hmac"] {
		t.Errorf("chaining broken: entry2.prev_hmac=%v != entry1.hmac=%v", e2["prev_hmac"], e1["hmac"])
	}
}

func TestHMACWriterTamperDetection(t *testing.T) {
	var buf bytes.Buffer
	NewWithHMAC(&buf, testKey).LogExchange(testEvent)

	// Tamper: change the subject SPIFFE ID (valid JSON, different content).
	line := buf.Bytes()
	tampered := bytes.Replace(
		line,
		[]byte(`"spiffe://cluster.local/ns/default/sa/order"`),
		[]byte(`"spiffe://cluster.local/ns/default/sa/evil1"`),
		1,
	)
	if bytes.Equal(tampered, line) {
		t.Skip("replacement did not apply — test needs updating")
	}

	// Parse and recompute HMAC over the tampered payload.
	entry := parseJSON(t, tampered)
	storedMAC, _ := entry["hmac"].(string)

	// We expect the stored HMAC to NOT match a MAC computed over the tampered payload.
	// Strip the three injected fields to recover the tampered payload.
	prevMACHex, _ := entry["prev_hmac"].(string)
	seqF, _ := entry["seq"].(float64)
	seq := uint64(seqF)
	suffix := fmt.Sprintf(`,"seq":%d,"prev_hmac":"%s","hmac":"%s"}`, seq, prevMACHex, storedMAC)
	body := bytes.TrimRight(tampered, "\n")
	body = bytes.TrimSuffix(body, []byte(suffix))
	tamperedPayload := append(body, '}')

	prevMACBytes, _ := hex.DecodeString(prevMACHex)
	mac := hmac.New(sha256.New, testKey)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	mac.Write(seqBuf[:])
	mac.Write(prevMACBytes)
	mac.Write(tamperedPayload)
	recomputed := hex.EncodeToString(mac.Sum(nil))

	if recomputed == storedMAC {
		t.Error("tampered line passed HMAC verification — this should not happen")
	}
}

func TestHMACWriterSeqMonotonic(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithHMAC(&buf, testKey)
	const n = 5
	for range n {
		l.LogExchange(testEvent)
	}

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != n {
		t.Fatalf("expected %d lines, got %d", n, len(lines))
	}
	for i, line := range lines {
		entry := parseJSON(t, line)
		want := float64(i + 1)
		if entry["seq"].(float64) != want {
			t.Errorf("line %d: seq = %v, want %v", i+1, entry["seq"], want)
		}
	}
}

// errWriter is an io.Writer that always returns an error.
type errWriter struct{ err error }

func (e errWriter) Write(_ []byte) (int, error) { return 0, e.err }

func TestHMACWriterWriteError(t *testing.T) {
	want := errors.New("disk full")
	hw := newHMACWriter(errWriter{err: want}, testKey)
	_, err := hw.Write([]byte(`{"event":"x"}` + "\n"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
}
