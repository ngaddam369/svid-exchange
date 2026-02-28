// Package audit emits structured JSON audit log entries to stdout.
package audit

import (
	"os"

	"github.com/rs/zerolog"
)

// Logger writes audit events as structured JSON.
type Logger struct {
	log zerolog.Logger
}

// New creates an audit Logger writing to stdout.
func New() *Logger {
	return &Logger{
		log: zerolog.New(os.Stdout).With().Timestamp().Logger(),
	}
}

// ExchangeEvent is the payload for a token exchange audit log entry.
type ExchangeEvent struct {
	Subject         string
	Target          string
	ScopesRequested []string
	ScopesGranted   []string
	Granted         bool
	TTL             int32
	TokenID         string
	DenialReason    string
}

// LogExchange emits one audit log line for a token exchange attempt.
func (l *Logger) LogExchange(e ExchangeEvent) {
	ev := l.log.Info().
		Str("event", "token.exchange").
		Str("subject", e.Subject).
		Str("target", e.Target).
		Strs("scopes_requested", e.ScopesRequested).
		Bool("granted", e.Granted)

	if e.Granted {
		ev = ev.
			Strs("scopes_granted", e.ScopesGranted).
			Int32("ttl", e.TTL).
			Str("token_id", e.TokenID)
	} else {
		ev = ev.Str("denial_reason", e.DenialReason)
	}

	ev.Send()
}
