package client

import "net/http"

type roundTripper struct {
	c    *Client
	base http.RoundTripper
}

// NewHTTPTransport returns an [http.RoundTripper] that fetches a token from c
// and injects it as an Authorization: Bearer header on every request. Pass the
// result as the Transport field of an [http.Client].
// If base is nil, [http.DefaultTransport] is used.
func NewHTTPTransport(c *Client, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &roundTripper{c: c, base: base}
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	// Clone the request before mutating headers — the RoundTripper contract
	// forbids modifying the original request.
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return t.base.RoundTrip(r)
}
