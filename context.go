// +build go1.7

package nosurf

import "net/http"

type ctxKey int

const (
	nosurfKey ctxKey = iota
)

type csrfContext struct {
	// The unmasked "real" token. This is the single source of truth:
	// the cookie mirrors it and the masked token below is derived from it.
	realToken []byte
	// The masked, base64 encoded token
	// That's suitable for use in form fields, etc.
	token string
	// reason for the failure of CSRF check
	reason error
}

// Token takes an HTTP request and returns
// the CSRF token for that request
// or an empty string if the token does not exist.
//
// Note that the token won't be available after
// CSRFHandler finishes
// (that is, in another handler that wraps it,
// or after the request has been served)
func Token(req *http.Request) string {
	ctx, ok := req.Context().Value(nosurfKey).(*csrfContext)
	if !ok {
		return ""
	}

	return ctx.token
}

// Reason takes an HTTP request and returns
// the reason of failure of the CSRF check for that request
//
// Note that the same availability restrictions apply for Reason() as for Token().
func Reason(req *http.Request) error {
	ctx := req.Context().Value(nosurfKey).(*csrfContext)

	return ctx.reason
}

func ctxClear(_ *http.Request) {
}

func ctxSetReason(req *http.Request, reason error) {
	ctx := req.Context().Value(nosurfKey).(*csrfContext)
	if len(ctx.realToken) == 0 {
		panic("Reason should never be set when there's no token in the context yet.")
	}

	ctx.reason = reason
}

// ctxRealToken returns the unmasked "real" token, the single source of
// truth for all equality checks. It returns nil if no token has been set.
func ctxRealToken(req *http.Request) []byte {
	ctx, ok := req.Context().Value(nosurfKey).(*csrfContext)
	if !ok {
		return nil
	}
	return ctx.realToken
}

// ctxSetToken stores the unmasked real token as the source of truth and
// derives the masked, base64-encoded token used in forms and headers.
func ctxSetToken(req *http.Request, token []byte) {
	ctx := req.Context().Value(nosurfKey).(*csrfContext)
	ctx.realToken = token
	ctx.token = b64encode(maskToken(token))
}
