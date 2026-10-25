package gh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// maxAttempts bounds how often one request is sent.
	maxAttempts = 6
	// maxBackoff caps one exponential backoff wait.
	maxBackoff = 30 * time.Second
	// maxOutage is how long a run keeps retrying through one outage: from
	// the first failure after an answer, all retries must end within it.
	// A wait GitHub asks for that ends later, e.g. until an exhausted
	// primary rate limit resets, is not made: the error is returned now.
	maxOutage = 2 * time.Minute
)

// retryTransport retries requests that ended without a usable answer:
// transport failures, server errors and rate limits. Every request the
// client sends is a read (REST GETs and GraphQL queries), so a retry is
// always safe. It is the only retry layer; callers never retry.
type retryTransport struct {
	inner http.RoundTripper
	// onRetry is told about each wait, for Stats.
	onRetry func(wait time.Duration)

	mu sync.Mutex
	// outageStart is when the current outage began, or zero while GitHub is
	// answering.
	outageStart time.Time

	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(n int64) int64
}

func newRetryTransport(inner http.RoundTripper, onRetry func(time.Duration)) *retryTransport {
	return &retryTransport{
		inner:   inner,
		onRetry: onRetry,
		now:     time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		jitter: rand.Int64N,
	}
}

func (rt *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	for attempt := 1; ; attempt++ {
		r := req
		if attempt > 1 {
			if req.Body != nil && req.GetBody == nil {
				return nil, errNoReplay
			}
			r = req.Clone(ctx)
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				r.Body = body
			}
		}

		resp, err := rt.inner.RoundTrip(r)
		var retryAt time.Time
		retry := false
		switch {
		case err != nil:
			retry = ctx.Err() == nil
		default:
			retryAt, retry = retryable(resp, rt.now())
		}
		if !retry {
			if err == nil {
				rt.answered()
			}
			return resp, err
		}
		if attempt >= maxAttempts {
			return resp, err
		}

		wait := rt.backoff(attempt)
		if !retryAt.IsZero() {
			wait = max(retryAt.Sub(rt.now()), 0)
		}
		if !rt.allow(wait) {
			return resp, err
		}
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if rt.onRetry != nil {
			rt.onRetry(wait)
		}
		if err := rt.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// errNoReplay is returned when a request must be retried but its body can't
// be sent again. The client's requests always can.
var errNoReplay = errors.New("request body cannot be replayed for a retry")

// backoff is exponential with full jitter: a random wait up to 1s, 2s, 4s,
// and so on, capped at maxBackoff.
func (rt *retryTransport) backoff(attempt int) time.Duration {
	ceiling := min(time.Second<<(attempt-1), maxBackoff)
	return time.Duration(rt.jitter(int64(ceiling) + 1))
}

// allow reports whether a wait of d still ends within the outage window,
// opening the window if this is the first failure since an answer.
func (rt *retryTransport) allow(d time.Duration) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := rt.now()
	if rt.outageStart.IsZero() {
		rt.outageStart = now
	}
	return now.Add(d).Sub(rt.outageStart) <= maxOutage
}

// answered closes the outage window: GitHub is answering again.
func (rt *retryTransport) answered() {
	rt.mu.Lock()
	rt.outageStart = time.Time{}
	rt.mu.Unlock()
}

// retryable reports whether resp is an outage or a rate limit worth
// retrying, and when GitHub said a retry could succeed (zero if it didn't).
func retryable(resp *http.Response, now time.Time) (time.Time, bool) {
	switch code := resp.StatusCode; {
	case code >= 500:
		return retryAt(resp.Header, now), true
	case code == http.StatusTooManyRequests:
		return retryAt(resp.Header, now), true
	case code == http.StatusForbidden:
		// A 403 is a permission answer unless it is a secondary rate limit
		// (Retry-After) or an exhausted primary one.
		if resp.Header.Get("Retry-After") != "" || resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return retryAt(resp.Header, now), true
		}
	case code == http.StatusOK && resp.Request != nil && resp.Request.Method == http.MethodPost:
		// GraphQL reports its rate limit as HTTP 200 with a RATE_LIMITED error.
		if graphQLRateLimited(resp) {
			return retryAt(resp.Header, now), true
		}
	}
	return time.Time{}, false
}

// graphQLRateLimited reports whether a GraphQL response is a RATE_LIMITED
// error. It reads the body and puts it back for the caller.
func graphQLRateLimited(resp *http.Response) bool {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var payload struct {
		Errors []struct {
			Type string `json:"type"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	for _, e := range payload.Errors {
		if e.Type == "RATE_LIMITED" {
			return true
		}
	}
	return false
}

// retryAt returns when GitHub said a request may be retried, from
// Retry-After (seconds or an HTTP date) or, for an exhausted budget,
// X-RateLimit-Reset. It is zero when GitHub didn't say.
func retryAt(h http.Header, now time.Time) time.Time {
	if v := h.Get("Retry-After"); v != "" {
		if s, err := strconv.Atoi(v); err == nil {
			return now.Add(time.Duration(s) * time.Second)
		}
		if t, err := http.ParseTime(v); err == nil {
			return t
		}
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		if s, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return time.Unix(s, 0)
		}
	}
	return time.Time{}
}
