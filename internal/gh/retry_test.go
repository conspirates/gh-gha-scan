package gh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// script answers each request with the next of its responses. An entry
// with a nil response is a transport failure.
type script struct {
	steps  []step
	bodies []string
}

type step struct {
	code   int
	header map[string]string
	body   string
}

func (s *script) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
	}
	s.bodies = append(s.bodies, body)
	st := s.steps[min(len(s.bodies), len(s.steps))-1]
	if st.code == 0 {
		return nil, errors.New("connection reset")
	}
	h := http.Header{}
	for k, v := range st.header {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: st.code, Header: h, Body: io.NopCloser(strings.NewReader(st.body)), Request: req}, nil
}

// fakeClock records the waits a transport would make.
type fakeClock struct {
	now   time.Time
	waits []time.Duration
}

func newTestTransport(s *script) (*retryTransport, *fakeClock) {
	clock := &fakeClock{now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	rt := newRetryTransport(s, nil)
	rt.now = func() time.Time { return clock.now }
	rt.sleep = func(_ context.Context, d time.Duration) error {
		clock.waits = append(clock.waits, d)
		clock.now = clock.now.Add(d)
		return nil
	}
	rt.jitter = func(n int64) int64 { return n - 1 } // the longest wait
	return rt, clock
}

func post(body string) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://api.github.com/graphql", strings.NewReader(body))
	return req
}

func TestRetryTransport(t *testing.T) {
	ok := step{code: 200, body: `{"data":{}}`}
	tests := []struct {
		name     string
		steps    []step
		wantCode int
		wantErr  bool
		waits    []time.Duration
	}{
		{"server errors back off", []step{{code: 502}, {code: 503}, ok}, 200, false, []time.Duration{time.Second, 2 * time.Second}},
		{"transport failure", []step{{}, ok}, 200, false, []time.Duration{time.Second}},
		{"429 waits as told", []step{{code: 429, header: map[string]string{"Retry-After": "7"}}, ok}, 200, false, []time.Duration{7 * time.Second}},
		{"Retry-After as an HTTP date", []step{{code: 429, header: map[string]string{"Retry-After": "Mon, 26 Oct 2026 12:00:05 GMT"}}, ok}, 200, false, []time.Duration{5 * time.Second}},
		{"secondary limit as 403", []step{{code: 403, header: map[string]string{"Retry-After": "3"}}, ok}, 200, false, []time.Duration{3 * time.Second}},
		{"GraphQL RATE_LIMITED at HTTP 200", []step{{code: 200, body: `{"errors":[{"type":"RATE_LIMITED"}]}`}, ok}, 200, false, []time.Duration{time.Second}},
		{"a permission 403 is an answer", []step{{code: 403, body: `{"message":"Forbidden"}`}}, 403, false, nil},
		{"a 404 is an answer", []step{{code: 404}}, 404, false, nil},
		{"other GraphQL errors are answers", []step{{code: 200, body: `{"errors":[{"type":"FORBIDDEN"}]}`}}, 200, false, nil},
		{"gives up after maxAttempts", []step{{code: 502}}, 502, false, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}},
		{
			"an exhausted primary limit that resets after the outage window is returned now",
			[]step{{code: 403, header: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": strconv.FormatInt(time.Date(2026, 10, 26, 13, 0, 0, 0, time.UTC).Unix(), 10)}}},
			403, false, nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &script{steps: tt.steps}
			rt, clock := newTestTransport(s)
			resp, err := rt.RoundTrip(post(`{"query":"q"}`))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if resp != nil && resp.StatusCode != tt.wantCode {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantCode)
			}
			if len(clock.waits) != len(tt.waits) {
				t.Fatalf("waits = %v, want %v", clock.waits, tt.waits)
			}
			for i := range tt.waits {
				if clock.waits[i] != tt.waits[i] {
					t.Errorf("waits = %v, want %v", clock.waits, tt.waits)
					break
				}
			}
			for i, b := range s.bodies {
				if b != `{"query":"q"}` {
					t.Errorf("attempt %d sent body %q, want the original", i+1, b)
				}
			}
		})
	}
}

func TestRetryBodyIsReadableAfterRateLimitCheck(t *testing.T) {
	body := `{"data":{"x":1}}`
	rt, _ := newTestTransport(&script{steps: []step{{code: 200, body: body}}})
	resp, err := rt.RoundTrip(post("q"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestOutageWindowIsShared(t *testing.T) {
	// The first request uses up the outage window; a second one during the
	// same outage gets the error without waiting.
	rt, clock := newTestTransport(&script{steps: []step{{code: 502}}})
	rt.RoundTrip(post("a"))
	used := len(clock.waits)
	clock.now = clock.now.Add(maxOutage)
	resp, _ := rt.RoundTrip(post("b"))
	if resp.StatusCode != 502 || len(clock.waits) != used {
		t.Errorf("status %d after %d more waits; want 502 with none", resp.StatusCode, len(clock.waits)-used)
	}
}
