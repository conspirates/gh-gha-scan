package gh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cli/go-gh/v2/pkg/api"
)

// handlerTransport serves requests with a handler instead of the network.
type handlerTransport http.HandlerFunc

func (h handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	h(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// testClient returns a client whose GraphQL and REST requests go to h.
func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	opts := api.ClientOptions{Host: "github.com", AuthToken: "test", Transport: handlerTransport(h)}
	gql, err := api.NewGraphQLClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.NewRESTClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{gql: gql, rest: rest, Concurrency: 4}
}

func TestRetriesAreCounted(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			// A secondary rate limit that asks for no wait, to keep the test fast.
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"rateLimit":{"cost":1,"remaining":4999,"resetAt":"x"}}}`))
	})
	var out struct{}
	if err := c.do(context.Background(), "query { rateLimit { cost } }", nil, &out); err != nil {
		t.Fatal(err)
	}
	s := c.Stats()
	if calls != 3 || s.Retries != 2 || s.Queries != 1 {
		t.Errorf("calls = %d, stats = %+v; want 3 calls, 2 retries, 1 query", calls, s)
	}
}
