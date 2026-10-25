package gh

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
)

// aliasError is a GraphQL error about one top-level alias of a batched
// query.
type aliasError struct {
	typ, msg string
}

// message explains e for a repository of owner. A SAML block says what to
// do about it.
func (e aliasError) message(owner string) string {
	if strings.Contains(e.msg, "SAML") {
		return fmt.Sprintf("the %s organization requires SAML single sign-on; authorize your token for it (for gh: gh auth refresh)", owner)
	}
	if e.msg == "" {
		return "repository not found or not accessible"
	}
	return e.msg
}

// aliasErrors sorts the errors of a batched query. An error with a path
// belongs to one alias, e.g. NOT_FOUND, FORBIDDEN or a SAML block, and fails
// only that item; those are returned by alias. A GraphQL error without a
// path, or any other error, rejected the whole query and is returned as is.
func aliasErrors(err error) (map[string]aliasError, error) {
	if err == nil {
		return nil, nil
	}
	var ge *api.GraphQLError
	if !errors.As(err, &ge) {
		return nil, err
	}
	out := map[string]aliasError{}
	for _, e := range ge.Errors {
		var alias string
		if len(e.Path) > 0 {
			alias, _ = e.Path[0].(string)
		}
		if alias == "" {
			return nil, err
		}
		if _, ok := out[alias]; !ok {
			out[alias] = aliasError{typ: e.Type, msg: e.Message}
		}
	}
	return out, nil
}

// splittable reports whether a batch rejected with err may succeed in
// smaller parts: a GraphQL error about the whole query, e.g. its cost, or a
// gateway timeout, which a query too heavy for GitHub gets. Other outages
// and rate limits would reject every part the same way, and the transport
// has already retried them.
func splittable(err error) bool {
	var ge *api.GraphQLError
	if errors.As(err, &ge) {
		for _, e := range ge.Errors {
			if e.Type == "RATE_LIMITED" {
				return false
			}
		}
		return true
	}
	var he *api.HTTPError
	return errors.As(err, &he) && (he.StatusCode == http.StatusBadGateway || he.StatusCode == http.StatusGatewayTimeout)
}

// inHalves runs a batched query over items. When the whole query is
// rejected in a way smaller ones may avoid, it runs each half, down to
// single items, so one bad item can't fail its batch-mates; an item still
// rejected on its own gets failed(item, err). Any other error is returned.
func inHalves[T, R any](items []T, run func([]T) ([]R, error), failed func(T, error) R) ([]R, error) {
	res, err := run(items)
	if err == nil || !splittable(err) {
		return res, err
	}
	if len(items) == 1 {
		return []R{failed(items[0], err)}, nil
	}
	mid := len(items) / 2
	a, err := inHalves(items[:mid], run, failed)
	if err != nil {
		return nil, err
	}
	b, err := inHalves(items[mid:], run, failed)
	if err != nil {
		return nil, err
	}
	return append(a, b...), nil
}
