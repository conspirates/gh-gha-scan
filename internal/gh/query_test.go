package gh

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/scan"
)

func TestBatchQuery(t *testing.T) {
	q := batchQuery([]scan.FileReq{
		{Owner: "actions", Repo: "checkout", Ref: "v4", Paths: []string{"action.yml", "action.yaml"}, Resolve: true},
		{Owner: "o", Repo: "r", Ref: "main", Paths: []string{".github/workflows/x.yml"}},
	})
	for _, want := range []string{
		`r0: repository(owner: "actions", name: "checkout")`,
		`f0: object(expression: "v4:action.yml")`,
		`f1: object(expression: "v4:action.yaml")`,
		`c: object(expression: "v4")`,
		`r1: repository(owner: "o", name: "r")`,
		`f0: object(expression: "main:.github/workflows/x.yml")`,
		`rateLimit { cost remaining resetAt }`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %q:\n%s", want, q)
		}
	}
	if strings.Count(q, "c: object") != 1 {
		t.Errorf("only requests with Resolve should resolve a commit:\n%s", q)
	}
}

func TestQuoteEscapes(t *testing.T) {
	if got := quote(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("quote = %s", got)
	}
}

func TestCommitPeelsTags(t *testing.T) {
	tests := map[string]string{
		`{"oid":"c1"}`:                       "c1",
		`{"oid":"t1","target":{"oid":"c2"}}`: "c2",
		`{"oid":"t1","target":{"oid":"t2","target":{"oid":"c3"}}}`: "c3",
		`null`: "",
	}
	for in, want := range tests {
		var o *object
		if err := json.Unmarshal([]byte(in), &o); err != nil {
			t.Fatal(err)
		}
		if got := o.commit(); got != want {
			t.Errorf("commit(%s) = %q, want %q", in, got, want)
		}
	}
}
