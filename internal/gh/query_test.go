package gh

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/scan"
)

func TestBatchQuery(t *testing.T) {
	q, vars := batchQuery([]scan.FileReq{
		{Owner: "actions", Repo: "checkout", Ref: "v4", Paths: []string{"action.yml", "action.yaml"}, Resolve: true},
		{Owner: "o", Repo: "r", Ref: "main", Paths: []string{".github/workflows/x.yml"}},
	})
	for _, want := range []string{
		`query($o0: String!, $n0: String!, $e0: String!, $p0_0: String!, $p0_1: String!, $o1: String!`,
		`r0: repository(owner: $o0, name: $n0)`,
		`object(expression: $e0) { ... on Commit { oid f0: file(path: $p0_0)`,
		`f1: file(path: $p0_1)`,
		`r1: repository(owner: $o1, name: $n1)`,
		`rateLimit { cost remaining resetAt }`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %q:\n%s", want, q)
		}
	}
	want := map[string]any{
		"o0": "actions", "n0": "checkout", "e0": "v4^{commit}", "p0_0": "action.yml", "p0_1": "action.yaml",
		"o1": "o", "n1": "r", "e1": "main^{commit}", "p1_0": ".github/workflows/x.yml",
	}
	if !reflect.DeepEqual(vars, want) {
		t.Errorf("vars = %v, want %v", vars, want)
	}
}

func TestValuesAreNeverInTheQueryText(t *testing.T) {
	odd := `a"b\c} { x`
	q, _ := batchQuery([]scan.FileReq{{Owner: odd, Repo: odd, Ref: odd, Paths: []string{odd}}})
	q2, _ := tagsQuery([]string{odd + "/" + odd}, map[string][]string{odd + "/" + odd: {odd}})
	q3, _ := workflowsQuery([]repoNode{{NameWithOwner: odd + "/" + odd}})
	for _, q := range []string{q, q2, q3} {
		if strings.Contains(q, "b\\c") || strings.Contains(q, `a"b`) {
			t.Errorf("a value is in the query text:\n%s", q)
		}
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

func TestTagsQuery(t *testing.T) {
	q, vars := tagsQuery([]string{"actions/checkout", "o/r"}, map[string][]string{"o/r": {"main"}})
	for _, want := range []string{
		`t1: repository(owner: $o1, name: $n1)`,
		`defaultBranchRef { name target { oid } }`,
		`t0: repository(owner: $o0, name: $n0)`,
		`b0: ref(qualifiedName: $b1_0) { target { oid } }`,
		`x0: ref(qualifiedName: $x1_0) { name }`,
		`refs(refPrefix: "refs/tags/", first: 50, orderBy: {field: TAG_COMMIT_DATE, direction: DESC})`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %q:\n%s", want, q)
		}
	}
	if vars["b1_0"] != "refs/heads/main" || vars["x1_0"] != "refs/tags/main" || vars["o0"] != "actions" {
		t.Errorf("vars = %v", vars)
	}
}
