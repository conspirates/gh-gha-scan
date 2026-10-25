// Package gh fetches repositories and files from GitHub with batched GraphQL
// queries.
package gh

import (
	"fmt"
	"strings"

	"github.com/conspirates/gh-gha-scan/internal/scan"
)

// BatchSize is the number of file requests per GraphQL query.
const BatchSize = 50

const rateLimitField = "rateLimit { cost remaining resetAt }"

const blobFields = "... on Blob { text isTruncated isBinary }"

// workflowsTree selects the top-level workflow files under a tree object.
const workflowsTree = "... on Tree { entries { name type object { " + blobFields + " } } }"

// repoFields selects a repository with the contents of its top-level
// workflow files.
const repoFields = `fragment repoFields on Repository {
  nameWithOwner
  isFork
  defaultBranchRef { target { oid } }
  object(expression: "HEAD:.github/workflows") { ` + workflowsTree + ` }
}`

// ownerReposQuery lists repositories with only their default branch commit,
// so that workflow files are fetched only for commits not cached yet.
const ownerReposQuery = `query($login: String!, $after: String, $archived: Boolean, $fork: Boolean) {
  ` + rateLimitField + `
  repositoryOwner(login: $login) {
    forks: repositories(isFork: true, isArchived: $archived, ownerAffiliations: [OWNER]) { totalCount }
    repositories(first: 100, after: $after, isArchived: $archived, isFork: $fork, ownerAffiliations: [OWNER], orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes { nameWithOwner isFork defaultBranchRef { target { oid } } }
    }
  }
}`

// WorkflowsPerQuery is how many repositories' workflow files are read per
// query. Some repositories have huge workflow files, so it is small, and
// halved further when GitHub times out.
const WorkflowsPerQuery = 25

// workflowsQuery reads the top-level workflow files of each repository at a
// commit, aliased rN.
func workflowsQuery(repos []repoNode) (string, map[string]any) {
	var v vars
	var b strings.Builder
	for i, r := range repos {
		owner, name, _ := strings.Cut(r.NameWithOwner, "/")
		fmt.Fprintf(&b, "  r%d: repository(owner: %s, name: %s) {\n", i, v.add(fmt.Sprintf("o%d", i), owner), v.add(fmt.Sprintf("n%d", i), name))
		fmt.Fprintf(&b, "    object(expression: %s) { %s }\n", v.add(fmt.Sprintf("e%d", i), r.oid()+":.github/workflows"), workflowsTree)
		b.WriteString("  }\n")
	}
	return v.query(b.String()), v.vals
}

const repoQuery = `query($owner: String!, $name: String!) {
  ` + rateLimitField + `
  repository(owner: $owner, name: $name) { ...repoFields }
}
` + repoFields

// vars collects the String! variables of a query built in pieces, so that
// values never have to be quoted into the query text.
type vars struct {
	decl []string
	vals map[string]any
}

// add declares variable name with value val and returns its reference.
func (v *vars) add(name, val string) string {
	if v.vals == nil {
		v.vals = map[string]any{}
	}
	v.decl = append(v.decl, "$"+name+": String!")
	v.vals[name] = val
	return "$" + name
}

// query wraps body, the selections of the query, in a query that declares
// the variables.
func (v *vars) query(body string) string {
	head := "query"
	if len(v.decl) > 0 {
		head += "(" + strings.Join(v.decl, ", ") + ")"
	}
	return head + " {\n  " + rateLimitField + "\n" + body + "}\n"
}

// batchQuery builds one query for reqs, which must be in a stable order. Each
// request becomes alias rN. Its ref is looked up as a commit, which also peels
// annotated tags, and each candidate path is read from that commit as fM, so
// the commit comes back even when no file is found.
func batchQuery(reqs []scan.FileReq) (string, map[string]any) {
	var v vars
	var b strings.Builder
	for i, req := range reqs {
		fmt.Fprintf(&b, "  r%d: repository(owner: %s, name: %s) {\n", i, v.add(fmt.Sprintf("o%d", i), req.Owner), v.add(fmt.Sprintf("n%d", i), req.Repo))
		fmt.Fprintf(&b, "    object(expression: %s) { ... on Commit { oid", v.add(fmt.Sprintf("e%d", i), req.Ref+"^{commit}"))
		for j, p := range req.Paths {
			fmt.Fprintf(&b, " f%d: file(path: %s) { object { %s } }", j, v.add(fmt.Sprintf("p%d_%d", i, j), p), blobFields)
		}
		b.WriteString(" } }\n  }\n")
	}
	return v.query(b.String()), v.vals
}

// TagsPerRepo is how many of the most recent tags are listed per repository
// when looking for a release to upgrade to.
const TagsPerRepo = 50

// tagsQuery lists the default branch and recent tags of repos (owner/repo),
// aliased tN. For each name in branches[repo] it also asks for the branch,
// aliased bM, and for a tag of the same name, aliased xM.
func tagsQuery(repos []string, branches map[string][]string) (string, map[string]any) {
	var v vars
	var b strings.Builder
	for i, r := range repos {
		owner, name, _ := strings.Cut(r, "/")
		fmt.Fprintf(&b, "  t%d: repository(owner: %s, name: %s) {\n", i, v.add(fmt.Sprintf("o%d", i), owner), v.add(fmt.Sprintf("n%d", i), name))
		b.WriteString("    defaultBranchRef { name target { oid } }\n")
		fmt.Fprintf(&b, "    refs(refPrefix: \"refs/tags/\", first: %d, orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) {\n", TagsPerRepo)
		b.WriteString("      nodes { name target { oid ... on Tag { target { oid ... on Tag { target { oid } } } } } }\n")
		b.WriteString("    }\n")
		for j, name := range branches[r] {
			fmt.Fprintf(&b, "    b%d: ref(qualifiedName: %s) { target { oid } }\n", j, v.add(fmt.Sprintf("b%d_%d", i, j), "refs/heads/"+name))
			fmt.Fprintf(&b, "    x%d: ref(qualifiedName: %s) { name }\n", j, v.add(fmt.Sprintf("x%d_%d", i, j), "refs/tags/"+name))
		}
		b.WriteString("  }\n")
	}
	return v.query(b.String()), v.vals
}

type tagNode struct {
	Name   string  `json:"name"`
	Target *object `json:"target"`
}

type rateLimit struct {
	Cost      int    `json:"cost"`
	Remaining int    `json:"remaining"`
	ResetAt   string `json:"resetAt"`
}

type blob struct {
	Text        *string `json:"text"`
	IsTruncated bool    `json:"isTruncated"`
	IsBinary    bool    `json:"isBinary"`
}

type repoNode struct {
	NameWithOwner    string `json:"nameWithOwner"`
	IsFork           bool   `json:"isFork"`
	DefaultBranchRef *struct {
		Target struct {
			OID string `json:"oid"`
		} `json:"target"`
	} `json:"defaultBranchRef"`
	Object *struct {
		Entries []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Object *blob  `json:"object"`
		} `json:"entries"`
	} `json:"object"`
}

// oid returns the default branch commit, or "" for an empty repository.
func (n repoNode) oid() string {
	if n.DefaultBranchRef == nil {
		return ""
	}
	return n.DefaultBranchRef.Target.OID
}

type object struct {
	OID    string `json:"oid"`
	Target *struct {
		OID    string `json:"oid"`
		Target *struct {
			OID string `json:"oid"`
		} `json:"target"`
	} `json:"target"`
}

// commit peels up to two levels of annotated tags.
func (o *object) commit() string {
	switch {
	case o == nil:
		return ""
	case o.Target == nil:
		return o.OID
	case o.Target.Target == nil:
		return o.Target.OID
	}
	return o.Target.Target.OID
}
