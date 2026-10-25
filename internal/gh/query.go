// Package gh fetches repositories and files from GitHub with batched GraphQL
// queries.
package gh

import (
	"encoding/json"
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
func workflowsQuery(repos []repoNode) string {
	var b strings.Builder
	b.WriteString("query {\n  " + rateLimitField + "\n")
	for i, r := range repos {
		owner, name, _ := strings.Cut(r.NameWithOwner, "/")
		fmt.Fprintf(&b, "  r%d: repository(owner: %s, name: %s) {\n", i, quote(owner), quote(name))
		fmt.Fprintf(&b, "    object(expression: %s) { %s }\n", quote(r.oid()+":.github/workflows"), workflowsTree)
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

const repoQuery = `query($owner: String!, $name: String!) {
  ` + rateLimitField + `
  repository(owner: $owner, name: $name) { ...repoFields }
}
` + repoFields

// quote returns s as a GraphQL string literal. JSON string syntax is a
// subset of GraphQL's.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// batchQuery builds one query for reqs, which must be in a stable order. Each
// request becomes alias rN, each candidate path fM, and the resolved commit c.
func batchQuery(reqs []scan.FileReq) string {
	var b strings.Builder
	b.WriteString("query {\n  " + rateLimitField + "\n")
	for i, req := range reqs {
		fmt.Fprintf(&b, "  r%d: repository(owner: %s, name: %s) {\n", i, quote(req.Owner), quote(req.Repo))
		for j, p := range req.Paths {
			fmt.Fprintf(&b, "    f%d: object(expression: %s) { %s }\n", j, quote(req.Ref+":"+p), blobFields)
		}
		if req.Resolve {
			fmt.Fprintf(&b, "    c: object(expression: %s) { oid ... on Tag { target { oid ... on Tag { target { oid } } } } }\n", quote(req.Ref))
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// TagsPerRepo is how many of the most recent tags are listed per repository
// when looking for a release to upgrade to.
const TagsPerRepo = 50

// tagsQuery lists the default branch and recent tags of repos (owner/repo),
// aliased tN.
func tagsQuery(repos []string) string {
	var b strings.Builder
	b.WriteString("query {\n  " + rateLimitField + "\n")
	for i, r := range repos {
		owner, name, _ := strings.Cut(r, "/")
		fmt.Fprintf(&b, "  t%d: repository(owner: %s, name: %s) {\n", i, quote(owner), quote(name))
		b.WriteString("    defaultBranchRef { name target { oid } }\n")
		fmt.Fprintf(&b, "    refs(refPrefix: \"refs/tags/\", first: %d, orderBy: {field: TAG_COMMIT_DATE, direction: DESC}) {\n", TagsPerRepo)
		b.WriteString("      nodes { name target { oid ... on Tag { target { oid ... on Tag { target { oid } } } } } }\n")
		b.WriteString("    }\n  }\n")
	}
	b.WriteString("}\n")
	return b.String()
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
