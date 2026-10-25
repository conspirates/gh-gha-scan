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

// repoFields selects a repository with the contents of its top-level
// workflow files, so listing repos and reading workflows is one query.
const repoFields = `fragment repoFields on Repository {
  nameWithOwner
  defaultBranchRef { target { oid } }
  object(expression: "HEAD:.github/workflows") {
    ... on Tree { entries { name type object { ` + blobFields + ` } } }
  }
}`

const ownerReposQuery = `query($login: String!, $first: Int!, $after: String, $archived: Boolean, $fork: Boolean) {
  ` + rateLimitField + `
  repositoryOwner(login: $login) {
    repositories(first: $first, after: $after, isArchived: $archived, isFork: $fork, ownerAffiliations: [OWNER], orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes { ...repoFields }
    }
  }
}
` + repoFields

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
