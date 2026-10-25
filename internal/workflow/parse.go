// Package workflow extracts `uses:` references from workflow and action files.
package workflow

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Use is one `uses:` occurrence in a file.
type Use struct {
	Value string
	Line  int
	// Comment is the trailing comment on the same line, e.g. "v4.1.0" for
	// `uses: actions/checkout@<sha> # v4.1.0`.
	Comment string
}

// Extract returns every `uses:` in a workflow file (jobs.*.uses and
// jobs.*.steps[].uses) or a composite action file (runs.steps[].uses).
func Extract(data []byte) ([]Use, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	root := doc.Content[0]

	var uses []Use
	if jobs := get(root, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 1; i < len(jobs.Content); i += 2 {
			job := jobs.Content[i]
			uses = appendUse(uses, get(job, "uses"))
			uses = appendSteps(uses, get(job, "steps"))
		}
	}
	if runs := get(root, "runs"); runs != nil {
		uses = appendSteps(uses, get(runs, "steps"))
	}
	return uses, nil
}

func appendSteps(uses []Use, steps *yaml.Node) []Use {
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return uses
	}
	for _, step := range steps.Content {
		uses = appendUse(uses, get(step, "uses"))
	}
	return uses
}

func appendUse(uses []Use, n *yaml.Node) []Use {
	if n == nil || n.Kind != yaml.ScalarNode || n.Value == "" {
		return uses
	}
	return append(uses, Use{
		Value:   n.Value,
		Line:    n.Line,
		Comment: strings.TrimSpace(strings.TrimPrefix(n.LineComment, "#")),
	})
}

// get returns the value for key in a mapping node, following aliases.
func get(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			v := n.Content[i+1]
			if v.Kind == yaml.AliasNode {
				v = v.Alias
			}
			return v
		}
	}
	return nil
}
