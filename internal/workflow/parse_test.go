package workflow

import (
	"os"
	"reflect"
	"testing"
)

func TestExtractWorkflow(t *testing.T) {
	data, err := os.ReadFile("testdata/workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Extract(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Use{
		{Value: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", Line: 9, Comment: "v4.1.0"},
		{Value: "actions/setup-go@v5", Line: 10},
		{Value: "./.github/actions/local", Line: 13},
		{Value: "docker://alpine:3.20", Line: 14},
		{Value: "octo/reusable/.github/workflows/build.yml@main", Line: 16},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Extract() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestExtractCompositeAction(t *testing.T) {
	data, err := os.ReadFile("testdata/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Extract(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Use{
		{Value: "actions/cache@v4", Line: 7},
		{Value: "third/party@1.2.3", Line: 10, Comment: "pinned someday"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Extract() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestExtractNodeActionHasNoUses(t *testing.T) {
	got, err := Extract([]byte("name: x\nruns:\n  using: node20\n  main: index.js\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("Extract() = %+v, want none", got)
	}
}

func TestExtractInvalidYAML(t *testing.T) {
	if _, err := Extract([]byte("jobs: [")); err == nil {
		t.Error("expected an error for invalid yaml")
	}
}
