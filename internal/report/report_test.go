package report

import (
	"bytes"
	"testing"

	"github.com/conspirates/gh-gha-scan/internal/fix"
)

func TestTableListsEveryRepository(t *testing.T) {
	repos := []fix.Repo{
		{Repository: "o/clean", Items: []fix.Item{}},
		{Repository: "o/app", Items: []fix.Item{
			{Action: "actions/checkout@v5", Fix: "Pin to actions/checkout@abc # v5"},
			{Action: "up/x@v1", Fix: "Upgrade to up/x@def # v2.0.0"},
		}},
	}
	var b bytes.Buffer
	if err := Table(&b, repos, false, 80); err != nil {
		t.Fatal(err)
	}
	want := "o/clean\tNone\t\n" +
		"o/app\tactions/checkout@v5\tPin to actions/checkout@abc # v5\n" +
		"o/app\tup/x@v1\tUpgrade to up/x@def # v2.0.0\n"
	if b.String() != want {
		t.Errorf("Table() =\n%q\nwant\n%q", b.String(), want)
	}
}

func TestTableTruncatesNothingInNarrowTerminal(t *testing.T) {
	fixText := "Pin to actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5"
	repos := []fix.Repo{{Repository: "o/app", Items: []fix.Item{{Action: "actions/checkout@v5", Fix: fixText}}}}
	var b bytes.Buffer
	if err := Table(&b, repos, true, 60); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"REPOSITORY  UNPINNED ACTION", "actions/checkout@v5", fixText} {
		if !bytes.Contains(b.Bytes(), []byte(want)) {
			t.Errorf("output is missing %q:\n%s", want, b.String())
		}
	}
}

func TestIncompleteRepository(t *testing.T) {
	repos := []fix.Repo{{Repository: "o/app", Items: []fix.Item{}, Incomplete: true}}
	var table, summary bytes.Buffer
	if err := Table(&table, repos, false, 80); err != nil {
		t.Fatal(err)
	}
	if want := "o/app\tNone (incomplete, see warnings)\t\n"; table.String() != want {
		t.Errorf("Table() = %q, want %q", table.String(), want)
	}
	Summary(&summary, repos, []string{"o/app: stopped at --depth 10; refs inside x were not checked"})
	if !bytes.Contains(summary.Bytes(), []byte("1 repositories were not fully checked")) {
		t.Errorf("Summary() = %q", summary.String())
	}
}
