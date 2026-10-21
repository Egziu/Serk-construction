package kernel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/workflow"
)

// The shipped example definitions must pass the same validation as any
// definition proposed through the API.
func TestExampleWorkflowDefinitionsAreValid(t *testing.T) {
	svc := New(nil, auth.NewAuthorizer(nil, true))
	files, err := filepath.Glob("../../examples/workflows/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := workflow.Parse(b, svc.WorkflowCatalog()); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}
