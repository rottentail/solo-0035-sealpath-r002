package repository

import (
	"os"
	"path/filepath"
	"testing"
)

// A state file written before OCSP existed must still load: absent optional
// maps are restored to empty collections by NewState.
func TestStateWithoutOCSPFieldsLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	data := []byte(`{"version":1,"sequence":0,"certificates":{},"trust_sets":{},"artifacts":{},"signatures":{},"revocations":{},"policies":{},"decisions":{},"materials":{},"events":[]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatalf("legacy state failed to load: %v", err)
	}
	state, err := store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if state.OCSPResponders == nil || state.OCSPResponses == nil {
		t.Fatal("OCSP collections were not initialized for a legacy state file")
	}
}
