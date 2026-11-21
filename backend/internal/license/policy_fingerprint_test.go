package license

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyFingerprintTracksClassificationAndMode(t *testing.T) {
	previous, err := json.Marshal(GetPolicy())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license-policy.json")
	load := func(document string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadPolicy(path); err != nil {
			t.Fatal(err)
		}
		return PolicyFingerprint()
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, previous, 0o600); err != nil {
			t.Errorf("restore policy: %v", err)
			return
		}
		if _, _, err := LoadPolicy(path); err != nil {
			t.Errorf("reload policy: %v", err)
		}
	})

	first := load(`{"permissive":["MIT","Apache-2.0"],"copyleft":["GPL-3.0-only"],"expressionMode":"strict"}`)
	reordered := load(`{"permissive":["Apache-2.0","MIT"],"copyleft":["GPL-3.0-only"],"expressionMode":"strict"}`)
	if first != reordered {
		t.Fatal("reordering equivalent policy lists must keep the fingerprint stable")
	}

	changedPolicy := load(`{"permissive":["MIT"],"copyleft":["GPL-3.0-only"],"expressionMode":"strict"}`)
	if changedPolicy == first {
		t.Fatal("changing a classification list must change the fingerprint")
	}
	changedMode := load(`{"permissive":["MIT"],"copyleft":["GPL-3.0-only"],"expressionMode":"permissive-wins"}`)
	if changedMode == changedPolicy {
		t.Fatal("changing expression mode must change the fingerprint")
	}
}
