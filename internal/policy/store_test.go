package policy

import (
	"path/filepath"
	"testing"
)

func TestStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	p := Policy{
		Name:          "a-to-b",
		Subject:       "spiffe://cluster.local/ns/default/sa/a",
		Target:        "spiffe://cluster.local/ns/default/sa/b",
		AllowedScopes: []string{"read"},
		MaxTTL:        60,
	}

	t.Run("list empty store", func(t *testing.T) {
		got, err := store.List()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected 0 policies, got %d", len(got))
		}
	})

	t.Run("save and list", func(t *testing.T) {
		if err := store.Save(p); err != nil {
			t.Fatalf("save: %v", err)
		}
		got, err := store.List()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].Name != p.Name {
			t.Errorf("expected policy %q, got %+v", p.Name, got)
		}
	})

	t.Run("save overwrites existing", func(t *testing.T) {
		updated := p
		updated.MaxTTL = 120
		if err := store.Save(updated); err != nil {
			t.Fatalf("save: %v", err)
		}
		got, err := store.List()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 1 || got[0].MaxTTL != 120 {
			t.Errorf("expected updated MaxTTL=120, got %+v", got)
		}
	})

	t.Run("delete removes policy", func(t *testing.T) {
		if err := store.Delete(p.Name); err != nil {
			t.Fatalf("delete: %v", err)
		}
		got, err := store.List()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected 0 policies after delete, got %d", len(got))
		}
	})

	t.Run("delete non-existent is not an error", func(t *testing.T) {
		if err := store.Delete("does-not-exist"); err != nil {
			t.Errorf("expected no error deleting non-existent key, got: %v", err)
		}
	})
}
