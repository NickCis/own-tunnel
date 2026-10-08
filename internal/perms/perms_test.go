package perms

import "testing"

func TestParseDefault(t *testing.T) {
	s, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(Publish) || !s.Has(Dial) || s.Has(Peers) || s.Has(Blocks) {
		t.Fatalf("default=%v", s.List())
	}
}

func TestParseAliasesAndAdmin(t *testing.T) {
	s, err := Parse([]string{"remote-forwarding", "ALL", "block-list"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(Publish) || !s.Has(Peers) || !s.Has(Blocks) {
		t.Fatalf("got %v", s.List())
	}
	admin, err := Parse([]string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Permission{Publish, Dial, Peers, Blocks} {
		if !admin.Has(p) {
			t.Fatalf("admin missing %s", p)
		}
	}
}

func TestParseUnknown(t *testing.T) {
	if _, err := Parse([]string{"superuser"}); err == nil {
		t.Fatal("expected error")
	}
}
