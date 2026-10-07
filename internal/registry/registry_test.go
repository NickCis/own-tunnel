package registry

import "testing"

func TestRegisterConflictAndMultiPort(t *testing.T) {
	r := New()
	_, err := r.Register(RegisterOpts{Name: "app", Port: 80, ClientBind: "app", User: "alice", ConnID: "1", Conn: nil})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Register(RegisterOpts{Name: "app", Port: 5432, ClientBind: "app", User: "alice", ConnID: "1", Conn: nil})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Register(RegisterOpts{Name: "app", Port: 80, ClientBind: "app", User: "bob", ConnID: "2", Conn: nil})
	if err == nil {
		t.Fatal("expected conflict on app:80")
	}
	if _, ok := r.GetHTTP("app"); !ok {
		t.Fatal("missing http")
	}
	if _, ok := r.Get("app", 5432); !ok {
		t.Fatal("missing tcp")
	}
	list := r.ListByUser("alice")
	if len(list) != 2 {
		t.Fatalf("list=%d", len(list))
	}
}

func TestUnregisterByClientBind(t *testing.T) {
	r := New()
	_, err := r.Register(RegisterOpts{Name: "abc12345", Port: 80, ClientBind: "", User: "alice", ConnID: "1", Conn: nil})
	if err != nil {
		t.Fatal(err)
	}
	tunn, ok := r.UnregisterByClientBind("1", "", 80)
	if !ok || tunn.Name != "abc12345" {
		t.Fatalf("unregister: %+v %v", tunn, ok)
	}
	if _, ok := r.GetHTTP("abc12345"); ok {
		t.Fatal("still present")
	}
}

func TestUnregisterConn(t *testing.T) {
	r := New()
	_, _ = r.Register(RegisterOpts{Name: "a", Port: 80, ClientBind: "a", User: "u", ConnID: "c1", Conn: nil})
	_, _ = r.Register(RegisterOpts{Name: "a", Port: 22, ClientBind: "a", User: "u", ConnID: "c1", Conn: nil})
	removed := r.UnregisterConn("c1")
	if len(removed) != 2 {
		t.Fatalf("removed=%d", len(removed))
	}
}

func TestRegisterAllocatedAtomic(t *testing.T) {
	r := New()
	_, err := r.Register(RegisterOpts{Name: "taken001", Port: 80, ClientBind: "", User: "a", ConnID: "1", Conn: nil})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	tunn, err := r.RegisterAllocated(RegisterOpts{Port: 80, ClientBind: "", User: "b", ConnID: "2", Conn: nil}, func() (string, error) {
		calls++
		if calls == 1 {
			return "taken001", nil
		}
		return "fresh001", nil
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if tunn.Name != "fresh001" || calls != 2 {
		t.Fatalf("got name=%s calls=%d", tunn.Name, calls)
	}
}

func TestListAllSorted(t *testing.T) {
	r := New()
	_, _ = r.Register(RegisterOpts{Name: "zeta", Port: 80, ClientBind: "zeta", User: "bob", ConnID: "2", Conn: nil})
	_, _ = r.Register(RegisterOpts{Name: "alpha", Port: 5432, ClientBind: "alpha", User: "alice", ConnID: "1", Conn: nil})
	_, _ = r.Register(RegisterOpts{Name: "alpha", Port: 80, ClientBind: "alpha", User: "alice", ConnID: "1", Conn: nil})
	_, _ = r.Register(RegisterOpts{Name: "alpha", Port: 22, ClientBind: "alpha", User: "alice", ConnID: "1", Conn: nil})

	list := r.ListAll()
	want := []string{"alpha:22", "alpha:80", "alpha:5432", "zeta:80"}
	if len(list) != len(want) {
		t.Fatalf("len=%d want %d", len(list), len(want))
	}
	for i, tnl := range list {
		got := key(tnl.Name, tnl.Port)
		if got != want[i] {
			t.Fatalf("index %d: got %s want %s", i, got, want[i])
		}
	}
}
