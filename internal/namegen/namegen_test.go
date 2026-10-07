package namegen

import "testing"

func TestIsEphemeralBind(t *testing.T) {
	cases := map[string]bool{
		"":          true,
		"0.0.0.0":   true,
		"localhost": true,
		"127.0.0.1": true,
		"myapp":     false,
		"MyApp":     false,
	}
	for in, want := range cases {
		if got := IsEphemeralBind(in); got != want {
			t.Fatalf("IsEphemeralBind(%q)=%v want %v", in, got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	got, err := Sanitize("My-App")
	if err != nil || got != "my-app" {
		t.Fatalf("Sanitize My-App: got %q err %v", got, err)
	}
	if _, err := Sanitize("bad_name!"); err == nil {
		t.Fatal("expected error for invalid name")
	}
}

func TestRandom(t *testing.T) {
	a, err := Random(8)
	if err != nil || len(a) != 8 {
		t.Fatalf("Random: %q %v", a, err)
	}
	if !labelRe.MatchString(a) {
		t.Fatalf("not a label: %q", a)
	}
}
