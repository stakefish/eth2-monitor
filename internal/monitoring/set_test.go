package monitoring

import (
	"slices"
	"strings"
	"testing"
)

// TestSet_NewWithInitial — variadic constructor populates the set.
func TestSet_NewWithInitial(t *testing.T) {
	s := NewSet[int](1, 2, 3, 2) // duplicates collapse
	if got := len(s); got != 3 {
		t.Errorf("len(NewSet(1,2,3,2)) = %d, want 3", got)
	}
	for _, want := range []int{1, 2, 3} {
		if !s.Contains(want) {
			t.Errorf("missing %d", want)
		}
	}
}

// TestSet_Add_Contains_Remove — the basic CRUD operations.
func TestSet_Add_Contains_Remove(t *testing.T) {
	s := NewSet[string]()
	if !s.IsEmpty() {
		t.Errorf("fresh set should be empty")
	}
	s.Add("a", "b")
	if !s.Contains("a") || !s.Contains("b") {
		t.Errorf("Add did not populate set: %v", s)
	}
	if s.Contains("missing") {
		t.Errorf("Contains returned true for absent key")
	}
	s.Remove("a")
	if s.Contains("a") {
		t.Errorf("Remove failed for %q", "a")
	}
	if !s.Contains("b") {
		t.Errorf("Remove dropped wrong key — %q still expected", "b")
	}
	s.Remove("nope") // remove of absent must not panic
}

// TestSet_RemoveOnNilSet — pkg code may call Remove via map lookup when the
// slot has no entry. delete on a nil map is a no-op in Go; this test pins
// that behaviour so refactors don't reintroduce a nil-deref crash.
func TestSet_RemoveOnNilSet(t *testing.T) {
	var s Set[int] // nil
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Remove panicked on nil set: %v", r)
		}
	}()
	s.Remove(42)
	if !s.IsEmpty() {
		t.Errorf("nil set should report empty")
	}
}

// TestSet_AddOnNilSet — Add on a nil map panics (cannot grow a nil map).
// Documents the contract so callers know NewSet is required before Add.
func TestSet_AddOnNilSet(t *testing.T) {
	var s Set[int] // nil
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when adding to nil set; got none")
		}
	}()
	s.Add(1)
}

// TestSet_Elems — yield iteration covers every element exactly once.
// Order is not guaranteed (map iteration), so compare sorted slices.
func TestSet_Elems(t *testing.T) {
	s := NewSet[int](3, 1, 4, 1, 5, 9, 2, 6)
	var got []int
	for v := range s.Elems() {
		got = append(got, v)
	}
	slices.Sort(got)
	want := []int{1, 2, 3, 4, 5, 6, 9}
	if !slices.Equal(got, want) {
		t.Errorf("Elems yielded %v, want %v (after sort)", got, want)
	}
}

// TestSet_String_Empty — empty set has stable string form.
func TestSet_String_Empty(t *testing.T) {
	if got := NewSet[int]().String(); got != "{}" {
		t.Errorf("empty set String = %q, want %q", got, "{}")
	}
}

// TestSet_String_NonEmpty — ordering is non-deterministic but the wrapper
// braces and member content are stable.
func TestSet_String_NonEmpty(t *testing.T) {
	got := NewSet[int](1, 2, 3).String()
	if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
		t.Errorf("String = %q, want braces", got)
	}
	for _, want := range []string{"1", "2", "3"} {
		if !strings.Contains(got, want) {
			t.Errorf("String %q missing element %q", got, want)
		}
	}
}
