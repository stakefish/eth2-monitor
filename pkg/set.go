package pkg

import (
	"fmt"
	"iter"
	"strings"
)

// Set is a generic comparable-keyed set backed by an underlying map.
// Nil-receiver contract: Contains, IsEmpty, Remove, Elems, and String
// are safe on a nil Set (treated as empty); Add panics on a nil Set
// because Go nil maps can't be grown. Always construct with NewSet
// before Add. The tests pin this contract in set_test.go.
type Set[E comparable] map[E]struct{}

// NewSet returns an initialised (non-nil) Set containing the given values.
// Duplicate values in vals collapse to one entry.
func NewSet[E comparable](vals ...E) Set[E] {
	s := Set[E]{}
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

// Add inserts each value into the set. Panics on a nil Set (see type doc).
// Duplicates collapse to one entry.
func (s Set[E]) Add(vals ...E) {
	for _, v := range vals {
		s[v] = struct{}{}
	}
}

// Contains reports whether v is in the set. Safe on a nil Set (returns false).
func (s Set[E]) Contains(v E) bool {
	_, ok := s[v]
	return ok
}

// Remove deletes v from the set. Safe on a nil Set (no-op).
func (s Set[E]) Remove(v E) {
	delete(s, v)
}

// IsEmpty reports whether the set has no entries. Safe on a nil Set
// (returns true).
func (s Set[E]) IsEmpty() bool {
	return len(s) == 0
}

// String renders the set as "{a b c}" with elements in unspecified order.
// Safe on a nil Set (returns "{}").
func (s Set[E]) String() string {
	var sb strings.Builder
	first := true
	sb.WriteString("{")
	for v := range s {
		if !first {
			sb.WriteString(" ")
		}
		fmt.Fprint(&sb, v)
		first = false
	}
	sb.WriteString("}")
	return sb.String()
}

// Elems returns an iterator over the set's values. Iteration order is
// unspecified (map iter). Safe on a nil Set (yields nothing).
func (s Set[E]) Elems() iter.Seq[E] {
	return func(yield func(E) bool) {
		for v := range s {
			if !yield(v) {
				return
			}
		}
	}
}
