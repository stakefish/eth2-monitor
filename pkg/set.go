package pkg

import (
	"fmt"
	"strings"
)

type Set[E comparable] map[E]struct{}

func NewSet[E comparable](vals ...E) Set[E] {
	s := Set[E]{}
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

func (s Set[E]) Add(vals ...E) {
	for _, v := range vals {
		s[v] = struct{}{}
	}
}

func (s Set[E]) Contains(v E) bool {
	_, ok := s[v]
	return ok
}

func (s Set[E]) Remove(v E) {
	delete(s, v)
}

func (s Set[E]) IsEmpty() bool {
	return len(s) == 0
}

func (s Set[E]) String() string {
	var sb strings.Builder
	first := true
	sb.WriteString("{")
	for v := range s {
		if !first {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprint(v))
		first = false
	}
	sb.WriteString("}")
	return sb.String()
}
