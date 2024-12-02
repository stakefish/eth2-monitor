package pkg

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
