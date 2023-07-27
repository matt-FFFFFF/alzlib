// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// package sets is used to provide set like functionality for the library.
package sets

import "fmt"

// Set is a set of comparable elements.
type Set[E comparable] map[E]struct{}

// NewSet creates a new set.
func NewSet[E comparable](vals ...E) Set[E] {
	s := Set[E]{}
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

// Add adds elements to the set.
func (s Set[E]) Add(vals ...E) {
	for _, v := range vals {
		s[v] = struct{}{}
	}
}

// Remove deletes elements from the set.
func (s Set[E]) Remove(vals ...E) {
	for _, v := range vals {
		if _, exists := s[v]; !exists {
			continue
		}
		delete(s, v)
	}
}

// Contains returns true if the set contains the element.
func (s Set[E]) Contains(v E) bool {
	_, ok := s[v]
	return ok
}

// Members returns the members of the set.
func (s Set[E]) Members() []E {
	result := make([]E, 0, len(s))
	for v := range s {
		result = append(result, v)
	}
	return result
}

// String implements the Stringer interface.
func (s Set[E]) String() string {
	return fmt.Sprintf("%v", s.Members())
}

// Union returns the union of two sets.
func (s Set[E]) Union(s2 Set[E]) Set[E] {
	result := NewSet(s.Members()...)
	result.Add(s2.Members()...)
	return result
}

// Intersection returns the intersection of two sets.
func (s Set[E]) Intersection(s2 Set[E]) Set[E] {
	result := NewSet[E]()
	for _, v := range s.Members() {
		if s2.Contains(v) {
			result.Add(v)
		}
	}
	return result
}
