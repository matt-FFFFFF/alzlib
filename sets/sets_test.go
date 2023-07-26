package sets_test

import (
	"fmt"
	"testing"

	"github.com/matt-FFFFFF/alzlib/sets"
)

func TestSet_Add(t *testing.T) {
	s := sets.NewSet(1, 2, 3)
	s.Add(4, 5)
	if !s.Contains(4) || !s.Contains(5) {
		t.Errorf("Set.Add failed to add elements to the set")
	}
}

func TestSet_Remove(t *testing.T) {
	s := sets.NewSet(1, 2, 3)
	s.Remove(2, 3)
	if s.Contains(2) || s.Contains(3) {
		t.Errorf("Set.Remove failed to remove elements from the set")
	}
}

func TestSet_Contains(t *testing.T) {
	s := sets.NewSet(1, 2, 3)
	if !s.Contains(2) {
		t.Errorf("Set.Contains failed to find an element in the set")
	}
	if s.Contains(4) {
		t.Errorf("Set.Contains found an element that is not in the set")
	}
}

func TestSet_Members(t *testing.T) {
	s := sets.NewSet(1, 2, 3)
	members := s.Members()
	if len(members) != 3 {
		t.Errorf("Set.Members returned an incorrect number of members")
	}
	if members[0] != 1 || members[1] != 2 || members[2] != 3 {
		t.Errorf(fmt.Sprintf("Set.Members returned incorrect members: %v, %v", s, members))
	}
}

func TestSet_Union(t *testing.T) {
	s1 := sets.NewSet(1, 2, 3)
	s2 := sets.NewSet(3, 4, 5)
	union := s1.Union(s2)
	if len(union) != 5 {
		t.Errorf("Set.Union returned an incorrect number of elements")
	}
	if !union.Contains(1) || !union.Contains(2) || !union.Contains(3) || !union.Contains(4) || !union.Contains(5) {
		t.Errorf("Set.Union returned incorrect elements")
	}
}

func TestSet_Intersection(t *testing.T) {
	s1 := sets.NewSet(1, 2, 3)
	s2 := sets.NewSet(3, 4, 5)
	intersection := s1.Intersection(s2)
	if len(intersection) != 1 {
		t.Errorf("Set.Intersection returned an incorrect number of elements")
	}
	if !intersection.Contains(3) {
		t.Errorf("Set.Intersection returned incorrect elements")
	}
}
