package alzlib

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

type AlzLib struct {
	Archetypes           map[string]Archetype
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	// This is not exported and only used on the initial load
	libArchetypeDefinitions []libArchetypeDefinition
}

type Archetype struct {
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicyAssignments    map[string]*armpolicy.Assignment
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
}

type libArchetypeDefinition struct {
	id                   string
	PolicyAssignments    []string `json:"policy_assignments"`
	PolicyDefinitions    []string `json:"policy_definitions"`
	PolicySetDefinitions []string `json:"policy_set_definitions"`
}

type processFunc func(alzlib *AlzLib, data []byte) error
