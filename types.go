package alzlib

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// processFunc is the function signature that is used to process different types of lib file
type processFunc func(alzlib *AlzLib, data []byte) error

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
type AlzLib struct {
	Archetypes           map[string]*ArchetypeDefinition
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	// This is not exported and only used on the initial load
	libArchetypeDefinitions []*LibArchetypeDefinition
	libArchetypeExtensions  []*LibArchetypeDefinition
	libArchetypeExclusions  []*LibArchetypeDefinition
}

// ArchetypeDefinition represents an archetype definition that hasn't been assigned to a management group
// maps contain values, rather than pointers, because we don't want to modify the original
type ArchetypeDefinition struct {
	AlzLib               *AlzLib
	PolicyDefinitions    map[string]armpolicy.Definition
	PolicyAssignments    map[string]armpolicy.Assignment
	PolicySetDefinitions map[string]armpolicy.SetDefinition
}

// LibArchetypeDefinition represents an archetype definition file,
// it used to construct the Archetype struct and is then added to the AlzLib struct
type LibArchetypeDefinition struct {
	Id                   string
	Config               *libArchetypeDefinitionConfig `json:"archetype_config"`
	PolicyAssignments    []string                      `json:"policy_assignments"`
	PolicyDefinitions    []string                      `json:"policy_definitions"`
	PolicySetDefinitions []string                      `json:"policy_set_definitions"`
}

// libArchetypeConfig is a representation of the archetype_config parameters
// that are used in the archetype definition files.
// .
// They override any paremeters defined in the policy assignment files.
type libArchetypeDefinitionConfig struct {
	Parameters    map[string]interface{} `json:"parameters"`
	AccessControl map[string]interface{} `json:"access_control"`
}
