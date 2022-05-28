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
	RootManagementGroup  *ManagementGroup
	RootScopeId          string
	RootParentId         string
	DefaultLocation      string
	// These are not exported and only used on the initial load
	libArchetypeDefinitions []*LibArchetypeDefinition
	libArchetypeExtensions  []*LibArchetypeDefinition
	libArchetypeExclusions  []*LibArchetypeDefinition
	libManagementGroups     map[string]*LibManagementGroup
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
// They override any parameters defined in the policy assignment files.
type libArchetypeDefinitionConfig struct {
	Parameters    map[string]interface{} `json:"parameters"`
	AccessControl map[string]interface{} `json:"access_control"`
}

// Template is the structure that is used to represent the data fields in the templated files
type TemplateData struct {
	Current_scope_resource_id string
	Default_location          string
	Root_scope_id             string
	Root_scope_resource_id    string
	Private_dns_zone_prefix   string
}

// ManagementGroup represents an Azure Management Group, with links to parent and children.
type ManagementGroup struct {
	Name        string
	DisplayName string
	Archetype   ArchetypeDefinition
	children    []*ManagementGroup
	parent      *ManagementGroup
}

// LibManagementGroup represents an Azure Management Group definition file,
// it is used to construct the ManagementGroup struct hierarchy.
type LibManagementGroup struct {
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	ChildrenNames []string `json:"children"`
	ParentName    string   `json:"parent"`
	ArchetypeName string   `json:"archetype_name"`
	IsRoot        bool     `json:"is_root"`
}
