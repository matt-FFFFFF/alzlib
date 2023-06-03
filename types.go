package alzlib

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

// LibArchetypeDefinition represents an archetype definition file,
// it used to construct the Archetype struct and is then added to the AlzLib struct
type LibArchetypeDefinition struct {
	Name                 string   `json:"name"`
	PolicyAssignments    []string `json:"policy_assignments"`
	PolicyDefinitions    []string `json:"policy_definitions"`
	PolicySetDefinitions []string `json:"policy_set_definitions"`
}

// AlzManagementGroup represents an Azure Management Group, with links to parent and children.
type AlzManagementGroup struct {
	Name                 string
	DisplayName          string
	PolicyDefinitions    map[string]armpolicy.Definition
	PolicySetDefinitions map[string]armpolicy.SetDefinition
	PolicyAssignments    map[string]armpolicy.Assignment
	children             []*AlzManagementGroup
	parent               *AlzManagementGroup
}
