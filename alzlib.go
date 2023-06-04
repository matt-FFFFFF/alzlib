package alzlib

import (
	"embed"
	"fmt"
	"io/fs"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

//go:embed lib
var lib embed.FS

// These are the file prefixes for the resource types
const (
	archetypeDefinitionPrefix = "archetype_definition_"
	policyAssignmentPrefix    = "policy_assignment_"
	policyDefinitionPrefix    = "policy_definition_"
	policySetDefinitionPrefix = "policy_set_definition_"
)

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
type AlzLib struct {
	Archetypes           map[string]*Archetype
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	RoleDefinitions      map[string]*armauthorization.RoleDefinition
	//	RootManagementGroup  *AlzManagementGroup
	// These are not exported and only used on the initial load
	libArchetypeDefinitions []*libArchetypeDefinition
}

// Archetype represents an archetype definition that hasn't been assigned to a management group
type Archetype struct {
	//AlzLib               *AlzLib
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicyAssignments    map[string]*armpolicy.Assignment
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	//RoleAssignments      map[string]*armauthorization.RoleAssignment
}

// AlzManagementGroup represents an Azure Management Group, with links to parent and children.
type AlzManagementGroup struct {
	Name                 string
	DisplayName          string
	PolicyDefinitions    map[string]armpolicy.Definition
	PolicySetDefinitions map[string]armpolicy.SetDefinition
	PolicyAssignments    map[string]armpolicy.Assignment
	RoleAssignments      map[string]armauthorization.RoleAssignment
	children             []*AlzManagementGroup
	parent               *AlzManagementGroup
}

// NewAlzLib returns a new instance of the alzlib library using the supplied directory
func NewAlzLib(dir string) (*AlzLib, error) {
	if dir != "" {
		if err := checkDirExists(dir); err != nil {
			return nil, err
		}
	}

	az := &AlzLib{
		Archetypes:              make(map[string]*Archetype),
		PolicyAssignments:       make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:       make(map[string]*armpolicy.Definition),
		PolicySetDefinitions:    make(map[string]*armpolicy.SetDefinition),
		libArchetypeDefinitions: make([]*libArchetypeDefinition, 0),
	}

	// Walk the embedded lib FS and process files
	if err := fs.WalkDir(lib, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory %s: %s", path, err)
		}
		// Skip directories
		if d.IsDir() {
			return nil
		}
		i, _ := d.Info()
		return az.processLibFile(path, i)
	}); err != nil {
		return nil, err
	}

	// if err := az.generateArchetypes(); err != nil {
	// 	return nil, fmt.Errorf("error generating archetypes: %s", err)
	// }

	// if err := az.generateManagementGroups(); err != nil {
	// 	return nil, fmt.Errorf("error generating management groups: %s", err)
	// }

	return az, nil
}

// checkDirExists checks if the supplied directory exists and is a directory
func checkDirExists(dir string) error {
	fs, err := os.Stat(dir)
	if err == os.ErrNotExist {
		return fmt.Errorf("the supplied lib directory does not exist: %s. %s", dir, err)
	}
	if err != nil {
		return fmt.Errorf("error checking lib dir exists: %s. %s", dir, err)
	}
	// The error is nil, so let's check if it's actually a directory
	if !fs.IsDir() {
		return fmt.Errorf("%s is not a directory and it should be", dir)
	}
	return nil
}
