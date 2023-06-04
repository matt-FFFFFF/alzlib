package alzlib

import (
	"embed"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/matt-FFFFFF/alzlib/processor"
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
		Archetypes:           make(map[string]*Archetype),
		PolicyAssignments:    make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:    make(map[string]*armpolicy.Definition),
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
	}

	res := new(processor.Result)
	pc := processor.NewProcessorClient(lib)
	if err := pc.Process(res); err != nil {
		return nil, fmt.Errorf("error processing built-in library: %s", err)
	}

	// Put results into the AlzLib

	// If we have a directory, process that too
	if dir == "" {
		return az, nil
	}

	localLib := os.DirFS(dir)
	pc = processor.NewProcessorClient(localLib)
	res = new(processor.Result)
	if err := pc.Process(res); err != nil {
		return nil, fmt.Errorf("error processing local library (%s): %s", dir, err)
	}

	// Put the results into the AlzLib

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
