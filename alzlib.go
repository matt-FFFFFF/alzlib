package alzlib

import (
	"embed"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"strings"

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
	Archetypes           map[string]*ArchetypeDefinition
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	RootManagementGroup  *AlzManagementGroup
	RootScopeId          string
	RootParentId         string
	DefaultLocation      string
	// These are not exported and only used on the initial load
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

// NewAlzLib returns a new instance of the alzlib library using the supplied directory
func NewAlzLib(dir string) (*AlzLib, error) {
	if dir != "" {
		if err := checkDirExists(dir); err != nil {
			return nil, err
		}
	}

	az := &AlzLib{
		Archetypes:              make(map[string]*ArchetypeDefinition),
		PolicyAssignments:       make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:       make(map[string]*armpolicy.Definition),
		PolicySetDefinitions:    make(map[string]*armpolicy.SetDefinition),
		RootManagementGroup:     nil,
		libArchetypeDefinitions: make([]*LibArchetypeDefinition, 0),
	}

	// Walk the directory and process files
	if err := fs.WalkDir(lib, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory %s: %s", dir, err)
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
	if err != nil {
		return fmt.Errorf("the supplied lib directory does not exist: %s. %s", dir, err)
	}
	// The error is nil, so let's check if it's actually a directory
	if !fs.IsDir() {
		return fmt.Errorf("%s is not a directory and it should be", dir)
	}
	return nil
}

// processLibFile processes the supplied file and adds the processed contents to the struct for validation later
func (az *AlzLib) processLibFile(path string, info fs.FileInfo) error {
	err := error(nil)
	// process by file type
	switch n := strings.ToLower(info.Name()); {

	// if the file is a policy definition
	case strings.HasPrefix(n, policyDefinitionPrefix):
		err = readAndProcessFile(az, path, processPolicyDefinition)

	// if the file is a policy set definition
	case strings.HasPrefix(n, policySetDefinitionPrefix):
		err = readAndProcessFile(az, path, processPolicySetDefinition)

	// if the file is a policy assignment
	case strings.HasPrefix(n, policyAssignmentPrefix):
		err = readAndProcessFile(az, path, processPolicyAssignment)

	// if the file is an archetype definition
	case strings.HasPrefix(n, archetypeDefinitionPrefix):
		err = readAndProcessFile(az, path, processArchetypeDefinition)
	}

	// If there's an error, wrap it with the file path
	if err != nil {
		err = fmt.Errorf("error processing file %s: %s", path, err)
	}
	return err
}

// readAndProcessFile reads the file bytes at the supplied path and processes it using the supplied processFunc
func readAndProcessFile(az *AlzLib, path string, processFn processFunc) error {
	// open the file and read the contents
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	// pass the  data to the supplied process function
	if err := processFn(az, data); err != nil {
		return err
	}

	return nil
}
