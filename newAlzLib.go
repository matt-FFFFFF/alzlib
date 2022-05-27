package alzlib

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// These are the file prefixes for the resource types
const (
	archetypeDefinitionPrefix = "archetype_definition_"
	archetypeExclusionPrefix  = "archetype_exclusion_"
	archetypeExtensionPrefix  = "archetype_extension_"
	policyAssignmentPrefix    = "policy_assignment_"
	policyDefinitionPrefix    = "policy_definition_"
	policySetDefinitionPrefix = "policy_set_definition_"
	managementGroupPrefix     = "management_group_"
)

// NewAlzLib returns a new instance of the alzlib library using the supplied directory
func NewAlzLib(dir string) (*AlzLib, error) {
	if err := checkDirExists(dir); err != nil {
		return nil, err
	}

	az := &AlzLib{
		Archetypes:              make(map[string]*ArchetypeDefinition),
		PolicyAssignments:       make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:       make(map[string]*armpolicy.Definition),
		PolicySetDefinitions:    make(map[string]*armpolicy.SetDefinition),
		RootManagementGroup:     nil,
		libManagementGroups:     make(map[string]*LibManagementGroup),
		libArchetypeDefinitions: make([]*LibArchetypeDefinition, 0),
	}

	// Walk the directory and process files
	if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error walking directory %s: %s", dir, err)
		}
		// Skip directories
		if info.IsDir() {
			return nil
		}
		return az.processLibFile(path, info)
	}); err != nil {
		return nil, err
	}

	if err := az.generateArchetypes(); err != nil {
		return nil, fmt.Errorf("error generating archetypes: %s", err)
	}

	if err := az.generateManagementGroups(); err != nil {
		return nil, fmt.Errorf("error generating management groups: %s", err)
	}

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

	// if the file is an archetype exclusion
	case strings.HasPrefix(n, archetypeExclusionPrefix):
		err = readAndProcessFile(az, path, processArchetypeExclusion)

	// if the file is an archetype extension
	case strings.HasPrefix(n, archetypeExtensionPrefix):
		err = readAndProcessFile(az, path, processArchetypeExtension)

	// if the file is a management group
	case strings.HasPrefix(n, managementGroupPrefix):
		err = readAndProcessFile(az, path, processManagementGroup)
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
