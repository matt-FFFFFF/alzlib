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
const archetypeDefinitionPrefix = "archetype_definition_"
const policyAssignmentPrefix = "policy_assignment_"
const policyDefinitionPrefix = "policy_definition_"
const policySetDefinitionPrefix = "policy_set_definition_"

// NewAlzLib returns a new instance of the alzlib library
func NewAlzLib(dir string) (*AlzLib, error) {

	if err := checkDirExists(dir); err != nil {
		return nil, err
	}

	az := &AlzLib{
		PolicyDefinitions:       make(map[string]*armpolicy.Definition),
		PolicySetDefinitions:    make(map[string]*armpolicy.SetDefinition),
		PolicyAssignments:       make(map[string]*armpolicy.Assignment),
		Archetypes:              make(map[string]*ArchetypeDefinition),
		libArchetypeDefinitions: make([]*libArchetypeDefinition, 0),
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

	return az, nil
}

// checkDirExists checks if the supplied directory exists and is a directory
func checkDirExists(dir string) error {
	fs, err := os.Stat(dir)
	if err != nil {
		return err
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
	// anonymous func for now, will add functionality later
	case strings.HasPrefix(n, archetypeDefinitionPrefix):
		err = readAndProcessFile(az, path, processArchetypeDefinition)
	}

	// If there's an error, wrap it with the file path
	if err != nil {
		err = fmt.Errorf("error processing file %s: %s", path, err)
	}
	return err
}

// readAndProcessFile reads the file at the supplied path and processes it using the supplied processFunc
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

// generateArchetypes generates the archetype definitions from the supplied data
// in the libArchetypeDefinitions struct, PolicyDefinitions, PolicySetDefinitions, and PolicyAssignments maps
func (az *AlzLib) generateArchetypes() error {
	for _, ad := range az.libArchetypeDefinitions {

		// create the archetype
		if _, exists := az.Archetypes[ad.id]; exists {
			return fmt.Errorf("duplicate archetype id: %s", ad.id)
		}

		az.Archetypes[ad.id] = &ArchetypeDefinition{
			PolicyDefinitions:    make(map[string]armpolicy.Definition),
			PolicyAssignments:    make(map[string]armpolicy.Assignment),
			PolicySetDefinitions: make(map[string]armpolicy.SetDefinition),
		}

		// add the policy set definitions to the Archetype struct
		for _, ps := range ad.PolicySetDefinitions {
			if _, exists := az.Archetypes[ad.id].PolicySetDefinitions[ps]; exists {
				return fmt.Errorf("duplicate policy set definition in archetype %s: %s", ad.id, ps)
			}
			// look up the policy assignment to check we have it in the library
			p, ok := az.PolicySetDefinitions[ps]
			if !ok {
				return fmt.Errorf("policy set definition %s not found for archetype %s", ps, ad.id)
			}
			az.Archetypes[ad.id].PolicySetDefinitions[ps] = *p
		}

		// add the policy definitions to the Archetype struct
		for _, pd := range ad.PolicyDefinitions {
			if _, exists := az.Archetypes[ad.id].PolicyDefinitions[pd]; exists {
				return fmt.Errorf("duplicate policy definition in archetype %s: %s", ad.id, pd)
			}
			// look up the policy assignment to check we have it in the library
			p, ok := az.PolicyDefinitions[pd]
			if !ok {
				return fmt.Errorf("policy definition %s not found for archetype %s", pd, ad.id)
			}
			az.Archetypes[ad.id].PolicyDefinitions[pd] = *p
		}

		// add policy assignments to the Archetype struct
		for _, pa := range ad.PolicyAssignments {
			if _, exists := az.Archetypes[ad.id].PolicyAssignments[pa]; exists {
				return fmt.Errorf("duplicate policy assignment in archetype %s: %s", ad.id, pa)
			}
			// look up the policy assignment to check we have it in the library
			p, ok := az.PolicyAssignments[pa]
			if !ok {
				return fmt.Errorf("policy assignment %s not found for archetype %s", pa, ad.id)
			}
			az.Archetypes[ad.id].PolicyAssignments[pa] = *p
		}

	}
	return nil
}
