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
const archetypeExclusionPrefix = "archetype_exclusion_"
const archetypeExtensionPrefix = "archetype_extension_"
const policyAssignmentPrefix = "policy_assignment_"
const policyDefinitionPrefix = "policy_definition_"
const policySetDefinitionPrefix = "policy_set_definition_"

// NewAlzLib returns a new instance of the alzlib library
func NewAlzLib(dir string) (*AlzLib, error) {
	if err := checkDirExists(dir); err != nil {
		return nil, err
	}

	az := &AlzLib{
		Archetypes:              make(map[string]*ArchetypeDefinition),
		PolicyAssignments:       make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:       make(map[string]*armpolicy.Definition),
		PolicySetDefinitions:    make(map[string]*armpolicy.SetDefinition),
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
	case strings.HasPrefix(n, archetypeDefinitionPrefix):
		err = readAndProcessFile(az, path, processArchetypeDefinition)

	// if the file is an archetype exclusion
	case strings.HasPrefix(n, archetypeExclusionPrefix):
		err = readAndProcessFile(az, path, processArchetypeExclusion)

	// if the file is an archetype extension
	case strings.HasPrefix(n, archetypeExtensionPrefix):
		err = readAndProcessFile(az, path, processArchetypeExtension)
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

// generateArchetypes generates the archetype definitions from the supplied data
// in the libArchetypeDefinitions struct, PolicyDefinitions, PolicySetDefinitions, and PolicyAssignments maps
func (az *AlzLib) generateArchetypes() error {
	// Generate the initial ArchetypeDefinitions from the libArchetypeDefinitions map
	for _, lad := range az.libArchetypeDefinitions {
		// create the archetype and add it to the AlzLib
		if _, exists := az.Archetypes[lad.Id]; exists {
			return fmt.Errorf("duplicate archetype id: %s", lad.Id)
		}

		// Create the new archetype and add it to the AlzLib struct, then process the lib archetype definition
		// to populate the new archetype definition.
		//
		// This process will create copies of the policy definitions, policy set definitions, and policy assignments
		// They will then be modified based on the archetype_config in the lib archetype definition
		az.Archetypes[lad.Id] = newArchetypeDefinition(az)
		if err := az.Archetypes[lad.Id].AddLibArchetype(lad); err != nil {
			return err
		}
	}

	// Extend the ArchetypeDefinitions with the libArchetypeExtensions slice
	for _, ext := range az.libArchetypeExtensions {
		if err := az.Archetypes[ext.Id].AddLibArchetype(ext); err != nil {
			return err
		}
	}

	// Exclude from the ArchetypeDefinitions with the libArchetypeExclusions slice
	for _, excl := range az.libArchetypeExclusions {
		if err := az.Archetypes[excl.Id].RemoveLibArchetype(excl); err != nil {
			return err
		}
	}

	return nil
}

// newArchetypeDefinition creates a new archetype definition linked to the supplied AlzLib
func newArchetypeDefinition(az *AlzLib) *ArchetypeDefinition {
	return &ArchetypeDefinition{
		AlzLib:               az,
		PolicyDefinitions:    make(map[string]armpolicy.Definition),
		PolicyAssignments:    make(map[string]armpolicy.Assignment),
		PolicySetDefinitions: make(map[string]armpolicy.SetDefinition),
	}
}

// AddLibArchetype method add the supplied lib archetype definition to the archetype definition.
// This is used at the initial processing of the lib directory as well as for archetype extensions.
func (ad *ArchetypeDefinition) AddLibArchetype(lad *LibArchetypeDefinition) error {
	// add the policy set definitions to the Archetype struct
	// range over the strings in in the libArchetypeDefinition array
	for _, ps := range lad.PolicySetDefinitions {
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicySetDefinitions[ps]; exists {
			return fmt.Errorf("duplicate policy set definition in archetype %s: %s", lad.Id, ps)
		}
		// look up the policy set definition to check we have it in the library
		p, ok := ad.AlzLib.PolicySetDefinitions[ps]
		if !ok {
			return fmt.Errorf("policy set definition %s not found for archetype %s", ps, lad.Id)
		}
		ad.AlzLib.Archetypes[lad.Id].PolicySetDefinitions[ps] = *p
	}

	// add the policy definitions to the Archetype struct
	// range over the strings in in the libArchetypeDefinition array
	for _, pd := range lad.PolicyDefinitions {
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyDefinitions[pd]; exists {
			return fmt.Errorf("duplicate policy definition in archetype %s: %s", lad.Id, pd)
		}
		// look up the policy definitions to check we have it in the library
		p, ok := ad.AlzLib.PolicyDefinitions[pd]
		if !ok {
			return fmt.Errorf("policy definition %s not found for archetype %s", pd, lad.Id)
		}
		ad.AlzLib.Archetypes[lad.Id].PolicyDefinitions[pd] = *p
	}

	// add the policy assignments to the Archetype struct
	// range over the strings in in the libArchetypeDefinition array
	for _, pa := range lad.PolicyAssignments {
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[pa]; exists {
			return fmt.Errorf("duplicate policy assignment in archetype %s: %s", lad.Id, pa)
		}
		// look up the policy assignment to check we have it in the library
		p, ok := ad.AlzLib.PolicyAssignments[pa]
		if !ok {
			return fmt.Errorf("policy assignment %s not found for archetype %s", pa, lad.Id)
		}
		ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[pa] = *p
	}

	// Update policy assignment properties with any defined in the archetype config
	// range over the parameters map, getting the name of the policy assignment using the key
	// TODO: test if this exists!
	for policy, params := range lad.Config.Parameters {
		// for each key, check if we have the same key in the az.Archetypes[lad.id].PolicyAssignments map
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[policy]; !exists {
			continue
		}

		// if we do, cast the value to a map[string]{interface} and range over that map, the key being the parameter name and the value being the parameter value
		params, ok := params.(map[string]interface{})
		if !ok {
			return fmt.Errorf("policy assignment %s parameters are not a map", policy)
		}

		// range over the parameters
		for pk, pv := range params {
			// and test if the Policy Assignment.Properties.Parameters map has the same key (the parameter name)
			if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[policy].Properties.Parameters[pk]; !exists {
				continue
			}

			// if it does, create a new ParameterValuesValue, set the Value field to the value of the parameter in the archetype config
			// and set the ParameterValuesValue in the Policy Assignment.Properties.Parameters map to the new ParameterValuesValue
			ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[policy].Properties.Parameters[pk] = &armpolicy.ParameterValuesValue{Value: pv}
		}
	}
	return nil
}

// AddLibArchetype method add the supplied lib archetype definition to the archetype definition.
// This is used at the initial processing of the lib directory as well as for archetype extensions.
func (ad *ArchetypeDefinition) RemoveLibArchetype(lad *LibArchetypeDefinition) error {
	// remove the policy set definitions to the Archetype struct
	// range over the strings in in the libArchetypeDefinition array
	for _, ps := range lad.PolicySetDefinitions {
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicySetDefinitions[ps]; !exists {
			return fmt.Errorf("cannot exclude policy set %s from archetype %s as it does not exist", ps, lad.Id)
		}
		// remove the policy set definition
		delete(ad.AlzLib.Archetypes[lad.Id].PolicySetDefinitions, ps)
	}

	// add the policy definitions to the Archetype struct
	// range over the strings in in the libArchetypeDefinition array
	for _, pd := range lad.PolicyDefinitions {
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyDefinitions[pd]; !exists {
			return fmt.Errorf("cannot exclude policy definition %s from archetype %s as it does not exist", pd, lad.Id)
		}
		// remove the policy definition
		delete(ad.AlzLib.Archetypes[lad.Id].PolicyDefinitions, pd)
	}

	// add the policy assignments to the Archetype struct
	// range over the strings in in the libArchetypeDefinition array
	for _, pa := range lad.PolicyAssignments {
		if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[pa]; !exists {
			return fmt.Errorf("cannot exclude policy assignment %s from archetype %s as it does not exist", pa, lad.Id)
		}
		// remove the policy assignment
		delete(ad.AlzLib.Archetypes[lad.Id].PolicyAssignments, pa)
	}
	return nil
}
