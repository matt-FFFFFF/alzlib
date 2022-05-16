package alzlib

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// processArchetypeDefinition is a processFunc that reads the archetype_definition
// bytes, processes, then adds the created LibArchetypeDefinition to the AlzLib
func processArchetypeDefinition(az *AlzLib, data []byte) error {
	lad, err := getLibArchetypeDefinition(data)
	if err != nil {
		return fmt.Errorf("error processing archetype definition: %s", err)
	}
	az.libArchetypeDefinitions = append(az.libArchetypeDefinitions, lad)
	return nil
}

// processArchetypeExtension is a processFunc that reads the archetype_extension
// bytes, processes, then adds the created LibArchetypeDefinition to the AlzLib
func processArchetypeExtension(az *AlzLib, data []byte) error {
	ext, err := getLibArchetypeDefinition(data)
	if err != nil {
		return fmt.Errorf("error processing archetype definition: %s", err)
	}
	// remove the prefix so that we can match the id to the definition
	ext.Id = strings.Replace(ext.Id, "extend_", "", 1)
	az.libArchetypeExtensions = append(az.libArchetypeExtensions, ext)
	return nil
}

// processArchetypeExtension is a processFunc that reads the archetype_exclusion
// bytes, processes, then adds the created LibArchetypeDefinition to the AlzLib
func processArchetypeExclusion(az *AlzLib, data []byte) error {
	excl, err := getLibArchetypeDefinition(data)
	if err != nil {
		return fmt.Errorf("error processing archetype definition: %s", err)
	}
	// remove the prefix so that we can match the id to the definition
	excl.Id = strings.Replace(excl.Id, "exclude_", "", 1)
	az.libArchetypeExclusions = append(az.libArchetypeExclusions, excl)
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_assignment
// bytes, processes, then adds the created armpolicy.Assignment to the AlzLib
func processPolicyAssignment(az *AlzLib, data []byte) error {
	pa := &armpolicy.Assignment{}
	if err := json.Unmarshal(data, pa); err != nil {
		return fmt.Errorf("error unmarshalling policy assignment: %s", err)
	}
	if pa.Name == nil || *pa.Name == "" {
		return fmt.Errorf("policy assignment name is empty or not present")
	}
	az.PolicyAssignments[*pa.Name] = pa
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_definition
// bytes, processes, then adds the created armpolicy.Definition to the AlzLib
func processPolicyDefinition(az *AlzLib, data []byte) error {
	pd := &armpolicy.Definition{}
	if err := json.Unmarshal(data, pd); err != nil {
		return fmt.Errorf("error unmarshalling policy definition: %s", err)
	}
	if pd.Name == nil || *pd.Name == "" {
		return fmt.Errorf("policy definition name is empty or not present")
	}
	az.PolicyDefinitions[*pd.Name] = pd
	return nil
}

// processPolicyAssignment is a processFunc that reads the policy_set_definition
// bytes, processes, then adds the created armpolicy.SetDefinition to the AlzLib
func processPolicySetDefinition(az *AlzLib, data []byte) error {
	psd := &armpolicy.SetDefinition{}
	if err := json.Unmarshal(data, psd); err != nil {
		return fmt.Errorf("error unmarshalling policy set definition: %s", err)
	}
	if psd.Name == nil || *psd.Name == "" {
		return fmt.Errorf("policy set definition name is empty or not present")
	}
	az.PolicySetDefinitions[*psd.Name] = psd
	return nil
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Helper funcs
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// getLibArchetypeDefinition returns the same from the bytes of the
// archetype_[definition,extension,exclusion] file
// it is used because we do not know the JSON key name from the archetype definition file
func getLibArchetypeDefinition(data []byte) (*LibArchetypeDefinition, error) {
	// Top level object key name is unknowable, so we need to unmarshal into a map
	parent := make(map[string]interface{})
	child := make([]byte, 0)
	id := ""

	if err := json.Unmarshal(data, &parent); err != nil {
		return nil, err
	}

	// check we only have 1 top level object
	if len(parent) != 1 {
		return nil, fmt.Errorf("expected 1 top-level object, got %d", len(parent))
	}

	// We know there is one top level object, but we don't know what it's called, so use range
	for k := range parent {
		id = k
		c, err := json.Marshal(parent[k].(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		child = c
	}
	ad := &LibArchetypeDefinition{
		Id: id,
	}
	if err := json.Unmarshal(child, &ad); err != nil {
		return nil, fmt.Errorf("error processing archetype definition: %s", err)
	}
	return ad, nil
}
