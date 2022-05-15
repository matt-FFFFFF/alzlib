package alzlib

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func processArchetypeDefinition(az *AlzLib, data []byte) error {
	id, child, err := getArchetypeIdAndData(data)
	if err != nil {
		return fmt.Errorf("error processing archetype definition: %s", err)
	}
	ad := &libArchetypeDefinition{
		id: id,
	}
	if err := json.Unmarshal(child, &ad); err != nil {
		return fmt.Errorf("error processing archetype definition: %s", err)
	}
	az.libArchetypeDefinitions = append(az.libArchetypeDefinitions, ad)

	return nil
}

func processPolicyAssignment(az *AlzLib, data []byte) error {
	pa := &armpolicy.Assignment{}
	if err := json.Unmarshal(data, pa); err != nil {
		return fmt.Errorf("error unmarshalling policy assignment: %s", err)
	}
	if *pa.Name == "" {
		return fmt.Errorf("policy assignment name is empty")
	}
	az.PolicyAssignments[*pa.Name] = pa
	return nil
}

func processPolicyDefinition(az *AlzLib, data []byte) error {
	pd := &armpolicy.Definition{}
	if err := json.Unmarshal(data, pd); err != nil {
		return fmt.Errorf("error unmarshalling policy definition: %s", err)
	}
	if *pd.Name == "" {
		return fmt.Errorf("policy definition name is empty")
	}
	az.PolicyDefinitions[*pd.Name] = pd
	return nil
}

func processPolicySetDefinition(az *AlzLib, data []byte) error {
	psd := &armpolicy.SetDefinition{}
	if err := json.Unmarshal(data, psd); err != nil {
		return fmt.Errorf("error unmarshalling policy set definition: %s", err)
	}
	if *psd.Name == "" {
		return fmt.Errorf("policy set definition name is empty")
	}
	az.PolicySetDefinitions[*psd.Name] = psd
	return nil
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Helper funcs
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// getArchetypeIdAndData returns the archetype id and the json data for the archetype_definition file
// it is used because we do not know the JSON key name from the archetype definition file
func getArchetypeIdAndData(data []byte) (string, []byte, error) {
	// Top level object key name is unknowable, so we need to unmarshal into a map
	parent := make(map[string]interface{})
	child := make([]byte, 0)
	id := ""

	if err := json.Unmarshal(data, &parent); err != nil {
		return "", nil, err
	}

	// check we only have 1 top level object
	if len(parent) != 1 {
		return "", nil, fmt.Errorf("expected 1 top-level object, got %d", len(parent))
	}

	// We know there is one top level object, but we don't know what it's called, so use range
	for k := range parent {
		id = k
		c, err := json.Marshal(parent[k].(map[string]interface{}))
		if err != nil {
			return "", nil, err
		}
		child = c
	}
	return id, child, nil
}
