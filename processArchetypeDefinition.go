package alzlib

import (
	"encoding/json"
	"fmt"
)

func processArchetypeDefinition(az *AlzLib, data []byte) error {
	// Top level object key name is unknowable, so we need to unmarshal into a map
	parent := make(map[string]interface{})
	if err := json.Unmarshal(data, &parent); err != nil {
		return err
	}

	// check we only have 1 top level object
	if len(parent) != 1 {
		return fmt.Errorf("expected 1 top-level object, got %d", len(parent))
	}

	// We know there is one top level object, but we don't know what it's called, so use range
	for k := range parent {
		ad := libArchetypeDefinition{
			id: k,
		}

		child, err := json.Marshal(parent[k].(map[string]interface{}))
		if err != nil {
			return err
		}

		if err := json.Unmarshal(child, &ad); err != nil {
			return err
		}

		az.libArchetypeDefinitions = append(az.libArchetypeDefinitions, ad)
	}

	return nil
}
