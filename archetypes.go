package alzlib

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

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
	if lad.Config != nil && lad.Config.Parameters != nil {
		for policy, params := range lad.Config.Parameters {
			// for each key, check if we have the same key in the az.Archetypes[lad.id].PolicyAssignments map
			if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[policy]; !exists {
				return fmt.Errorf("archetype_config.parameters error: cannot modify policy assignment %s, in archetype %s. policy %s does not exist", policy, lad.Id, policy)
			}

			// if we do, use type assertion to a get a map[string]{interface} and range over that map, the key being the parameter name and the value being the parameter value
			params, ok := params.(map[string]interface{})
			if !ok {
				return fmt.Errorf("policy assignment %s parameters are not a map", policy)
			}

			// range over the parameters
			for pk, pv := range params {
				// and test if the Policy Assignment.Properties.Parameters map has the same key (the parameter name)
				if _, exists := ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[policy].Properties.Parameters[pk]; !exists {
					return fmt.Errorf("archetype_config.parameters error: cannot modify policy parameter %s in assignment %s, in archetype %s. parameter %s does not exist", pk, policy, lad.Id, pk)
				}

				// if it does, create a new ParameterValuesValue, set the Value field to the value of the parameter in the archetype config
				// and set the ParameterValuesValue in the Policy Assignment.Properties.Parameters map to the new ParameterValuesValue
				ad.AlzLib.Archetypes[lad.Id].PolicyAssignments[policy].Properties.Parameters[pk] = &armpolicy.ParameterValuesValue{Value: pv}
			}
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
