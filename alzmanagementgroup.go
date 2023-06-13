// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// AlzManagementGroup represents an Azure Management Group within a hierarchy, with links to parent and children.
type AlzManagementGroup struct {
	Name                                        string
	DisplayName                                 string
	PolicyDefinitions                           map[string]*armpolicy.Definition
	PolicySetDefinitions                        map[string]*armpolicy.SetDefinition
	PolicyAssignments                           map[string]*armpolicy.Assignment
	RoleDefinitions                             map[string]*armauthorization.RoleDefinition
	RoleAssignments                             map[string]*armauthorization.RoleAssignment
	AdditionalRoleAssignmentsByPolicyAssignment map[string]*PolicyAssignmentAdditionalRoleAssignments
	children                                    []*AlzManagementGroup
	parent                                      *AlzManagementGroup
}

type PolicyAssignmentAdditionalRoleAssignments struct {
	RoleDefinitionIds []string
	AdditionalScopes  []string
}

func (alzmg *AlzManagementGroup) GetChildren() []*AlzManagementGroup {
	return alzmg.children
}

func (alzmg *AlzManagementGroup) GetParent() *AlzManagementGroup {
	return alzmg.parent
}

func (alzmg *AlzManagementGroup) ResourceId() string {
	return fmt.Sprintf(managementGroupIdFmt, alzmg.Name)
}

// GeneratePolicyAssignmentAdditionalRoleAssignments generates the additional role assignment data needed for the policy assignments
// It should be run once the policy assignments map has been fully populated for a given ALZManagementGroup.
// It will iterate through all policy assignments and generate the additional role assignments for each one,
// storing them in the AdditionalRoleAssignmentsByPolicyAssignment map.
func (alzmg *AlzManagementGroup) GeneratePolicyAssignmentAdditionalRoleAssignments(az *AlzLib) error {
	for paName, pa := range alzmg.PolicyAssignments {
		// we only care about policy assignments that use an identity
		if pa.Identity == nil || pa.Identity.Type == nil || *pa.Identity.Type == "None" {
			continue
		}

		additionalRas := new(PolicyAssignmentAdditionalRoleAssignments)
		additionalRas.RoleDefinitionIds = make([]string, 0)
		additionalRas.AdditionalScopes = make([]string, 0)

		// get the policy definition name using the resource id
		defId := pa.Properties.PolicyDefinitionID

		switch lastButOneSegment(*defId) {
		case "policyDefinitions":
			// check the definition exists in the AlzLib
			pd, ok := az.PolicyDefinitions[lastSegment(*defId)]
			if !ok {
				return fmt.Errorf("policy definition %s not found in AlzLib", lastSegment(*defId))
			}

			// get the role definition ids from the policy definition and add to the additional role assignment data
			rids, err := getPolicyDefRoleDefinitionIds(pd.Properties.PolicyRule)
			if err != nil {
				return fmt.Errorf("error getting role definition ids for policy definition %s: %w", *pd.Name, err)
			}
			if len(rids) == 0 {
				return fmt.Errorf("policy definition %s has no role definition ids", *pd.Name)
			}
			for _, rid := range rids {
				additionalRas.RoleDefinitionIds = appendIfMissing[string](additionalRas.RoleDefinitionIds, rid)
			}

			// for each parameter with assignPermissions = true
			// add the additional role assignment data
			for paramName, paramVal := range pd.Properties.Parameters {
				if paramVal.Metadata == nil || paramVal.Metadata.AssignPermissions == nil || !*paramVal.Metadata.AssignPermissions {
					continue
				}

				val := pa.Properties.Parameters[paramName].Value
				valStr, ok := val.(string)
				if !ok {
					return fmt.Errorf("parameter %s value in policy assignment %s is not a string", paramName, *pa.Name)
				}
				additionalRas.AdditionalScopes = appendIfMissing[string](additionalRas.AdditionalScopes, valStr)
			}

		case "policySetDefinitions":
			psd, ok := az.PolicySetDefinitions[lastSegment(*defId)]
			if !ok {
				return fmt.Errorf("policy set definition %s not found in AlzLib", lastSegment(*defId))
			}

			// for each policy definition in the policy set definition
			for _, pdref := range psd.Properties.PolicyDefinitions {
				pdName := lastSegment(*pdref.PolicyDefinitionID)
				pd, ok := az.PolicyDefinitions[pdName]
				if !ok {
					return fmt.Errorf("policy definition %s, referenced by %s not found in AlzLib", pdName, *psd.Name)
				}

				// get the role definition ids from the policy definition and add to the additional role assignment data
				rids, err := getPolicyDefRoleDefinitionIds(pd.Properties.PolicyRule)
				if err != nil {
					return fmt.Errorf("error getting role definition ids for policy definition %s: %w", *pd.Name, err)
				}
				if len(rids) == 0 {
					return fmt.Errorf("policy definition %s, refernced by %s has no role definition ids", *pd.Name, *psd.Name)
				}
				for _, rid := range rids {
					additionalRas.RoleDefinitionIds = appendIfMissing[string](additionalRas.RoleDefinitionIds, rid)
				}

				// for each parameter with assignPermissions = true
				// add the additional scopes to the additional role assignment data
				// to do this we have to map the assignment parameter value to the policy definition parameter value
				for paramName, paramVal := range pd.Properties.Parameters {
					if paramVal.Metadata == nil || paramVal.Metadata.AssignPermissions == nil || !*paramVal.Metadata.AssignPermissions {
						continue
					}
					// get the parameter value from the policy reference within the set definition
					if _, ok := pdref.Parameters[paramName]; !ok {
						return fmt.Errorf("parameter %s not found in policy definition %s", paramName, *pd.Name)
					}
					pdrefParamVal := pdref.Parameters[paramName].Value
					pdrefParamValStr, ok := pdrefParamVal.(string)
					if !ok {
						return fmt.Errorf("parameter %s value in policy definition %s is not a string", paramName, *pd.Name)
					}
					// extract the assignment exposed policy set parameter name from the ARM function used in the policy definition reference
					paParamName, err := extractParameterNameFromArmFunction(pdrefParamValStr)
					if err != nil {
						return err
					}
					// get the parameter value from the assignment, check that it's a string and an ARM resource id
					paParmVal, ok := pa.Properties.Parameters[paParamName]
					if !ok {
						return fmt.Errorf("parameter %s not found in policy assignment %s", paParamName, *pa.Name)
					}
					paParamValStr, ok := paParmVal.Value.(string)
					if !ok {
						return fmt.Errorf("parameter %s value in policy assignment %s is not a string", paParamName, *pa.Name)
					}
					if _, err := arm.ParseResourceID(paParamValStr); err != nil {
						return fmt.Errorf("parameter %s value in policy assignment %s is not an ARM resource id", paParamName, *pa.Name)
					}
					additionalRas.AdditionalScopes = appendIfMissing[string](additionalRas.AdditionalScopes, paParamValStr)
				}
			}
		}
		alzmg.AdditionalRoleAssignmentsByPolicyAssignment[paName] = additionalRas
	}

	return nil
}

func modifyPolicyDefinitions(alzmg *AlzManagementGroup) {
	for k, v := range alzmg.PolicyDefinitions {
		v.ID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, alzmg.Name, k))
	}
}

// These for loops re-write the referenced policy definition resource IDs
// for all policy sets.
// It looks up the policy definition names that are in all archetypes in the Deployment.
// If it is found, the definition reference id is re-written with the correct management group name.
// If it is not found, we assume that it's built-in.
func modifyPolicySetDefinitions(alzmg *AlzManagementGroup, pd2mg map[string]string) {
	for k, v := range alzmg.PolicySetDefinitions {
		v.ID = to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, alzmg.Name, k))
		for _, pd := range v.Properties.PolicyDefinitions {
			pdname := lastSegment(*pd.PolicyDefinitionID)
			if mgname, ok := pd2mg[pdname]; ok {
				pd.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, mgname, pdname))
			}
		}
	}
}

func modifyPolicyAssignments(alzmg *AlzManagementGroup, pd2mg, psd2mg map[string]string, opts *WellKnownPolicyValues) error {
	for assignmentName, assignment := range alzmg.PolicyAssignments {
		assignment.ID = to.Ptr(fmt.Sprintf(policyAssignmentIdFmt, alzmg.Name, assignmentName))
		assignment.Properties.Scope = to.Ptr(fmt.Sprintf(managementGroupIdFmt, alzmg.Name))
		if assignment.Location != nil {
			assignment.Location = to.Ptr(opts.DefaultLocation)
		}

		// rewrite the referenced policy definition id
		pd := assignment.Properties.PolicyDefinitionID
		switch lastButOneSegment(*pd) {
		case "policyDefinitions":
			if mgname, ok := pd2mg[lastSegment(*pd)]; ok {
				assignment.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, mgname, lastSegment(*pd)))
			}
		case "policySetDefinitions":
			if mgname, ok := psd2mg[lastSegment(*pd)]; ok {
				assignment.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, mgname, lastSegment(*pd)))
			}
		default:
			return fmt.Errorf("policy assignment %s has invalid resource type in id %s", assignmentName, *pd)
		}
	}
	return nil
}

func modifyRoleDefinitions(alzmg *AlzManagementGroup) {
	for _, roledef := range alzmg.RoleDefinitions {
		u := uuidV5(alzmg.Name, *roledef.Name)
		roledef.ID = to.Ptr(fmt.Sprintf(roleDefinitionIdFmt, alzmg.Name, u))
		if roledef.Properties.AssignableScopes == nil || len(roledef.Properties.AssignableScopes) == 0 {
			roledef.Properties.AssignableScopes = make([]*string, 1)
		}
		roledef.Properties.AssignableScopes[0] = to.Ptr(fmt.Sprintf(managementGroupIdFmt, alzmg.Name))
	}
}

// appendIfMissing appends the value to the slice if it is not already in the slice
func appendIfMissing[E comparable](slice []E, v E) []E {
	for _, e := range slice {
		if e == v {
			return slice
		}
	}
	return append(slice, v)
}

func extractParameterNameFromArmFunction(value string) (string, error) {
	// value is of the form "[parameters('parameterName')]"
	if !strings.HasPrefix(value, "[parameters('") || !strings.HasSuffix(value, "')]") {
		return "", fmt.Errorf("value is not a parameter reference")
	}
	return value[13 : len(value)-3], nil
}
