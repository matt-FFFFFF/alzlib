// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"encoding/json"
	"fmt"
	"strings"

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
	parentExternal                              *string
}

// PolicyAssignmentAdditionalRoleAssignments represents the additional role assignments that need to be created for a management group.
// Since we could be using system assigned identities, we don't know the principal ID until after the deployment.
// Therefore this data can be used to create the role assignments after the deployment.
type PolicyAssignmentAdditionalRoleAssignments struct {
	RoleDefinitionIds []string
	AdditionalScopes  []string
}

// GetChildren returns the children of the management group.
func (alzmg *AlzManagementGroup) GetChildren() []*AlzManagementGroup {
	return alzmg.children
}

// GetParentId returns the ID of the parent management group.
// If the parent is external, this will be preferred.
// If neither are set an empty string is returned (though this should never happen).
func (alzmg *AlzManagementGroup) GetParentId() string {
	if alzmg.parentExternal != nil {
		return *alzmg.parentExternal
	}
	if alzmg.parent != nil {
		return alzmg.parent.Name
	}
	return ""
}

// GetParentMg returns parent *AlzManagementGroup.
// If the parent is external, the result will be nil
func (alzmg *AlzManagementGroup) GetParentMg() *AlzManagementGroup {
	if alzmg.parentExternal != nil {
		return nil
	}
	return alzmg.parent
}

// ParentIsExternal returns a bool value depending on whether the parent MG is external or not.
func (alzmg *AlzManagementGroup) ParentIsExternal() bool {
	if alzmg.parentExternal != nil && *alzmg.parentExternal != "" {
		return true
	}
	return false
}

// ResourceId returns the resource ID of the management group.
func (alzmg *AlzManagementGroup) ResourceId() string {
	return fmt.Sprintf(managementGroupIdFmt, alzmg.Name)
}

// PolicyDefinitionRule represents the rule section of a policy definition.
// This is used to determine the role assignments that need to be created,
// therefore we only care about the `then` field.
type PolicyDefinitionRule struct {
	Then *PolicyDefinitionRuleThen `json:"then"`
}

// PolicyDefinitionRuleThen represents the `then` section of a policy definition rule.
// This is used to determine the role assignments that need to be created.
// We only care about the `details` field.
type PolicyDefinitionRuleThen struct {
	Details *PolicyDefinitionRuleThenDetails `json:"details"`
}

// PolicyDefinitionRuleThenDetails represents the `details` section of a policy definition rule `then` section.
// This is used to determine the role assignments that need to be created.
// We only care about the `roleDefinitionIds` field.
type PolicyDefinitionRuleThenDetails struct {
	RoleDefinitionIds []string `json:"roleDefinitionIds"`
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
				paParamVal, err := getPolicyAssignmentParametersValueValue(pa, paramName)
				if err != nil {
					continue
				}
				additionalRas.AdditionalScopes = appendIfMissing[string](additionalRas.AdditionalScopes, paParamVal)
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

					// if the parameter in the assignment doesn't exist, skip it
					paParamVal, err := getPolicyAssignmentParametersValueValue(pa, paParamName)
					if err != nil {
						continue
					}
					additionalRas.AdditionalScopes = appendIfMissing[string](additionalRas.AdditionalScopes, paParamVal)
				}
			}
		}
		alzmg.AdditionalRoleAssignmentsByPolicyAssignment[paName] = additionalRas
	}

	return nil
}

func (alzmg *AlzManagementGroup) GetResourceId() string {
	return fmt.Sprintf(managementGroupIdFmt, alzmg.Name)
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

// getPolicyDefRoleDefinitionIds returns the role definition ids referenced in a policy definition
// if they exist.
// We marshall the policyRule as JSON and then unmarshal into a custom type
func getPolicyDefRoleDefinitionIds(rule any) ([]string, error) {
	j, err := json.Marshal(rule)
	if err != nil {
		return nil, fmt.Errorf("could not marshall policy rule: %w", err)
	}
	r := new(PolicyDefinitionRule)
	if err := json.Unmarshal(j, r); err != nil {
		return nil, fmt.Errorf("could not unmarshall policy rule: %w", err)
	}
	if r.Then.Details == nil || r.Then.Details.RoleDefinitionIds == nil || len(r.Then.Details.RoleDefinitionIds) == 0 {
		return []string{}, nil
	}
	return r.Then.Details.RoleDefinitionIds, nil
}

func getPolicyAssignmentParametersValueValue(pa *armpolicy.Assignment, paramname string) (string, error) {
	if pa.Properties.Parameters == nil {
		return "", fmt.Errorf("parameters is nil in policy assignment %s", *pa.Name)
	}
	paParamVal, ok := pa.Properties.Parameters[paramname]
	if !ok {
		return "", fmt.Errorf("parameter %s not found in policy assignment %s", paramname, *pa.Name)
	}
	if paParamVal.Value == nil {
		return "", fmt.Errorf("parameter %s value field in policy assignment %s is nil", paramname, *pa.Name)
	}
	paParamValStr, ok := paParamVal.Value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %s value in policy assignment %s is not a string", paramname, *pa.Name)
	}
	return paParamValStr, nil
}
