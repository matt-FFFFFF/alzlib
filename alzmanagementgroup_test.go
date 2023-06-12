package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

// TestGeneratePolicyAssignmentAdditionalRoleAssignments tests that the additional role assignments are generated correctly
// based on a set assignment and a definition assignment.
// It tests that the parameter values for the assignment are mapped correctly through the policy set, to the policy definition.
func TestGeneratePolicyAssignmentAdditionalRoleAssignments(t *testing.T) {
	// create a new AlzLib instance
	az := NewAlzLib()

	// create a new AlzManagementGroup instance
	alzmg := &AlzManagementGroup{
		AdditionalRoleAssignmentsByPolicyAssignment: make(map[string]*PolicyAssignmentAdditionalRoleAssignments),
	}

	// create a new policy assignment for the definition
	paDef := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg")},
				"parameter2": {Value: to.Ptr("value2")},
			},
		},
	}

	// create a new policy assignment for the definition
	paSetDef := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-set-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/test-policy-set-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"setparameter1": {Value: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg")},
				"setparameter2": {Value: to.Ptr("value2")},
			},
		},
	}

	ps := &armpolicy.SetDefinition{
		Name: to.Ptr("test-policy-set-definition"),
		Type: to.Ptr("Microsoft.Authorization/policySetDefinitions"),
		Properties: &armpolicy.SetDefinitionProperties{
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"setparameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
				"setparameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
				},
			},
			PolicyDefinitions: []*armpolicy.DefinitionReference{
				{
					PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition2"),
					Parameters: map[string]*armpolicy.ParameterValuesValue{
						"parameter1": {Value: to.Ptr("[parameters('setparameter1')]")},
						"parameter2": {Value: to.Ptr("[parameters('setparameter1')]")},
					},
				},
			},
		},
	}

	// create a new policy definition for direct assignment
	pd1 := &armpolicy.Definition{
		Name: to.Ptr("test-policy-definition"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyRule: map[string]any{
				"If": &map[string]any{
					"AllOf": []any{
						map[string]any{
							"Field": to.Ptr("type"),
							"Equals": []any{
								"Microsoft.Compute/virtualMachines",
							},
						},
					},
				},
				"then": map[string]any{
					"details": map[string]any{
						"roleDefinitionIds": []any{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"},
					},
				},
			},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"parameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
				"parameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(false),
					},
				},
			},
		},
	}

	// create a new policy definition for set assignment
	pd2 := &armpolicy.Definition{
		Name: to.Ptr("test-policy-definition2"),
		Properties: &armpolicy.DefinitionProperties{
			PolicyRule: map[string]any{
				"If": &map[string]any{
					"AllOf": []any{
						map[string]any{
							"Field": to.Ptr("type"),
							"Equals": []any{
								"Microsoft.Compute/virtualMachines",
							},
						},
					},
				},
				"then": map[string]any{
					"details": map[string]any{
						"roleDefinitionIds": []any{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition2"},
					},
				},
			},
			Parameters: map[string]*armpolicy.ParameterDefinitionsValue{
				"parameter1": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(true),
					},
				},
				"parameter2": {
					Type: to.Ptr(armpolicy.ParameterTypeString),
					Metadata: &armpolicy.ParameterDefinitionsValueMetadata{
						AssignPermissions: to.Ptr(false),
					},
				},
			},
		},
	}

	// add the policy (set) definitions and role definition to the AlzLib
	az.PolicyDefinitions[*pd1.Name] = pd1
	az.PolicyDefinitions[*pd2.Name] = pd2
	az.PolicySetDefinitions[*ps.Name] = ps

	// add the policy assignments to the AlzLib
	az.PolicyAssignments[*paDef.Name] = paDef
	az.PolicyAssignments[*paSetDef.Name] = paSetDef

	// generate the additional role assignments
	err := alzmg.GeneratePolicyAssignmentAdditionalRoleAssignments(az)

	// check that there were no errors
	assert.NoError(t, err)

	// check that the additional role assignments were generated correctly
	additionalRas, ok := alzmg.AdditionalRoleAssignmentsByPolicyAssignment[*paDef.Name]
	assert.True(t, ok)
	assert.Equal(t, []string{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"}, additionalRas.RoleDefinitionIds)
	assert.Equal(t, []string{*paDef.Properties.Parameters["parameter1"].Value.(*string)}, additionalRas.AdditionalScopes)
	additionalSetRas, ok := alzmg.AdditionalRoleAssignmentsByPolicyAssignment[*paSetDef.Name]
	assert.True(t, ok)
	assert.Equal(t, []string{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition2"}, additionalSetRas.RoleDefinitionIds)
	assert.Equal(t, []string{*paSetDef.Properties.Parameters["setparameter1"].Value.(*string)}, additionalSetRas.AdditionalScopes)
}
