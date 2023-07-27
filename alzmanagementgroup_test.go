package alzlib

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/matt-FFFFFF/alzlib/to"
	"github.com/stretchr/testify/assert"
)

func TestE2E(t *testing.T) {
	az := NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, err := armpolicy.NewClientFactory("", cred, nil)
	assert.NoError(t, err)
	az.AddPolicyClient(cf)
	assert.NoError(t, az.Init(ctx, Lib))
	vals := &WellKnownPolicyValues{
		DefaultLocation:                "eastus",
		DefaultLogAnalyticsWorkspaceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.OperationalInsights/workspaces/testlaworkspaceid",
	}
	arch, err := az.CopyArchetype("root", vals)
	assert.NoError(t, err)
	assert.NoError(t, az.AddManagementGroupToDeployment("root", "root", "external", true, arch))
	err = az.Deployment.MGs["root"].GeneratePolicyAssignmentAdditionalRoleAssignments(az)
	assert.NoError(t, err)
}

func TestGeneratePolicyAssignmentAdditionalRoleAssignments(t *testing.T) {
	t.Parallel()
	// create a new AlzLib instance.
	az := NewAlzLib()

	// create a new AlzManagementGroup instance.
	alzmg := &AlzManagementGroup{
		AdditionalRoleAssignmentsByPolicyAssignment: make(map[string]*PolicyAssignmentAdditionalRoleAssignments),
		PolicyDefinitions:    make(map[string]*armpolicy.Definition),
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		PolicyAssignments:    make(map[string]*armpolicy.Assignment),
	}

	// create a new policy assignment for the definition.
	paDef := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policyDefinitions/test-policy-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"parameter1": {Value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg"},
				"parameter2": {Value: "value2"},
			},
		},
	}

	// create a new policy assignment for the definition.
	paSetDef := &armpolicy.Assignment{
		Name: to.Ptr("test-policy-set-assignment"),
		Type: to.Ptr("Microsoft.Authorization/policyAssignments"),

		Identity: &armpolicy.Identity{Type: to.Ptr(armpolicy.ResourceIdentityTypeSystemAssigned)},
		Properties: &armpolicy.AssignmentProperties{
			PolicyDefinitionID: to.Ptr("/providers/Microsoft.Authorization/policySetDefinitions/test-policy-set-definition"),
			Parameters: map[string]*armpolicy.ParameterValuesValue{
				"setparameter1": {Value: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg"},
				"setparameter2": {Value: "value2"},
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
						"parameter1": {Value: "[parameters('setparameter1')]"},
						"parameter2": {Value: "[parameters('setparameter1')]"},
					},
				},
			},
		},
	}

	// create a new policy definition for direct assignment.
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

	// create a new policy definition for set assignment.
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

	// add the policy (set) definitions to the arch.
	alzmg.PolicyDefinitions[*pd1.Name] = pd1
	alzmg.PolicyDefinitions[*pd2.Name] = pd2
	alzmg.PolicySetDefinitions[*ps.Name] = ps

	// add the policy assignments to the arch.
	alzmg.PolicyAssignments[*paDef.Name] = paDef
	alzmg.PolicyAssignments[*paSetDef.Name] = paSetDef

	// add the policy (set) definitions to the alzlib.
	az.policyDefinitions[*pd2.Name] = pd2
	az.policyDefinitions[*pd1.Name] = pd1
	az.policySetDefinitions[*ps.Name] = ps
	// add the policy assignments to the arch.
	az.policyAssignments[*paDef.Name] = paDef
	az.policyAssignments[*paSetDef.Name] = paSetDef

	// generate the additional role assignments.
	err := alzmg.GeneratePolicyAssignmentAdditionalRoleAssignments(az)

	// check that there were no errors.
	assert.NoError(t, err)

	// check that the additional role assignments were generated correctly.
	additionalRas, ok := alzmg.AdditionalRoleAssignmentsByPolicyAssignment[*paDef.Name]
	assert.True(t, ok)
	assert.Equal(t, []string{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition"}, additionalRas.RoleDefinitionIds.Members())
	assert.Equal(t, []string{paDef.Properties.Parameters["parameter1"].Value.(string)}, additionalRas.AdditionalScopes.Members()) //nolint:forcetypeassert
	additionalSetRas, ok := alzmg.AdditionalRoleAssignmentsByPolicyAssignment[*paSetDef.Name]
	assert.True(t, ok)
	assert.Equal(t, []string{"/providers/Microsoft.Authorization/roleDefinitions/test-role-definition2"}, additionalSetRas.RoleDefinitionIds.Members())
	assert.Equal(t, []string{paSetDef.Properties.Parameters["setparameter1"].Value.(string)}, additionalSetRas.AdditionalScopes.Members()) //nolint:forcetypeassert
}

func TestExtractParameterNameFromArmFunction(t *testing.T) {
	t.Parallel()
	// Test with a valid parameter reference.
	value := "[parameters('parameterName')]"
	expected := "parameterName"
	actual, err := extractParameterNameFromArmFunction(value)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)

	// Test with an invalid prefix.
	value = "[param('parameterName')]"
	_, err = extractParameterNameFromArmFunction(value)
	assert.Error(t, err)

	// Test with an invalid suffix.
	value = "[parameters('parameterName')"
	_, err = extractParameterNameFromArmFunction(value)
	assert.Error(t, err)

	// Test with an invalid format.
	value = "parameters('parameterName')"
	_, err = extractParameterNameFromArmFunction(value)
	assert.Error(t, err)
}
