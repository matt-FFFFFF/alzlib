package alzlib

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestWellKnownParameterReplacement demonstrates the replacement of well-known parameters
func TestWellKnownParameterReplacement(t *testing.T) {
	t.Parallel()
	az := NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/wellknownparameters")
	err := az.Init(ctx, dirfs)
	if err != nil {
		fmt.Println(err)
	}

	vals := &WellKnownPolicyValues{
		DefaultLocation:                "eastus",
		DefaultLogAnalyticsWorkspaceId: "testlaworkspaceid",
	}

	arch := az.Archetypes["test"].WithWellKnownPolicyValues(vals)
	assert.NoError(t, az.Deployment.AddManagementGroup("test", "test", "", arch))

	paramValue := az.Deployment.MGs["test"].PolicyAssignments["Deploy-AzActivity-Log"].Properties.Parameters["logAnalytics"].Value
	assert.Equal(t, "testlaworkspaceid", paramValue)
}

func TestAppendIfMissing(t *testing.T) {
	t.Parallel()
	// Test appending to an empty slice
	slice := []int{}
	slice = appendIfMissing(slice, 1)
	assert.Equal(t, []int{1}, slice)

	// Test appending a value that is already in the slice
	slice = appendIfMissing(slice, 1)
	assert.Equal(t, []int{1}, slice)

	// Test appending a value that is not in the slice
	slice = appendIfMissing(slice, 2)
	assert.Equal(t, []int{1, 2}, slice)

	// Test appending to a slice of strings
	strSlice := []string{"foo", "bar"}
	strSlice = appendIfMissing(strSlice, "baz")
	assert.Equal(t, []string{"foo", "bar", "baz"}, strSlice)
}

func TestPolicySetDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy set definition
	d := DeploymentType{
		MGs: map[string]*AlzManagementGroup{
			"mg1": {
				PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
					"psd1": {},
				},
			},
		},
	}
	expected := map[string]string{
		"psd1": "mg1",
	}
	assert.Equal(t, expected, d.policySetDefinitionToMg())

	// Test with multiple management groups and policy set definitions
	d = DeploymentType{
		MGs: map[string]*AlzManagementGroup{
			"mg1": {
				PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
					"psd1": {},
				},
			},
			"mg2": {
				PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
					"psd2": {},
					"psd3": {},
				},
			},
		},
	}
	expected = map[string]string{
		"psd1": "mg1",
		"psd2": "mg2",
		"psd3": "mg2",
	}
	assert.Equal(t, expected, d.policySetDefinitionToMg())

	// Test with no management groups or policy set definitions
	d = DeploymentType{}
	expected = map[string]string{}
	assert.Equal(t, expected, d.policySetDefinitionToMg())
}

func TestPolicyDefinitionToMg(t *testing.T) {
	t.Parallel()
	// Test with a single management group and policy definition
	d := DeploymentType{
		MGs: map[string]*AlzManagementGroup{
			"mg1": {
				PolicyDefinitions: map[string]*armpolicy.Definition{
					"pd1": {},
				},
			},
		},
	}
	expected := map[string]string{
		"pd1": "mg1",
	}
	assert.Equal(t, expected, d.policyDefinitionToMg())

	// Test with multiple management groups and policy definitions
	d = DeploymentType{
		MGs: map[string]*AlzManagementGroup{
			"mg1": {
				PolicyDefinitions: map[string]*armpolicy.Definition{
					"pd1": {},
				},
			},
			"mg2": {
				PolicyDefinitions: map[string]*armpolicy.Definition{
					"pd2": {},
					"pd3": {},
				},
			},
		},
	}
	expected = map[string]string{
		"pd1": "mg1",
		"pd2": "mg2",
		"pd3": "mg2",
	}
	assert.Equal(t, expected, d.policyDefinitionToMg())

	// Test with no management groups or policy definitions
	d = DeploymentType{}
	expected = map[string]string{}
	assert.Equal(t, expected, d.policyDefinitionToMg())
}

func TestModifyPolicyDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single policy definition
	alzmg := &AlzManagementGroup{
		Name: "mg1",
		PolicyDefinitions: map[string]*armpolicy.Definition{
			"pd1": {},
		},
	}
	modifyPolicyDefinitions(alzmg)
	expected := fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.PolicyDefinitions["pd1"].ID)

	// Test with multiple policy definitions
	alzmg = &AlzManagementGroup{
		Name: "mg1",
		PolicyDefinitions: map[string]*armpolicy.Definition{
			"pd1": {},
			"pd2": {},
		},
	}
	modifyPolicyDefinitions(alzmg)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.PolicyDefinitions["pd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.PolicyDefinitions["pd2"].ID)

	// Test with no policy definitions
	alzmg = &AlzManagementGroup{
		Name:              "mg1",
		PolicyDefinitions: map[string]*armpolicy.Definition{},
	}
	modifyPolicyDefinitions(alzmg)
	assert.Empty(t, alzmg.PolicyDefinitions)
}

func TestModifyPolicySetDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single policy set definition and a single policy definition
	alzmg := &AlzManagementGroup{
		Name: "mg1",
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			"psd1": {
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
						},
					},
				},
			},
		},
	}
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	modifyPolicySetDefinitions(alzmg, pd2mg)
	expected := fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd1"].Properties.PolicyDefinitions[0].PolicyDefinitionID)

	// Test with multiple policy set definitions and policy definitions
	alzmg = &AlzManagementGroup{
		Name: "mg1",
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{
			"psd1": {
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
						},
					},
				},
			},
			"psd2": {
				Properties: &armpolicy.SetDefinitionProperties{
					PolicyDefinitions: []*armpolicy.DefinitionReference{
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd2")),
						},
						{
							PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd3")),
						},
					},
				},
			},
		},
	}
	pd2mg = map[string]string{
		"pd1": "mg1",
		"pd2": "mg1",
		"pd3": "mg1",
	}
	modifyPolicySetDefinitions(alzmg, pd2mg)
	expected = fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd1"].Properties.PolicyDefinitions[0].PolicyDefinitionID)
	expected = fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd2")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd2"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd2")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd2"].Properties.PolicyDefinitions[0].PolicyDefinitionID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd3")
	assert.Equal(t, expected, *alzmg.PolicySetDefinitions["psd2"].Properties.PolicyDefinitions[1].PolicyDefinitionID)

	// Test with no policy set definitions or policy definitions
	alzmg = &AlzManagementGroup{
		Name:                 "mg1",
		PolicySetDefinitions: map[string]*armpolicy.SetDefinition{},
	}
	pd2mg = map[string]string{}
	modifyPolicySetDefinitions(alzmg, pd2mg)
	assert.Empty(t, alzmg.PolicySetDefinitions)
}

func TestModifyRoleDefinitions(t *testing.T) {
	t.Parallel()
	// Test with a single role definition
	alzmg := &AlzManagementGroup{
		Name: "mg1",
		RoleDefinitions: map[string]*armauthorization.RoleDefinition{
			"rd1": {
				Name: to.Ptr("role1"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			},
		},
	}
	modifyRoleDefinitions(alzmg)
	expected := fmt.Sprintf(roleDefinitionIdFmt, "mg1", uuidV5("mg1", "role1"))
	assert.Equal(t, expected, *alzmg.RoleDefinitions["rd1"].ID)
	assert.Len(t, alzmg.RoleDefinitions["rd1"].Properties.AssignableScopes, 1)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.RoleDefinitions["rd1"].Properties.AssignableScopes[0])

	// Test with multiple role definitions
	alzmg = &AlzManagementGroup{
		Name: "mg1",
		RoleDefinitions: map[string]*armauthorization.RoleDefinition{
			"rd1": {
				Name: to.Ptr("role1"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			},
			"rd2": {
				Name: to.Ptr("role2"),
				Properties: &armauthorization.RoleDefinitionProperties{
					AssignableScopes: []*string{},
				},
			},
		},
	}
	modifyRoleDefinitions(alzmg)
	expected = fmt.Sprintf(roleDefinitionIdFmt, "mg1", uuidV5("mg1", "role1"))
	assert.Equal(t, expected, *alzmg.RoleDefinitions["rd1"].ID)
	assert.Len(t, alzmg.RoleDefinitions["rd1"].Properties.AssignableScopes, 1)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.RoleDefinitions["rd1"].Properties.AssignableScopes[0])
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), *alzmg.RoleDefinitions["rd1"].Properties.AssignableScopes[0])
	expected = fmt.Sprintf(roleDefinitionIdFmt, "mg1", uuidV5("mg1", "role2"))
	assert.Equal(t, expected, *alzmg.RoleDefinitions["rd2"].ID)
	assert.Len(t, alzmg.RoleDefinitions["rd2"].Properties.AssignableScopes, 1)
	assert.Equal(t, fmt.Sprintf(managementGroupIdFmt, "mg1"), *alzmg.RoleDefinitions["rd2"].Properties.AssignableScopes[0])

	// Test with no role definitions
	alzmg = &AlzManagementGroup{
		Name:            "mg1",
		RoleDefinitions: map[string]*armauthorization.RoleDefinition{},
	}
	modifyRoleDefinitions(alzmg)
	assert.Empty(t, alzmg.RoleDefinitions)
}

func TestModifyPolicyAssignments(t *testing.T) {
	t.Parallel()
	// Test with a single policy assignment and policy definition
	alzmg := &AlzManagementGroup{
		Name: "mg1",
		PolicyAssignments: map[string]*armpolicy.Assignment{
			"pa1": {
				Name: to.Ptr("pa1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			},
		},
	}
	pd2mg := map[string]string{
		"pd1": "mg1",
	}
	psd2mg := map[string]string{}
	opts := &WellKnownPolicyValues{
		DefaultLocation: "eastus",
	}
	err := modifyPolicyAssignments(alzmg, pd2mg, psd2mg, opts)
	assert.NoError(t, err)
	expected := fmt.Sprintf(policyAssignmentIdFmt, "mg1", "pa1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].Location)

	// Test with multiple policy assignments and policy definitions
	alzmg = &AlzManagementGroup{
		Name: "mg1",
		PolicyAssignments: map[string]*armpolicy.Assignment{
			"pa1": {
				Name: to.Ptr("pa1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, "changeme", "pd1")),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			},
			"pa2": {
				Name: to.Ptr("pa2"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, "changeme", "psd1")),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "changeme")),
				},
				Location: to.Ptr("changeme"),
			},
		},
	}
	pd2mg = map[string]string{
		"pd1": "mg1",
	}
	psd2mg = map[string]string{
		"psd1": "mg1",
	}
	err = modifyPolicyAssignments(alzmg, pd2mg, psd2mg, opts)
	assert.NoError(t, err)
	expected = fmt.Sprintf(policyAssignmentIdFmt, "mg1", "pa1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].ID)
	expected = fmt.Sprintf(policyDefinitionIdFmt, "mg1", "pd1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa1"].Location)
	expected = fmt.Sprintf(policyAssignmentIdFmt, "mg1", "pa2")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa2"].ID)
	expected = fmt.Sprintf(policySetDefinitionIdFmt, "mg1", "psd1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa2"].Properties.PolicyDefinitionID)
	expected = fmt.Sprintf(managementGroupIdFmt, "mg1")
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa2"].Properties.Scope)
	expected = "eastus"
	assert.Equal(t, expected, *alzmg.PolicyAssignments["pa2"].Location)

	// Test with invalid policy definition id
	alzmg = &AlzManagementGroup{
		Name: "mg1",
		PolicyAssignments: map[string]*armpolicy.Assignment{
			"pa1": {
				Name: to.Ptr("policy1"),
				Properties: &armpolicy.AssignmentProperties{
					PolicyDefinitionID: to.Ptr("invalid"),
					Scope:              to.Ptr(fmt.Sprintf(managementGroupIdFmt, "mg1")),
				},
			},
		},
	}
	pd2mg = map[string]string{}
	psd2mg = map[string]string{}
	err = modifyPolicyAssignments(alzmg, pd2mg, psd2mg, opts)
	assert.Error(t, err)
	expected = "policy assignment pa1 has invalid referenced definition id invalid"
	assert.Equal(t, expected, err.Error())
}

func TestAddManagementGroup(t *testing.T) {
	// create a new deployment type
	wkvs := &WellKnownPolicyValues{
		DefaultLocation: "eastus",
	}

	d := DeploymentType{
		MGs: make(map[string]*AlzManagementGroup),
	}

	// create a new archetype
	arch := &Archetype{
		PolicyDefinitions:    make(map[string]*armpolicy.Definition),
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		PolicyAssignments:    make(map[string]*armpolicy.Assignment),
		RoleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
	}
	arch = arch.WithWellKnownPolicyValues(wkvs)

	// test adding a new management group with no parent
	err := d.AddManagementGroup("mg1", "mg1", "", arch)
	assert.NoError(t, err)
	assert.Len(t, d.MGs, 1)
	assert.Contains(t, d.MGs, "mg1")
	assert.Equal(t, "mg1", d.MGs["mg1"].Name)
	assert.Equal(t, "mg1", d.MGs["mg1"].DisplayName)
	assert.Nil(t, d.MGs["mg1"].parent)
	assert.Empty(t, d.MGs["mg1"].children)

	// test adding a new management group with a parent
	err = d.AddManagementGroup("mg2", "mg2", "mg1", arch)
	assert.NoError(t, err)
	assert.Len(t, d.MGs, 2)
	assert.Contains(t, d.MGs, "mg2")
	assert.Equal(t, "mg2", d.MGs["mg2"].Name)
	assert.Equal(t, "mg2", d.MGs["mg2"].DisplayName)
	assert.NotNil(t, d.MGs["mg2"].parent)
	assert.Equal(t, "mg1", d.MGs["mg2"].parent.Name)
	assert.Len(t, d.MGs["mg1"].children, 1)
	assert.Equal(t, "mg2", d.MGs["mg1"].children[0].Name)

	// test adding a new management group with a non-existent parent
	err = d.AddManagementGroup("mg3", "mg3", "mg4", arch)
	assert.Error(t, err)
	assert.Len(t, d.MGs, 2)
	assert.Contains(t, d.MGs, "mg1")
	assert.Contains(t, d.MGs, "mg2")
	assert.NotContains(t, d.MGs, "mg3")

	// test adding a new management group with multiple root management groups
	err = d.AddManagementGroup("mg4", "mg4", "", arch)
	assert.Error(t, err)
	assert.Len(t, d.MGs, 2)
	assert.Contains(t, d.MGs, "mg1")
	assert.Contains(t, d.MGs, "mg2")
	assert.NotContains(t, d.MGs, "mg4")

	// test adding a new management group with an existing name
	err = d.AddManagementGroup("mg1", "mg1", "", arch)
	assert.Error(t, err)
	assert.Len(t, d.MGs, 2)
	assert.Contains(t, d.MGs, "mg1")
	assert.Contains(t, d.MGs, "mg2")
}

func TestNewUUID(t *testing.T) {
	// create a new UUID namespace
	ns := uuid.MustParse("d97506b3-4470-5694-a203-2c37e477d3ac")

	u := uuidV5("foo", "bar", "baz")

	assert.Equal(t, ns.String(), u.String())
}
