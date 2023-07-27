// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/google/uuid"
	"github.com/matt-FFFFFF/alzlib/to"
)

const (
	managementGroupIdFmt     = "/providers/Microsoft.Management/managementGroups/%s"
	policyAssignmentIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyAssignments/%s"
	policyDefinitionIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyDefinitions/%s"
	policySetDefinitionIdFmt = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policySetDefinitions/%s"
	roleDefinitionIdFmt      = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/roleDefinitions/%s"
)

// DeploymentType represents a deployment of Azure management group.
type DeploymentType struct {
	MGs map[string]*AlzManagementGroup
	mu  sync.RWMutex
}

func (d *DeploymentType) policyDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.MGs {
		for pdname := range mg.PolicyDefinitions {
			res[pdname] = mgname
		}
	}
	return res
}

func (d *DeploymentType) policySetDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.MGs {
		for psdname := range mg.PolicySetDefinitions {
			res[psdname] = mgname
		}
	}
	return res
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

func modifyPolicyAssignments(alzmg *AlzManagementGroup, pd2mg, psd2mg map[string]string, wkpv *WellKnownPolicyValues) error {
	// Update well known policy assignment parameters.
	wk := getWellKnownPolicyAssignmentParameterValues(wkpv)
	for assignmentName, params := range wk {
		pa, ok := alzmg.PolicyAssignments[assignmentName]
		if !ok {
			continue
		}
		if pa.Properties.Parameters == nil {
			pa.Properties.Parameters = make(map[string]*armpolicy.ParameterValuesValue, 1)
		}
		for param, value := range params {
			pa.Properties.Parameters[param] = value
		}
	}

	// Update resource ids and refs.
	for assignmentName, assignment := range alzmg.PolicyAssignments {
		assignment.ID = to.Ptr(fmt.Sprintf(policyAssignmentIdFmt, alzmg.Name, assignmentName))
		assignment.Properties.Scope = to.Ptr(fmt.Sprintf(managementGroupIdFmt, alzmg.Name))
		if assignment.Location != nil {
			assignment.Location = to.Ptr(wkpv.DefaultLocation)
		}

		// rewrite the referenced policy definition id
		// if the policy definition is in the list.
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
		roledef.Properties.AssignableScopes[0] = to.Ptr(alzmg.GetResourceId())
	}
}

func newAlzManagementGroup() *AlzManagementGroup {
	return &AlzManagementGroup{
		AdditionalRoleAssignmentsByPolicyAssignment: make(map[string]*PolicyAssignmentAdditionalRoleAssignments),
		PolicyDefinitions:    make(map[string]*armpolicy.Definition),
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		PolicyAssignments:    make(map[string]*armpolicy.Assignment),
		RoleAssignments:      make(map[string]*armauthorization.RoleAssignment),
		RoleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
	}
}

func uuidV5(s ...string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(strings.Join(s, "")))
}
