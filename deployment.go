// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"errors"
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

// DeploymentType represents a deployment of Azure management group
type DeploymentType struct {
	MGs map[string]*AlzManagementGroup
	mu  sync.RWMutex
}

// AddManagementGroup adds a management group to the deployment, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// You should pass the source Archetype through the .WithWellKnownPolicyParameters() method
// to ensure that the values in the wellKnownPolicyValues are honored.
func (d *DeploymentType) AddManagementGroup(name, displayName, parent string, parentIsExternal bool, arch *Archetype) error {
	if arch.wellKnownPolicyValues == nil {
		return errors.New("archetype well known values not set, use Archetype.WithWellKnownPolicyValues() to update")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.MGs[name]; exists {
		return fmt.Errorf("management group %s already exists", name)
	}
	alzmg := newAlzManagementGroup()

	alzmg.Name = name
	alzmg.DisplayName = displayName
	alzmg.children = make([]*AlzManagementGroup, 0)
	if parentIsExternal {
		if _, ok := d.MGs[parent]; ok {
			return fmt.Errorf("external parent management group set, but already exists %s", parent)
		}

		alzmg.parentExternal = to.Ptr[string](parent)
	}
	if !parentIsExternal && parent != "" {
		mg, ok := d.MGs[parent]
		if !ok {
			return fmt.Errorf("parent management group not found %s", parent)
		}
		alzmg.parent = mg
		d.MGs[parent].children = appendIfMissing(d.MGs[parent].children, alzmg)
	}

	// We only allow one intermediate root management group, so check if this is the first one
	if parentIsExternal {
		for mgname, mg := range d.MGs {
			if mg.parentExternal != nil {
				return fmt.Errorf("multiple root management groups: %s and %s", mgname, name)
			}
		}
	}

	// make copies of the archetype resources for modification in the Deployment management group
	for name, def := range arch.PolicyDefinitions {
		newdef := new(armpolicy.Definition)
		*newdef = *def
		alzmg.PolicyDefinitions[name] = newdef
	}
	for name, def := range arch.PolicySetDefinitions {
		newdef := new(armpolicy.SetDefinition)
		*newdef = *def
		alzmg.PolicySetDefinitions[name] = newdef
	}
	for name, polassign := range arch.PolicyAssignments {
		newpolassign := new(armpolicy.Assignment)
		*newpolassign = *polassign
		alzmg.PolicyAssignments[name] = newpolassign
	}
	for name, roledef := range arch.RoleDefinitions {
		newroledef := new(armauthorization.RoleDefinition)
		*newroledef = *roledef
		alzmg.RoleDefinitions[name] = newroledef
	}

	d.MGs[name] = alzmg

	pd2mg := d.policyDefinitionToMg()
	psd2mg := d.policySetDefinitionToMg()

	// re-write the policy definition ID property to be the current MG name
	modifyPolicyDefinitions(alzmg)

	// re-write the policy set definition ID property and go through the referenced definitions
	// and write the defintion id if it's custom
	modifyPolicySetDefinitions(alzmg, pd2mg)

	// re-write the policy assignment ID property to be the current MG name
	// and go through the referenced definitions and write the definition id if it's custom
	// and set the location property to the default location if it's not nil
	if err := modifyPolicyAssignments(alzmg, pd2mg, psd2mg, arch.wellKnownPolicyValues); err != nil {
		return err
	}

	// re-write the assignableScopes for the role definitions
	modifyRoleDefinitions(alzmg)

	return nil
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

func modifyPolicyAssignments(alzmg *AlzManagementGroup, pd2mg, psd2mg map[string]string, opts *WellKnownPolicyValues) error {
	for assignmentName, assignment := range alzmg.PolicyAssignments {
		assignment.ID = to.Ptr(fmt.Sprintf(policyAssignmentIdFmt, alzmg.Name, assignmentName))
		assignment.Properties.Scope = to.Ptr(fmt.Sprintf(managementGroupIdFmt, alzmg.Name))
		if assignment.Location != nil {
			assignment.Location = to.Ptr(opts.DefaultLocation)
		}

		// rewrite the referenced policy definition id
		// if the policy definition is in the list
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
