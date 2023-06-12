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
)

const (
	managementGroupIdFmt     = "/providers/Microsoft.Management/managementGroups/%s"
	policyAssignmentIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyAssignments/%s"
	policyDefinitionIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyDefinitions/%s"
	policySetDefinitionIdFmt = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policySetDefinitions/%s"
	roleDefinitionIdFmt      = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/roleDefinitions/%s"
)

var (
// WellKnownPolicyAssignmentParameterValues = getWellKnownPolicyAssignmentParameterValues()
)

// DeploymentType represents a deployment of Azure management group
type DeploymentType struct {
	MGs map[string]*AlzManagementGroup
	//options *DeploymentOptions
	mu sync.RWMutex
}

// AddManagementGroup adds a management group to the deployment, with a parent if specified.
// If the parent is not specified, the management group is considered the root of the hierarchy.
// Consider passing the source Archetype through the .WithWellKnownPolicyParameters() method
// to ensure that the values in the DeploymentOptions are honored.
func (d *DeploymentType) AddManagementGroup(name, displayName, parent string, arch *Archetype) error {
	if arch.options == nil {
		return errors.New("archetype deployment options not set, use .NewDeployment() to create a new deployment")
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
	if parent != "" {
		if _, ok := d.MGs[parent]; !ok {
			return fmt.Errorf("parent management group %s does not exist", parent)
		}
		alzmg.parent = d.MGs[parent]
		alzmg.parent.children = append(alzmg.parent.children, alzmg)
	}

	if parent == "" {
		for mgname, mg := range d.MGs {
			if mg.parent == nil {
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
	if err := modifyPolicyAssignments(alzmg, pd2mg, psd2mg, arch.options); err != nil {
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

func newAlzManagementGroup() *AlzManagementGroup {
	return &AlzManagementGroup{
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
