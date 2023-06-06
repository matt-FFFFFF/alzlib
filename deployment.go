package alzlib

import (
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

const (
	managementGroupIdFmt     = "/providers/Microsoft.Management/managementGroups/%s"
	policyAssignmentIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyAssignments/%s"
	policyDefinitionIdFmt    = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policyDefinitions/%s"
	policySetDefinitionIdFmt = "/providers/Microsoft.Management/managementGroups/%s/providers/Microsoft.Authorization/policySetDefinitions/%s"
)

// Deployment represents a deployment of Azure management group
type Deployment struct {
	MGs     map[string]*AlzManagementGroup
	options *DeploymentOptions
	mu      sync.RWMutex
}

type DeploymentOptions struct {
	DefaultLocation                string
	DefaultLogAnalyticsWorkspaceId string
}

// AlzManagementGroup represents an Azure Management Group within a hierarchy, with links to parent and children.
type AlzManagementGroup struct {
	Name                 string
	DisplayName          string
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	RoleAssignments      map[string]*armauthorization.RoleAssignment
	children             []*AlzManagementGroup
	parent               *AlzManagementGroup
}

func NewDeployment(opts *DeploymentOptions) *Deployment {
	d := new(Deployment)
	d.options = opts
	d.MGs = make(map[string]*AlzManagementGroup)
	return d
}

func (d *Deployment) AddManagementGroup(name, displayName, parent string, arch *Archetype) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.MGs[name]; exists {
		return fmt.Errorf("management group %s already exists", name)
	}
	alzmg := new(AlzManagementGroup)
	d.MGs[name] = alzmg
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
	for name, roleassign := range arch.RoleAssignments {
		newroleassign := new(armauthorization.RoleAssignment)
		*newroleassign = *roleassign
		alzmg.RoleAssignments[name] = newroleassign
	}

	pd2mg := d.policyDefinitionToMg()
	pds2mg := d.policySetDefinitionToMg()
	// re-write the policy definition ID property to be the current MG name
	modifyPolicyDefinitions(alzmg)
	// re-write the policy set definition ID property and go through the referenced definitions
	// and write the defintion id if it's custom
	modifyPolicySetDefinitions(alzmg, pd2mg)

	// re-write the policy assignment ID property to be the current MG name
	// and go through the referenced definitions and write the defintion id if it's custom
	// and set the location property to the default location if it's not nil
	modifyPolicyAssignments(alzmg, pd2mg, pds2mg, d.options)
	return nil
}

func (d *Deployment) policyDefinitionToMg() map[string]string {
	res := make(map[string]string, 0)
	for mgname, mg := range d.MGs {
		for pdname := range mg.PolicyDefinitions {
			res[pdname] = mgname
		}
	}
	return res
}

func (d *Deployment) policySetDefinitionToMg() map[string]string {
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

func modifyPolicyAssignments(alzmg *AlzManagementGroup, pd2mg, psd2mg map[string]string, opts *DeploymentOptions) error {
	for k, v := range alzmg.PolicyAssignments {
		v.ID = to.Ptr(fmt.Sprintf(policyAssignmentIdFmt, alzmg.Name, k))
		v.Properties.Scope = to.Ptr(fmt.Sprintf(managementGroupIdFmt, alzmg.Name))
		if v.Location != nil {
			v.Location = to.Ptr(opts.DefaultLocation)
		}

		// rewrite the referenced policy definition id
		pd := v.Properties.PolicyDefinitionID
		switch lastButOneSegment(*pd) {
		case "policyDefinitions":
			if mgname, ok := pd2mg[lastSegment(*pd)]; ok {
				v.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policyDefinitionIdFmt, mgname, lastSegment(*pd)))
			}
		case "policySetDefinitions":
			if mgname, ok := psd2mg[lastSegment(*pd)]; ok {
				v.Properties.PolicyDefinitionID = to.Ptr(fmt.Sprintf(policySetDefinitionIdFmt, mgname, lastSegment(*pd)))
			}
		default:
			return fmt.Errorf("policy assignment %s has invalid resource type in id %s", k, *pd)
		}

		// rewrite parameter values with well known values
		if wkp, ok := opts.WellKnownParameterValues[k]; ok {
			for wkpname, wkpval := range wkp {
				param, ok := v.Properties.Parameters[wkpname]
				if !ok {
					return fmt.Errorf("policy assignment %s does not have well known parameter %s", k, wkpname)
				}
				param.Value = wkpval
			}
		}
	}
	return nil
}
