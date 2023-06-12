package alzlib

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

// AlzManagementGroup represents an Azure Management Group within a hierarchy, with links to parent and children.
type AlzManagementGroup struct {
	Name                 string
	DisplayName          string
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	RoleDefinitions      map[string]*armauthorization.RoleDefinition
	RoleAssignments      map[string]*armauthorization.RoleAssignment
	children             []*AlzManagementGroup
	parent               *AlzManagementGroup
}

// PartialRoleAssignment represents a role assignment where we do not know the object id because the policy assignment is not yet deployed.
type PartialRoleAssignment struct {
	PolicyAssignment *armpolicy.Assignment
	RoleDefinitionId string
	Scope            string
}

type policyDefinitionRule struct {
	then struct {
		details struct {
			roleDefinitionIds []string
		}
	}
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

func (az *AlzLib) GeneratePolicyRoleAssignments() error {
	// Look through all assignments
	// if identity.Type is not set or None then continue
	//
	// if definition:
	//   range through each definition
	//     if definition is not in alzlib then error
	//     look up definition and get: properties.policyRule.then.details.roleDefinitionIds
	//     range through definition - properties.parameters
	//       if parameter.metadata.assignPermissions is true then create a partial role assignment using the assignment parameter value
	//
	//
	//
	// if set definition:
	//  range through each set definition
	//    range through each referenced definition in the set
	//      if definition is not in alzlib then error
	//      look up definition and get: properties.policyRule.then.details.roleDefinitionIds
	//      range through definition - properties.parameters
	//        if parameter.metadata.assignPermissions is true then create a partial role assignment using the assignment parameter value from the parent set definition
	//         - get the reference.Parameters[parameter.Name] value (a string), parse the set parameter name
	//         - look up the set parameter name in the parent set definition, get the value

	for _, assign := range az.PolicyAssignments {
		if assign.Identity == nil || assign.Identity.Type == nil || *assign.Identity.Type == "None" {
			continue
		}

		defId := assign.Properties.PolicyDefinitionID
		switch lastButOneSegment(*defId) {
		case "policyDefinitions":
			def, ok := az.PolicyDefinitions[lastSegment(*defId)]
			if !ok {
				return fmt.Errorf("policy definition %s not found in AlzLib", lastSegment(*defId))
			}
			roleIds, err := getPolicyDefRoleDefinitionIds(def.Properties.PolicyRule)
			if err != nil {
				return err
			}
			for paramName, paramVal := range def.Properties.Parameters {
				if paramVal.Metadata == nil || paramVal.Metadata.AssignPermissions == nil || !*paramVal.Metadata.AssignPermissions {
					continue
				}

			}
		case "policySetDefinitions":
		}
	}
	return nil
}

func getPolicyDefRoleDefinitionIds(rule any) ([]string, error) {
	ruleMap, ok := rule.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("rule is not a map")
	}
	then, ok := ruleMap["then"]
	if !ok {
		return nil, fmt.Errorf("rule does not have a then property")
	}
	thenMap, ok := then.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("then is not a map")
	}
	details, ok := thenMap["details"]
	if !ok {
		return nil, fmt.Errorf("then does not have a details property")
	}
	detailsMap, ok := details.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("details is not a map")
	}
	roleDefIds, ok := detailsMap["roleDefinitionIds"]
	if !ok {
		return nil, fmt.Errorf("details does not have a roleDefinitionIds property")
	}
	roleDefIdsSlice, ok := roleDefIds.([]string)
	if !ok {
		return nil, fmt.Errorf("roleDefinitionIds is not a slice of strings")
	}

	return roleDefIdsSlice, nil
}

func (alzmg *AlzManagementGroup) newPartialRoleAssignment(assignment *armpolicy.Assignment, val *armpolicy.ParameterValuesValue, roleDefId string) error {
	scope, ok := val.Value.(string)
	if !ok {
		return fmt.Errorf("parameter value is not a string")
	}

	alzmg.PartialRoleAssignments = append(alzmg.PartialRoleAssignments, PartialRoleAssignment{
		PolicyAssignment: assignment,
		Scope:            scope,
		RoleDefinitionId: roleDefId,
	})
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
