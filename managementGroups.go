package alzlib

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

const (
	managementGroupResourceIdPrefix = "/providers/Microsoft.Management/managementGroups/"
)

// generateManagementGroups generates the management group hierarchy and attaches it to the AlzLib instance
// Archetypes are modified and then assigned to the management groups, using go's text template engine
func (az *AlzLib) generateManagementGroups() error {
	for _, mg := range az.libManagementGroups {
		if mg.IsRoot && az.RootManagementGroup == nil {
			az.RootScopeId = mg.Name
			rmg, err := convertManagementGroupsToHierarchy(mg.Name, az, nil)
			if err != nil {
				return fmt.Errorf("error converting root management group %s: %s", mg.Name, err)
			}
			az.RootManagementGroup = rmg
		}
		if mg.IsRoot && az.RootManagementGroup != nil && mg.Name != az.RootManagementGroup.Name {
			return fmt.Errorf("duplicate root management group name: %s & %s", mg.Name, az.RootManagementGroup.Name)
		}
	}
	if az.RootManagementGroup == nil {
		return fmt.Errorf("no root management group found")
	}
	return nil
}

func convertManagementGroupsToHierarchy(name string, az *AlzLib, parent *ManagementGroup) (*ManagementGroup, error) {
	lmg, ok := az.libManagementGroups[name]
	if !ok {
		return nil, fmt.Errorf("lib management group %s not found", name)
	}

	mg := &ManagementGroup{
		Name:        name,
		DisplayName: lmg.DisplayName,
		parent:      parent,
	}

	arch, ok := az.Archetypes[lmg.ArchetypeName]
	if !ok {
		return nil, fmt.Errorf("archetype %s not found when converting management group %s", lmg.ArchetypeName, lmg.Name)
	}

	td, err := NewTemplateDataAtScope(name, az)
	if err != nil {
		return nil, fmt.Errorf("error creating template data for management group %s: %s", name, err)
	}

	ar, err := arch.ProjectArchetypeAtManagementGroup(td)
	if err != nil {
		return nil, fmt.Errorf("error projecting archetype %s to management group %s: %s", lmg.ArchetypeName, lmg.Name, err)
	}
	mg.Archetype = *ar

	for _, child := range lmg.ChildrenNames {
		childmg, err := convertManagementGroupsToHierarchy(child, az, mg)
		if err != nil {
			return nil, fmt.Errorf("error converting management group %s to hierarchy: %s", child, err)
		}
		mg.children = append(mg.children, childmg)
	}

	return mg, nil
}

func getManagementGroupResourceId(id string) (*arm.ResourceID, error) {
	return arm.ParseResourceID(managementGroupResourceIdPrefix + id)
}
