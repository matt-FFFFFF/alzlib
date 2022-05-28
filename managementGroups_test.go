package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"gotest.tools/v3/assert"
)

// TestGenerateManagementGroupsNoRoot tests the generation of management groups when there is no root management group.
func TestGenerateManagementGroupsNoRoot(t *testing.T) {
	az := &AlzLib{
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name: "test",
			},
			"test2": {
				Name: "test2",
			},
		},
	}
	assert.ErrorContains(t, az.generateManagementGroups(), "no root management group found")
}

// TestGenerateManagementGroupsDuplicateRoot tests the generation of management groups when there is a duplicate root management group.
func TestGenerateManagementGroupsDuplicateRoot(t *testing.T) {
	az := &AlzLib{
		Archetypes: map[string]*ArchetypeDefinition{
			"test": {},
		},
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name:          "test",
				ArchetypeName: "test",
				IsRoot:        true,
			},
			"test2": {
				Name:          "test2",
				ArchetypeName: "test",
				IsRoot:        true,
			},
		},
	}
	assert.ErrorContains(t, az.generateManagementGroups(), "duplicate root management group name")
}

// TestGenerateManagementGroupsDuplicateRoot tests generation of management groups when the referenced archetype cannot be found.
func TestGenerateManagementGroupsArchetypeNotFound(t *testing.T) {
	az := &AlzLib{
		Archetypes: map[string]*ArchetypeDefinition{},
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name:          "test",
				ArchetypeName: "notfound",
				IsRoot:        true,
			},
		},
	}
	assert.ErrorContains(t, az.generateManagementGroups(), "archetype notfound not found when converting management group test")
}

// TestConvertManagementGroupsToHierarchyLibMgNotFound tests the error for when the libmanagement group is not found in the AlzLib
func TestConvertManagementGroupsToHierarchyLibMgNotFound(t *testing.T) {
	az := &AlzLib{}
	_, err := convertManagementGroupsToHierarchy("test", az, nil)
	assert.ErrorContains(t, err, "lib management group test not found")
}

// TestConvertManagementGroupsToHierarchyArchetypeNotFound tests the error for when the archetype is not found in the AlzLib
func TestConvertManagementGroupsToHierarchyArchetypeNotFound(t *testing.T) {
	az := &AlzLib{
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name:          "test",
				ArchetypeName: "notfound",
			},
		},
	}
	_, err := convertManagementGroupsToHierarchy("test", az, nil)
	assert.ErrorContains(t, err, "archetype notfound not found when converting management group test")
}

// TestConvertManagementGroupsToHierarchyBadTemplate tests that an error is generated when submitting bad templating data.
func TestConvertManagementGroupsToHierarchyBadTemplate(t *testing.T) {
	az := &AlzLib{
		Archetypes: map[string]*ArchetypeDefinition{
			"test": {},
		},
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name:          "test",
				ArchetypeName: "test",
			},
		},
	}
	_, err := convertManagementGroupsToHierarchy("test", az, nil)
	assert.ErrorContains(t, err, "error creating template data for management group test")
}

// TestConvertManagementGroupsToHierarchyBadMgProjection tests an error is generated when the management group cannot be projected at scope
func TestConvertManagementGroupsToHierarchyBadMgProjection(t *testing.T) {
	paname := "testpaname {{.BadData}}"
	az := &AlzLib{
		RootScopeId: "test",
		Archetypes: map[string]*ArchetypeDefinition{
			"test": {
				PolicyAssignments: map[string]armpolicy.Assignment{
					"badtemplate": {
						Name: &paname,
					},
				},
			},
		},
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name:          "test",
				ArchetypeName: "test",
			},
		},
	}

	_, err := convertManagementGroupsToHierarchy("test", az, nil)
	assert.ErrorContains(t, err, "error projecting archetype test to management group test")
}

// TestConvertManagementGroupsToHierarchyBadChildMg tests that an error is generated when a child mg is bad.
func TestConvertManagementGroupsToHierarchyBadChildMg(t *testing.T) {
	az := &AlzLib{
		RootScopeId: "root",
		Archetypes: map[string]*ArchetypeDefinition{
			"test": {},
		},
		libManagementGroups: map[string]*LibManagementGroup{
			"test": {
				Name:          "test",
				ArchetypeName: "test",
				ChildrenNames: []string{"bad"},
			},
			"bad": {
				Name:          "bad",
				ArchetypeName: "notfound",
			},
		},
	}
	_, err := convertManagementGroupsToHierarchy("test", az, nil)
	assert.ErrorContains(t, err, "archetype notfound not found when converting management group bad")
}
