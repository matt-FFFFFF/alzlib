package alzlib

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

// policyAssignmentsParameterValues represents the values for well-known policy assignment parameters.
// The first map key is the assignment name, the second is the parameter name, and the value is the parameter value.
type policyAssignmentsParameterValues map[string]map[string]*armpolicy.ParameterValuesValue

// getWellKnownPolicyAssignmentParameterValues is used by the *Archetype.WithWellKnownPolicyValues() method to
// set the values for well-known policy assignment parameters.
func getWellKnownPolicyAssignmentParameterValues(wkpv *WellKnownPolicyValues) policyAssignmentsParameterValues {
	return policyAssignmentsParameterValues{
		"Deploy-AzActivity-Log": {
			"logAnalytics": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-AzSqlDb-Auditing": {
			"logAnalyticsWorkspaceId": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-Log-Analytics": {
			"workspaceRegion": {
				Value: wkpv.DefaultLocation,
			},
			"automationRegion": {
				Value: wkpv.DefaultLocation,
			},
		},
		"Deploy-MDFC-Config": {
			"logAnalytics": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
			"ascExportResourceGroupLocation": {
				Value: wkpv.DefaultLocation,
			},
		},
		"Deploy-Resource-Diag": {
			"logAnalytics": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-VM-Monitoring": {
			"logAnalytics_1": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-VMSS-Monitoring": {
			"logAnalytics_1": {
				Value: wkpv.DefaultLogAnalyticsWorkspaceId,
			},
		},
	}
}
