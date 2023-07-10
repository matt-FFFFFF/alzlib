package alzlib

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

// policyAssignmentsParameterValues represents the values for well-known policy assignment parameters.
// The first map key is the assignment name, the second is the parameter name, and the value is the parameter value
type policyAssignmentsParameterValues map[string]map[string]*armpolicy.ParameterValuesValue

// getWellKnownPolicyAssignmentParameterValues is used by the *Archetype.WithWellKnownPolicyValues() method to set the values for well-known policy assignment parameters.
func getWellKnownPolicyAssignmentParameterValues(opts *WellKnownPolicyValues) policyAssignmentsParameterValues {
	return policyAssignmentsParameterValues{
		"Deploy-AzActivity-Log": {
			"logAnalytics": {
				Value: opts.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-AzSqlDb-Auditing": {
			"logAnalyticsWorkspaceId": {
				Value: opts.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-Log-Analytics": {
			"workspaceRegion": {
				Value: opts.DefaultLocation,
			},
			"automationRegion": {
				Value: opts.DefaultLocation,
			},
		},
		"Deploy-MDFC-Config": {
			"logAnalytics": {
				Value: opts.DefaultLogAnalyticsWorkspaceId,
			},
			"ascExportResourceGroupLocation": {
				Value: opts.DefaultLocation,
			},
		},
		"Deploy-Resource-Diag": {
			"logAnalytics": {
				Value: opts.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-VM-Monitoring": {
			"logAnalytics_1": {
				Value: opts.DefaultLogAnalyticsWorkspaceId,
			},
		},
		"Deploy-VMSS-Monitoring": {
			"logAnalytics_1": {
				Value: opts.DefaultLogAnalyticsWorkspaceId,
			},
		},
	}
}
