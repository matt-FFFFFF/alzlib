package alzlib

func getWellKnownPolicyAssignmentParameterValues(opts *DeploymentOptions) PolicyAssignmentsParameterValues {
	return PolicyAssignmentsParameterValues{
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
