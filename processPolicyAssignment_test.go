package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_processPolicyAssignment_valid(t *testing.T) {
	sampleData := getSamplePolicyAssignment()
	az := &AlzLib{}

	assert.NilError(t, processPolicyAssignment(az, sampleData))
	assert.Equal(t, len(az.PolicyAssignments), 1)
	assert.Equal(t, *az.PolicyAssignments[0].Name, "Deny-Storage-http")
	assert.Equal(t, *az.PolicyAssignments[0].Properties.DisplayName, "Secure transfer to storage accounts should be enabled")
}

func getSamplePolicyAssignment() []byte {
	return []byte(`{
		"name": "Deny-Storage-http",
		"type": "Microsoft.Authorization/policyAssignments",
		"apiVersion": "2019-09-01",
		"properties": {
			"description": "Audit requirement of Secure transfer in your storage account. Secure transfer is an option that forces your storage account to accept requests only from secure connections (HTTPS). Use of HTTPS ensures authentication between the server and the service and protects data in transit from network layer attacks such as man-in-the-middle, eavesdropping, and session-hijacking.",
			"displayName": "Secure transfer to storage accounts should be enabled",
			"notScopes": [],
			"parameters": {},
			"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9",
			"scope": "${current_scope_resource_id}",
			"enforcementMode": null
		},
		"location": "${default_location}",
		"identity": {
			"type": "None"
		}
	}`)
}
