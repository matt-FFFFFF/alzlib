package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"gotest.tools/v3/assert"
)

func Test_processPolicyDefinition_valid(t *testing.T) {
	sampleData := getSamplePolicyDefinition()
	az := &AlzLib{}

	assert.NilError(t, processPolicyDefinition(az, sampleData))
	assert.Equal(t, len(az.PolicyDefinitions), 1)
	assert.Equal(t, *az.PolicyDefinitions[0].Name, "Append-AppService-httpsonly")
	assert.Equal(t, *az.PolicyDefinitions[0].Properties.PolicyType, armpolicy.PolicyTypeCustom)
}

func getSamplePolicyDefinition() []byte {
	return []byte(`{
		"name": "Append-AppService-httpsonly",
		"type": "Microsoft.Authorization/policyDefinitions",
		"apiVersion": "2021-06-01",
		"scope": null,
		"properties": {
			"policyType": "Custom",
			"mode": "All",
			"displayName": "AppService append enable https only setting to enforce https setting.",
			"description": "Appends the AppService sites object to ensure that  HTTPS only is enabled for  server/service authentication and protects data in transit from network layer eavesdropping attacks. Please note Append does not enforce compliance use then deny.",
			"metadata": {
				"version": "1.0.0",
				"category": "App Service"
			},
			"parameters": {
				"effect": {
					"type": "String",
					"defaultValue": "Append",
					"allowedValues": [
						"Append",
						"Disabled"
					],
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				}
			},
			"policyRule": {
				"if": {
					"allOf": [
						{
							"field": "type",
							"equals": "Microsoft.Web/sites"
						},
						{
							"field": "Microsoft.Web/sites/httpsOnly",
							"notequals": true
						}
					]
				},
				"then": {
					"effect": "[parameters('effect')]",
					"details": [
						{
							"field": "Microsoft.Web/sites/httpsOnly",
							"value": true
						}
					]
				}
			}
		}
	}`)
}
