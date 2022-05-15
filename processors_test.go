package alzlib

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"gotest.tools/v3/assert"
)

func Test_processArchetypeDefinition_valid(t *testing.T) {
	sampleData := getSampleArchetypeDefinition()
	az := &AlzLib{
		libArchetypeDefinitions: make([]*libArchetypeDefinition, 0),
	}

	assert.NilError(t, processArchetypeDefinition(az, sampleData))
	assert.Equal(t, len(az.libArchetypeDefinitions), 1)
	assert.Equal(t, az.libArchetypeDefinitions[0].id, "es_root")
	assert.Equal(t, len(az.libArchetypeDefinitions[0].PolicyAssignments), 8)
	assert.Equal(t, len(az.libArchetypeDefinitions[0].PolicyDefinitions), 104)
	assert.Equal(t, len(az.libArchetypeDefinitions[0].PolicySetDefinitions), 7)
	assert.Equal(t, az.libArchetypeDefinitions[0].Config.Parameters["Deploy-MDFC-Config"].(map[string]interface{})["emailSecurityContact"], "test@test.com")
}

func Test_processPolicyAssignment_valid(t *testing.T) {
	sampleData := getSamplePolicyAssignment()
	az := &AlzLib{
		PolicyAssignments: make(map[string]*armpolicy.Assignment),
	}

	assert.NilError(t, processPolicyAssignment(az, sampleData))
	assert.Equal(t, len(az.PolicyAssignments), 1)
	assert.Equal(t, *az.PolicyAssignments["Deny-Storage-http"].Name, "Deny-Storage-http")
	assert.Equal(t, *az.PolicyAssignments["Deny-Storage-http"].Properties.DisplayName, "Secure transfer to storage accounts should be enabled")
}

func Test_processPolicyDefinition_valid(t *testing.T) {
	sampleData := getSamplePolicyDefinition()
	az := &AlzLib{
		PolicyDefinitions: make(map[string]*armpolicy.Definition),
	}

	assert.NilError(t, processPolicyDefinition(az, sampleData))
	assert.Equal(t, len(az.PolicyDefinitions), 1)
	assert.Equal(t, *az.PolicyDefinitions["Append-AppService-httpsonly"].Name, "Append-AppService-httpsonly")
	assert.Equal(t, *az.PolicyDefinitions["Append-AppService-httpsonly"].Properties.PolicyType, armpolicy.PolicyTypeCustom)
}

func Test_processSetPolicyDefinition_valid(t *testing.T) {
	sampleData := getSamplePolicySetDefinition()
	az := &AlzLib{
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
	}

	assert.NilError(t, processPolicySetDefinition(az, sampleData))
	assert.Equal(t, len(az.PolicySetDefinitions), 1)
	assert.Equal(t, *az.PolicySetDefinitions["Deploy-MDFC-Config"].Name, "Deploy-MDFC-Config")
	assert.Equal(t, *az.PolicySetDefinitions["Deploy-MDFC-Config"].Properties.PolicyType, armpolicy.PolicyTypeCustom)
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Below are helper functions for the above tests
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func getSampleArchetypeDefinition() []byte {
	return []byte(`{
		"es_root": {
			"policy_assignments": [
				"Deploy-ASC-Monitoring",
				"Deploy-MDFC-Config",
				"Deploy-AzActivity-Log",
				"Deploy-LX-Arc-Monitoring",
				"Deploy-Resource-Diag",
				"Deploy-VM-Monitoring",
				"Deploy-VMSS-Monitoring",
				"Deploy-WS-Arc-Monitoring"
			],
			"policy_definitions": [
				"Append-AppService-httpsonly",
				"Append-AppService-latestTLS",
				"Append-KV-SoftDelete",
				"Append-Redis-disableNonSslPort",
				"Append-Redis-sslEnforcement",
				"Audit-MachineLearning-PrivateEndpointId",
				"Deny-AA-child-resources",
				"Deny-AppGW-Without-WAF",
				"Deny-AppServiceApiApp-http",
				"Deny-AppServiceFunctionApp-http",
				"Deny-AppServiceWebApp-http",
				"Deny-Databricks-NoPublicIp",
				"Deny-Databricks-Sku",
				"Deny-Databricks-VirtualNetwork",
				"Deny-MachineLearning-Aks",
				"Deny-MachineLearning-Compute-SubnetId",
				"Deny-MachineLearning-Compute-VmSize",
				"Deny-MachineLearning-ComputeCluster-RemoteLoginPortPublicAccess",
				"Deny-MachineLearning-ComputeCluster-Scale",
				"Deny-MachineLearning-HbiWorkspace",
				"Deny-MachineLearning-PublicAccessWhenBehindVnet",
				"Deny-MachineLearning-PublicNetworkAccess",
				"Deny-MySql-http",
				"Deny-PostgreSql-http",
				"Deny-Private-DNS-Zones",
				"Deny-PublicEndpoint-MariaDB",
				"Deny-PublicIP",
				"Deny-RDP-From-Internet",
				"Deny-Redis-http",
				"Deny-Sql-minTLS",
				"Deny-SqlMi-minTLS",
				"Deny-Storage-minTLS",
				"Deny-Subnet-Without-Nsg",
				"Deny-Subnet-Without-Udr",
				"Deny-VNET-Peer-Cross-Sub",
				"Deny-VNET-Peering-To-Non-Approved-VNETs",
				"Deny-VNet-Peering",
				"Deploy-ASC-SecurityContacts",
				"Deploy-Budget",
				"Deploy-Custom-Route-Table",
				"Deploy-DDoSProtection",
				"Deploy-Diagnostics-AA",
				"Deploy-Diagnostics-ACI",
				"Deploy-Diagnostics-ACR",
				"Deploy-Diagnostics-AnalysisService",
				"Deploy-Diagnostics-ApiForFHIR",
				"Deploy-Diagnostics-APIMgmt",
				"Deploy-Diagnostics-ApplicationGateway",
				"Deploy-Diagnostics-CDNEndpoints",
				"Deploy-Diagnostics-CognitiveServices",
				"Deploy-Diagnostics-CosmosDB",
				"Deploy-Diagnostics-Databricks",
				"Deploy-Diagnostics-DataExplorerCluster",
				"Deploy-Diagnostics-DataFactory",
				"Deploy-Diagnostics-DLAnalytics",
				"Deploy-Diagnostics-EventGridSub",
				"Deploy-Diagnostics-EventGridSystemTopic",
				"Deploy-Diagnostics-EventGridTopic",
				"Deploy-Diagnostics-ExpressRoute",
				"Deploy-Diagnostics-Firewall",
				"Deploy-Diagnostics-FrontDoor",
				"Deploy-Diagnostics-Function",
				"Deploy-Diagnostics-HDInsight",
				"Deploy-Diagnostics-iotHub",
				"Deploy-Diagnostics-LoadBalancer",
				"Deploy-Diagnostics-LogicAppsISE",
				"Deploy-Diagnostics-MariaDB",
				"Deploy-Diagnostics-MediaService",
				"Deploy-Diagnostics-MlWorkspace",
				"Deploy-Diagnostics-MySQL",
				"Deploy-Diagnostics-NetworkSecurityGroups",
				"Deploy-Diagnostics-NIC",
				"Deploy-Diagnostics-PostgreSQL",
				"Deploy-Diagnostics-PowerBIEmbedded",
				"Deploy-Diagnostics-RedisCache",
				"Deploy-Diagnostics-Relay",
				"Deploy-Diagnostics-SignalR",
				"Deploy-Diagnostics-SQLElasticPools",
				"Deploy-Diagnostics-SQLMI",
				"Deploy-Diagnostics-TimeSeriesInsights",
				"Deploy-Diagnostics-TrafficManager",
				"Deploy-Diagnostics-VirtualNetwork",
				"Deploy-Diagnostics-VM",
				"Deploy-Diagnostics-VMSS",
				"Deploy-Diagnostics-VNetGW",
				"Deploy-Diagnostics-WebServerFarm",
				"Deploy-Diagnostics-Website",
				"Deploy-Diagnostics-WVDAppGroup",
				"Deploy-Diagnostics-WVDHostPools",
				"Deploy-Diagnostics-WVDWorkspace",
				"Deploy-FirewallPolicy",
				"Deploy-MySQL-sslEnforcement",
				"Deploy-Nsg-FlowLogs-to-LA",
				"Deploy-Nsg-FlowLogs",
				"Deploy-PostgreSQL-sslEnforcement",
				"Deploy-Sql-AuditingSettings",
				"Deploy-SQL-minTLS",
				"Deploy-Sql-SecurityAlertPolicies",
				"Deploy-Sql-Tde",
				"Deploy-Sql-vulnerabilityAssessments",
				"Deploy-SqlMi-minTLS",
				"Deploy-Storage-sslEnforcement",
				"Deploy-VNET-HubSpoke",
				"Deploy-Windows-DomainJoin"
			],
			"policy_set_definitions": [
				"Deny-PublicPaaSEndpoints",
				"Deploy-Diagnostics-LogAnalytics",
				"Deploy-MDFC-Config",
				"Deploy-Private-DNS-Zones",
				"Deploy-Sql-Security",
				"Enforce-Encryption-CMK",
				"Enforce-EncryptTransit"
			],
			"role_definitions": [
				"Network-Subnet-Contributor",
				"Application-Owners",
				"Network-Management",
				"Security-Operations",
				"Subscription-Owner"
			],
			"archetype_config": {
				"parameters": {
					"Deploy-MDFC-Config": {
						"emailSecurityContact": "test@test.com"
					}
				},
				"access_control": {}
			}
		}
	}
	`)
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

func getSamplePolicySetDefinition() []byte {
	return []byte(`{
		"name": "Deploy-MDFC-Config",
		"type": "Microsoft.Authorization/policySetDefinitions",
		"apiVersion": "2021-06-01",
		"scope": null,
		"properties": {
			"policyType": "Custom",
			"displayName": "Deploy Microsoft Defender for Cloud configuration",
			"description": "Deploy Microsoft Defender for Cloud configuration",
			"metadata": {
				"version": "3.0.0",
				"category": "Security Center"
			},
			"parameters": {
				"emailSecurityContact": {
					"type": "string",
					"metadata": {
						"displayName": "Security contacts email address",
						"description": "Provide email address for Microsoft Defender for Cloud contact details"
					}
				},
				"logAnalytics": {
					"type": "String",
					"metadata": {
						"displayName": "Primary Log Analytics workspace",
						"description": "Select Log Analytics workspace from dropdown list. If this workspace is outside of the scope of the assignment you must manually grant 'Log Analytics Contributor' permissions (or similar) to the policy assignment's principal ID.",
						"strongType": "omsWorkspace"
					}
				},
				"ascExportResourceGroupName": {
					"type": "String",
					"metadata": {
						"displayName": "Resource Group name for the export to Log Analytics workspace configuration",
						"description": "The resource group name where the export to Log Analytics workspace configuration is created. If you enter a name for a resource group that doesn't exist, it'll be created in the subscription. Note that each resource group can only have one export to Log Analytics workspace configured."
					}
				},
				"ascExportResourceGroupLocation": {
					"type": "String",
					"metadata": {
						"displayName": "Resource Group location for the export to Log Analytics workspace configuration",
						"description": "The location where the resource group and the export to Log Analytics workspace configuration are created."
					}
				},
				"enableAscForSql": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForSqlOnVm": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForDns": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForArm": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForOssDb": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForAppServices": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForKeyVault": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForStorage": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForContainers": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				},
				"enableAscForServers": {
					"type": "String",
					"metadata": {
						"displayName": "Effect",
						"description": "Enable or disable the execution of the policy"
					}
				}
			},
			"policyDefinitions": [
				{
					"policyDefinitionReferenceId": "defenderForOssDb",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/44433aa3-7ec2-4002-93ea-65c65ff0310a",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForOssDb')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForVM",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/8e86a5b6-b9bd-49d1-8e21-4bb8a0862222",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForServers')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForSqlServerVirtualMachines",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/50ea7265-7d8c-429e-9a7d-ca1f410191c3",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForSqlOnVm')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForAppServices",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b40e7bcd-a1e5-47fe-b9cf-2f534d0bfb7d",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForAppServices')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForStorageAccounts",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/74c30959-af11-47b3-9ed2-a26e03f427a3",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForStorage')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderforContainers",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/c9ddb292-b203-4738-aead-18e2716e858f",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForContainers')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForKeyVaults",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/1f725891-01c0-420a-9059-4fa46cb770b7",
					"parameters": {
						"Effect": {
							"value": "[parameters('enableAscForKeyVault')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForDns",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/2370a3c1-4a25-4283-a91a-c9c1a145fb2f",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForDns')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForArm",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b7021b2b-08fd-4dc0-9de7-3c6ece09faf9",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForArm')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "defenderForSqlPaas",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b99b73e7-074b-4089-9395-b7236f094491",
					"parameters": {
						"effect": {
							"value": "[parameters('enableAscForSql')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "securityEmailContact",
					"policyDefinitionId": "${root_scope_resource_id}/providers/Microsoft.Authorization/policyDefinitions/Deploy-ASC-SecurityContacts",
					"parameters": {
						"emailSecurityContact": {
							"value": "[parameters('emailSecurityContact')]"
						}
					},
					"groupNames": []
				},
				{
					"policyDefinitionReferenceId": "ascExport",
					"policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/ffb6f416-7bd2-4488-8828-56585fef2be9",
					"parameters": {
						"resourceGroupName": {
							"value": "[parameters('ascExportResourceGroupName')]"
						},
						"resourceGroupLocation": {
							"value": "[parameters('ascExportResourceGroupLocation')]"
						},
						"workspaceResourceId": {
							"value": "[parameters('logAnalytics')]"
						}
					},
					"groupNames": []
				}
			],
			"policyDefinitionGroups": null
		}
	}`)
}
