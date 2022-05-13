package alzlib

import (
	"testing"

	"gotest.tools/v3/assert"
)

func Test_processArchetypeDefinition_valid(t *testing.T) {
	sampleData := getSampleArchetypeDefinition()
	az := &AlzLib{
		libArchetypeDefinitions: make([]libArchetypeDefinition, 0),
	}

	assert.NilError(t, processArchetypeDefinition(az, sampleData))
	assert.Equal(t, len(az.libArchetypeDefinitions), 1)
	assert.Equal(t, az.libArchetypeDefinitions[0].id, "es_root")
	assert.Equal(t, len(az.libArchetypeDefinitions[0].PolicyAssignments), 8)
	assert.Equal(t, len(az.libArchetypeDefinitions[0].PolicyDefinitions), 104)
	assert.Equal(t, len(az.libArchetypeDefinitions[0].PolicySetDefinitions), 7)
}

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
				"parameters": {},
				"access_control": {}
			}
		}
	}
	`)
}
