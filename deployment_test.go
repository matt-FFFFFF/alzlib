package alzlib

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func ExampleAlzLib_NewDeployment() {
	az, err := NewAlzLib("")
	if err != nil {
		fmt.Println(err)
	}
	cred, _ := azidentity.NewDefaultAzureCredential(nil)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = az.Init(ctx)
	if err != nil {
		fmt.Println(err)
	}
	dopts := new(DeploymentOptions)
	dopts.DefaultLocation = "uksouth"
	dopts.DefaultLogAnalyticsWorkspaceId = "testlaworkspace"
	dep := az.NewDeployment(dopts)
	rootArch := az.Archetypes["root"].WithWellKnownPolicyParameters(dep.options)
	if err := dep.AddManagementGroup("myroot", "root management group", "", rootArch); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", dep.MGs["myroot"].PolicyAssignments["Deploy-AzActivity-Log"].Properties.Parameters["logAnalytics"].Value)
	// Output:
	// testlaworkspace
}
