package alzlib

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestWellKnownParameterReplacement demonstrates the replacement of well-known parameters
func TestWellKnownParameterReplacement(t *testing.T) {
	az, err := NewAlzLib()
	if err != nil {
		fmt.Println(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/wellknownparameters")
	err = az.Init(ctx, dirfs)
	if err != nil {
		fmt.Println(err)
	}

	do := &DeploymentOptions{
		DefaultLocation:                "eastus",
		DefaultLogAnalyticsWorkspaceId: "testlaworkspaceid",
	}

	az.NewDeployment(do)
	arch := az.Archetypes["test"].WithWellKnownPolicyParameters(do)
	az.Deployment.AddManagementGroup("test", "test", "", arch)

	paramValue := az.Deployment.MGs["test"].PolicyAssignments["Deploy-AzActivity-Log"].Properties.Parameters["logAnalytics"].Value
	assert.Equal(t, "testlaworkspaceid", paramValue)
}
