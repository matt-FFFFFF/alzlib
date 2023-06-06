// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

// Test_NewAlzLib tests the valid creation of a new AlzLib from a valid source directory
func Test_NewAlzLib(t *testing.T) {
	az, err := NewAlzLib("")
	cred, _ := azidentity.NewDefaultAzureCredential(nil)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	assert.NoError(t, err)
	assert.NoError(t, az.Init(context.Background()))
}

// Test_NewAlzLib_noDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func Test_NewAlzLib_noDir(t *testing.T) {
	_, err := NewAlzLib("./testdata/doesnotexist")
	assert.ErrorContains(t, err, "no such file or directory")
}

// Test_NewAlzLib_notADir tests the creation of a new AlzLib when supplied with a valid
// path that is not a directory.
// The error details are checked for the expected error message.
func Test_NewAlzLib_notADir(t *testing.T) {
	_, err := NewAlzLib("./testdata/notadirectory")
	assert.ErrorContains(t, err, "is not a directory and it should be")
}

// Benchmark_NewAlzLib benchmarks the creation of a new AlzLib based on the embedded data set
func Benchmark_NewAlzLib(b *testing.B) {
	_, e := NewAlzLib("")
	if e != nil {
		b.Error(e)
	}
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid source directory
func Test_NewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
	az, _ := NewAlzLib("./testdata/badlib-duplicatearchetypedef")
	assert.ErrorContains(t, az.Init(context.Background()), "archetype with name duplicate already exists")
}

func TestGetBuiltInPolicy(t *testing.T) {
	az, _ := NewAlzLib("")
	cred, _ := azidentity.NewDefaultAzureCredential(nil)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err := az.GetBuiltInPolicies(context.Background(), []string{"8154e3b3-cc52-40be-9407-7756581d71f6"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.PolicyDefinitions))
	assert.Equal(t, "Microsoft Managed Control 1614 - Developer Security Architecture And Design", *az.PolicyDefinitions["8154e3b3-cc52-40be-9407-7756581d71f6"].Properties.DisplayName)
}

func TestGetBuiltInPolicySet(t *testing.T) {
	az, _ := NewAlzLib("")
	cred, _ := azidentity.NewDefaultAzureCredential(nil)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err := az.GetBuiltInPolicySets(context.Background(), []string{"7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.PolicySetDefinitions))
	assert.Equal(t, "Evaluate Private Link Usage Across All Supported Azure Resources", *az.PolicySetDefinitions["7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"].Properties.DisplayName)
	assert.Equal(t, 30, len(az.PolicyDefinitions))
}
