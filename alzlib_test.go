// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/stretchr/testify/assert"
)

// ExampleAlzLib_Init demonstrates the creation of a new AlzLib based a sample directory
func ExampleAlzLib_Init() {
	az := NewAlzLib()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirfs := os.DirFS("./testdata/simple")
	err := az.Init(ctx, dirfs)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Archetype count: %d\n", len(az.Archetypes))
	// Output:
	// Archetype count: 1
}

// Test_NewAlzLib_noDir tests the creation of a new AlzLib when supplied with a path
// that does not exist.
// The error details are checked for the expected error message.
func TestNewAlzLibWithNoDir(t *testing.T) {
	az := NewAlzLib()
	path := filepath.Join("testdata", "doesnotexist")
	dir := os.DirFS(path)
	err := az.Init(context.Background(), dir)

	assert.ErrorIs(t, err, os.ErrNotExist)
}

// Test_NewAlzLibDuplicateArchetypeDefinition tests the creation of a new AlzLib from a invalid source directory
func Test_NewAlzLibDuplicateArchetypeDefinition(t *testing.T) {
	az := NewAlzLib()
	dir := os.DirFS("./testdata/badlib-duplicatearchetypedef")
	err := az.Init(context.Background(), dir)
	assert.ErrorContains(t, err, "archetype with name duplicate already exists")
}

func TestGetBuiltInPolicy(t *testing.T) {
	az := NewAlzLib()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err = az.GetBuiltInPolicies(context.Background(), []string{"8154e3b3-cc52-40be-9407-7756581d71f6"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.PolicyDefinitions))
	assert.Equal(t, "Microsoft Managed Control 1614 - Developer Security Architecture And Design", *az.PolicyDefinitions["8154e3b3-cc52-40be-9407-7756581d71f6"].Properties.DisplayName)
}

func TestGetBuiltInPolicySet(t *testing.T) {
	az := NewAlzLib()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	assert.NoError(t, err)
	cf, _ := armpolicy.NewClientFactory("", cred, nil)
	az.AddPolicyClient(cf)
	err = az.GetBuiltInPolicySets(context.Background(), []string{"7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(az.PolicySetDefinitions))
	assert.Equal(t, "Evaluate Private Link Usage Across All Supported Azure Resources", *az.PolicySetDefinitions["7379ef4c-89b0-48b6-a5cc-fd3a75eaef93"].Properties.DisplayName)
	assert.Equal(t, 30, len(az.PolicyDefinitions))
}
