// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package alzlib

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/matt-FFFFFF/alzlib/processor"
	"golang.org/x/sync/errgroup"
)

const (
	defaultParallelism = 10 // default number of parallel requests to make to Azure APIs
)

// Embed the Lib dir into the binary
//
//go:embed lib
var Lib embed.FS

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
type AlzLib struct {
	Options    *AlzLibOptions
	Deployment *DeploymentType // Deployment is the deployment object that stores the management group hierarchy

	archetypes           map[string]*Archetype
	policyAssignments    map[string]*armpolicy.Assignment
	policyDefinitions    map[string]*armpolicy.Definition
	policySetDefinitions map[string]*armpolicy.SetDefinition
	roleDefinitions      map[string]*armauthorization.RoleDefinition
	clients              *azureClients
	mu                   sync.RWMutex // mu is a mutex to concurrency protect the AlzLib maps (not the Deployment maps, which are protected by the Deployment mutex)
}

type azureClients struct {
	policyClient *armpolicy.ClientFactory
}

// AlzLibOptions are options for the AlzLib.
// This is created by NewAlzLib.
type AlzLibOptions struct {
	AllowOverwrite bool // AllowOverwrite allows overwriting of existing policy assignments when processing additional libraries with AlzLib.Init()
	Parallelism    int  // Parallelism is the number of parallel requests to make to Azure APIs
}

// Archetype represents an archetype definition that hasn't been assigned to a management group
type Archetype struct {
	PolicyDefinitions     map[string]*armpolicy.Definition
	PolicyAssignments     map[string]*armpolicy.Assignment
	PolicySetDefinitions  map[string]*armpolicy.SetDefinition
	RoleDefinitions       map[string]*armauthorization.RoleDefinition
	wellKnownPolicyValues *WellKnownPolicyValues // options are used to populate the Archetype with well known parameter values
}

// WellKnownPolicyValues represents options for a deployment
// These are values that are typically replaced in the deployed resources
// E.g. location, log analytics workspace ID, etc.
type WellKnownPolicyValues struct {
	DefaultLocation                string
	DefaultLogAnalyticsWorkspaceId string
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib() *AlzLib {
	az := &AlzLib{
		Options:    getDefaultAlzLibOptions(),
		archetypes: make(map[string]*Archetype),
		Deployment: &DeploymentType{
			MGs: make(map[string]*AlzManagementGroup),
		},
		policyAssignments:    make(map[string]*armpolicy.Assignment),
		policyDefinitions:    make(map[string]*armpolicy.Definition),
		policySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		roleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
		clients:              new(azureClients),
	}
	return az
}

func getDefaultAlzLibOptions() *AlzLibOptions {
	return &AlzLibOptions{
		Parallelism:    defaultParallelism,
		AllowOverwrite: false,
	}
}

// ListArchetypes returns a list of the archetypes in the AlzLib struct.
func (az *AlzLib) ListArchetypes() []string {
	result := make([]string, 0, len(az.archetypes))
	for k := range az.archetypes {
		result = append(result, k)
	}
	return result
}

// CopyArchetype returns a copy of the requested archetype by name.
// The returned struct can be used as a parameter to the Deployment.AddManagementGroup method.
func (az *AlzLib) CopyArchetype(name string) (*Archetype, error) {
	if arch, ok := az.archetypes[name]; ok {
		rtn := new(Archetype)
		*rtn = *arch
		return rtn, nil
	}
	return nil, fmt.Errorf("archetype %s not found", name)
}

// PolicyDefinitionExists returns true if the policy definition exists in the AlzLib struct.
func (az *AlzLib) PolicyDefinitionExists(name string) bool {
	_, exists := az.policyDefinitions[name]
	return exists
}

// PolicySetDefinitionExists returns true if the policy set definition exists in the AlzLib struct.
func (az *AlzLib) PolicySetDefinitionExists(name string) bool {
	_, exists := az.policySetDefinitions[name]
	return exists
}

// PolicyAssignmentExists returns true if the policy assignment exists in the AlzLib struct.
func (az *AlzLib) PolicyAssignmentExists(name string) bool {
	_, exists := az.policyAssignments[name]
	return exists
}

// RoleDefinitionExists returns true if the role definition exists in the AlzLib struct.
func (az *AlzLib) RoleDefinitionExists(name string) bool {
	_, exists := az.roleDefinitions[name]
	return exists
}

// AddPolicyClient adds an authenticated *armpolicy.ClientFactory to the AlzLib struct.
// This is needed to get policy objects from Azure.
func (az *AlzLib) AddPolicyClient(client *armpolicy.ClientFactory) {
	az.clients.policyClient = client
}

// Init processes ALZ libraries, supplied as fs.FS interfaces.
// These are typically the embed.FS global var `Lib`, or an `os.DirFS`.
// It populates the struct with the results of the processing.
func (az *AlzLib) Init(ctx context.Context, libs ...fs.FS) error {
	if az.Options == nil || az.Options.Parallelism == 0 {
		return errors.New("alzlib Options not set or parallelism is 0")
	}

	// Process the libraries
	for i, lib := range libs {
		res := new(processor.Result)
		pc := processor.NewProcessorClient(lib)
		if err := pc.Process(res); err != nil {
			return fmt.Errorf("error processing library %v: %w", lib, err)
		}

		// Put results into the AlzLib
		if err := az.addProcessedResult(res); err != nil {
			return err
		}

		// Generate archetypes from the first library
		if i == 0 {
			if err := az.generateArchetypes(res); err != nil {
				return err
			}
		}
	}

	// Get the policy definitions and policy set definitions referenced by the policy assignments
	assignedPolicyDefinitionIds := make([]string, 0)
	for _, arch := range az.archetypes {
		for _, pa := range arch.PolicyAssignments {
			assignedPolicyDefinitionIds = append(assignedPolicyDefinitionIds, *pa.Properties.PolicyDefinitionID)
		}
	}

	if err := az.GetDefinitionsFromAzure(ctx, assignedPolicyDefinitionIds); err != nil {
		return err
	}

	return nil
}

// GetDefinitionsFromAzure takes a slice of strings containing Azure resource IDs of policy definitions and policy set definitions.
// It then fetches them from Azure if needed and adds them to the AlzLib struct.
// For set definitions we need to get all of them, even if they exist in AlzLib already because they can contain built-in definitions.
func (az *AlzLib) GetDefinitionsFromAzure(ctx context.Context, pds []string) error {
	policyDefsToGet := make([]string, 0)
	policySetDefsToGet := make([]string, 0)
	for _, pd := range pds {
		switch strings.ToLower(lastButOneSegment(pd)) {
		case "policydefinitions":
			if _, exists := az.policyDefinitions[lastSegment(pd)]; !exists {
				policyDefsToGet = appendIfMissing(policyDefsToGet, lastSegment(pd))
			}
		case "policysetdefinitions":
			// If the set is not present, OR if the set contains referenced definitions that are not present
			// add it to the list of set defs to get
			psd, exists := az.policySetDefinitions[lastSegment(pd)]
			if exists {
				for _, ref := range psd.Properties.PolicyDefinitions {
					if ref.PolicyDefinitionID == nil {
						return fmt.Errorf("policy set definition %s has a nil policy definition ID", *psd.Name)
					}
					if _, exists := az.policyDefinitions[lastSegment(*ref.PolicyDefinitionID)]; !exists {
						policyDefsToGet = appendIfMissing(policyDefsToGet, lastSegment(*ref.PolicyDefinitionID))
					}
				}
			} else {
				policySetDefsToGet = appendIfMissing(policySetDefsToGet, lastSegment(pd))
			}

		default:
			return fmt.Errorf("unexpected policy definition type when processing assignments: %s", pd)
		}
	}

	// Add the referenced built-in definitions and set definitions to the AlzLib struct
	// so that we can use the data to determine the correct role assignments at scope.
	if len(policyDefsToGet) != 0 {
		if err := az.GetBuiltInPolicies(ctx, policyDefsToGet); err != nil {
			return err
		}
	}
	if len(policySetDefsToGet) != 0 {
		if err := az.GetBuiltInPolicySets(ctx, policySetDefsToGet); err != nil {
			return err
		}
	}
	return nil
}

// GetBuiltInPolicies retrieves the built-in policy definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) GetBuiltInPolicies(ctx context.Context, names []string) error {
	if az.clients.policyClient == nil {
		return errors.New("policy client not set")
	}
	grp, ctx := errgroup.WithContext(ctx)
	grp.SetLimit(az.Options.Parallelism)
	pdclient := az.clients.policyClient.NewDefinitionsClient()
	for _, name := range names {
		name := name
		grp.Go(func() error {
			az.mu.Lock()
			defer az.mu.Unlock()
			if _, exists := az.policyDefinitions[name]; exists {
				return nil
			}
			resp, err := pdclient.GetBuiltIn(ctx, name, nil)
			if err != nil {
				return err
			}
			az.policyDefinitions[name] = &resp.Definition
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return err
	}
	return nil
}

// GetBuiltInPolicySets retrieves the built-in policy set definitions with the given names
// and adds them to the AlzLib struct.
func (az *AlzLib) GetBuiltInPolicySets(ctx context.Context, names []string) error {
	if az.clients.policyClient == nil {
		return errors.New("policy client not set")
	}
	grp, ctxErrGroup := errgroup.WithContext(ctx)
	grp.SetLimit(az.Options.Parallelism)

	// We need to keep track of the names we've processed
	// so that we can get the policy definitions referenced within them
	processedNames := make([]string, 0, len(names))
	var mu sync.Mutex

	psclient := az.clients.policyClient.NewSetDefinitionsClient()
	for _, name := range names {
		name := name
		grp.Go(func() error {
			az.mu.Lock()
			defer az.mu.Unlock()
			if _, exists := az.policySetDefinitions[name]; exists {
				return nil
			}
			resp, err := psclient.GetBuiltIn(ctxErrGroup, name, nil)
			if err != nil {
				return err
			}
			// Add set definition to the AlzLib
			az.policySetDefinitions[name] = &resp.SetDefinition
			// Add name to processedNames
			mu.Lock()
			defer mu.Unlock()
			processedNames = append(processedNames, name)
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return err
	}

	// Get the policy definitions for newly added policy set definitions
	defnames := make([]string, 0)
	for _, name := range names {
		name := name
		for _, ref := range az.policySetDefinitions[name].Properties.PolicyDefinitions {
			defnames = append(defnames, lastSegment(*ref.PolicyDefinitionID))
		}
	}
	if err := az.GetBuiltInPolicies(ctx, defnames); err != nil {
		return err
	}

	return nil
}

// addProcessedResult adds the results of a processed library to the AlzLib
func (az *AlzLib) addProcessedResult(res *processor.Result) error {
	for k, v := range res.PolicyDefinitions {
		if _, exists := az.policyDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.policyDefinitions[k] = v
	}
	for k, v := range res.PolicySetDefinitions {
		if _, exists := az.policySetDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.policySetDefinitions[k] = v
	}
	for k, v := range res.PolicyAssignments {
		if _, exists := az.policyAssignments[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy assignment %s already exists in the library", k)
		}
		az.policyAssignments[k] = v
	}
	for k, v := range res.RoleDefinitions {
		if _, exists := az.roleDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("role definition %s already exists in the library", k)
		}
		az.roleDefinitions[k] = v
	}
	return nil
}

// generateArchetypes generates the archetypes from the result of the processor.
// The archetypes are stored in the AlzLib instance.
func (az *AlzLib) generateArchetypes(res *processor.Result) error {
	// add empty archetype if it doesn't exist
	if _, exists := res.LibArchetypes["empty"]; !exists {
		res.LibArchetypes["empty"] = &processor.LibArchetype{
			Name:                 "empty",
			PolicyAssignments:    make([]string, 0),
			PolicyDefinitions:    make([]string, 0),
			PolicySetDefinitions: make([]string, 0),
			RoleDefinitions:      make([]string, 0),
		}
	}

	// generate alzlib archetypes
	for k, v := range res.LibArchetypes {
		if _, exists := az.archetypes[k]; exists {
			return fmt.Errorf("archetype %s already exists in the library", v.Name)
		}
		arch := &Archetype{
			PolicyDefinitions:    make(map[string]*armpolicy.Definition),
			PolicyAssignments:    make(map[string]*armpolicy.Assignment),
			PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
			RoleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
		}
		for _, pd := range v.PolicyDefinitions {
			if _, ok := az.policyDefinitions[pd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy definition %s does not exist in the library", k, pd)
			}
			arch.PolicyDefinitions[pd] = az.policyDefinitions[pd]
		}
		for _, psd := range v.PolicySetDefinitions {
			if _, ok := az.policySetDefinitions[psd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy set definition %s does not exist in the library", k, psd)
			}
			arch.PolicySetDefinitions[psd] = az.policySetDefinitions[psd]
		}
		for _, pa := range v.PolicyAssignments {
			if _, ok := az.policyAssignments[pa]; !ok {
				return fmt.Errorf("error processing archetype %s, policy assignment %s does not exist in the library", k, pa)
			}
			arch.PolicyAssignments[pa] = az.policyAssignments[pa]
		}
		for _, rd := range v.RoleDefinitions {
			if _, ok := az.roleDefinitions[rd]; !ok {
				return fmt.Errorf("error processing archetype %s, role definition %s does not exist in the library", k, rd)
			}
			arch.RoleDefinitions[rd] = az.roleDefinitions[rd]
		}
		az.archetypes[v.Name] = arch
	}
	return nil
}

// WithWellKnownPolicyValues adds the well known policy parameters to the archetype
// ready for the caller to further customize, before sending back as a parameter to
// the Deployment.AddManagementGroup method
func (arch *Archetype) WithWellKnownPolicyValues(wkpv *WellKnownPolicyValues) *Archetype {
	result := new(Archetype)
	*result = *arch
	wk := getWellKnownPolicyAssignmentParameterValues(wkpv)
	for assignmentName, params := range wk {
		pa, ok := result.PolicyAssignments[assignmentName]
		if !ok {
			continue
		}
		if pa.Properties.Parameters == nil {
			pa.Properties.Parameters = make(map[string]*armpolicy.ParameterValuesValue, 1)
		}
		for param, value := range params {
			pa.Properties.Parameters[param] = value
		}
	}
	result.wellKnownPolicyValues = wkpv
	return result
}

// lastSegment returns the last segment of a string separated by "/"
func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) <= 1 {
		return "s"
	}
	return parts[len(parts)-1]
}

// lastButOneSegment returns the last but one segment of a string separated by "/"
func lastButOneSegment(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) <= 2 {
		return "s"
	}
	return parts[len(parts)-2]
}
