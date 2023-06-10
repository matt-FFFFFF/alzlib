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
	Archetypes           map[string]*Archetype
	Options              *AlzLibOptions
	PolicyAssignments    map[string]*armpolicy.Assignment
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	RoleDefinitions      map[string]*armauthorization.RoleDefinition
	Deployment           *DeploymentType
	clients              *azureClients
	mu                   sync.RWMutex
}

type azureClients struct {
	policyClient *armpolicy.ClientFactory
}

// AlzLibOptions are options for the AlzLib.
// This is created by NewAlzLib.
type AlzLibOptions struct {
	AllowOverwrite bool
	Parallelism    int
}

// Archetype represents an archetype definition that hasn't been assigned to a management group
type Archetype struct {
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicyAssignments    map[string]*armpolicy.Assignment
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	RoleDefinitions      map[string]*armauthorization.RoleDefinition
	RoleAssignments      map[string]*armauthorization.RoleAssignment
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib() (*AlzLib, error) {
	az := &AlzLib{
		Options: &AlzLibOptions{
			Parallelism:    defaultParallelism,
			AllowOverwrite: false,
		},
		Archetypes:           make(map[string]*Archetype),
		PolicyAssignments:    make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:    make(map[string]*armpolicy.Definition),
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		RoleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
		clients:              new(azureClients),
	}
	return az, nil
}

// AddPolicyClient adds an authenticeted *armpolicy.ClientFactory to the AlzLib struct.
// This is needed to get policy objects from Azure.
func (az *AlzLib) AddPolicyClient(client *armpolicy.ClientFactory) {
	az.clients.policyClient = client
}

func (az *AlzLib) NewDeployment(do *DeploymentOptions) {
	az.Deployment = &DeploymentType{
		options: do,
		MGs:     make(map[string]*AlzManagementGroup),
	}
}

// Init processes ALZ libraries, supplied as fs.FS interfaces.
// These are typically the embed.FS var Lib, or an os.DirFS.
// It populates the struct with the results of the processing.
func (az *AlzLib) Init(ctx context.Context, libs ...fs.FS) error {
	// Process the libraries
	for i, lib := range libs {
		res := new(processor.Result)
		pc := processor.NewProcessorClient(lib)
		if err := pc.Process(res); err != nil {
			return fmt.Errorf("error processing library %v: %w", lib, err)
		}

		// Only support definitions  (role, policy, policy set) in the first library
		if i != 0 {
			res.PolicyAssignments = make(map[string]*armpolicy.Assignment, 0)
			res.LibArchetypes = make(map[string]*processor.LibArchetype, 0)
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

	// Get the assigned built-in definitions and set definitions
	builtInDefs := make([]string, 0)
	builtInSetDefs := make([]string, 0)
	for _, arch := range az.Archetypes {
		for _, pa := range arch.PolicyAssignments {
			pd := *pa.Properties.PolicyDefinitionID
			switch strings.ToLower(lastButOneSegment(pd)) {
			case "policydefinitions":
				if _, exists := az.PolicyDefinitions[lastSegment(pd)]; !exists {
					builtInDefs = append(builtInDefs, lastSegment(pd))
				}
			case "policysetdefinitions":
				if _, exists := az.PolicySetDefinitions[lastSegment(pd)]; !exists {
					builtInSetDefs = append(builtInSetDefs, lastSegment(pd))
				}
			default:
				return fmt.Errorf("unexpected policy definition type when processing assignments: %s", pd)
			}
		}
	}

	// Add the referenced built-in definitions and set definitions to the AlzLib struct
	// so that we can use the data to determine the correct role assignments at scope.
	if len(builtInDefs) != 0 {
		if err := az.GetBuiltInPolicies(ctx, builtInDefs); err != nil {
			return err
		}
	}
	if len(builtInSetDefs) != 0 {
		if err := az.GetBuiltInPolicySets(ctx, builtInSetDefs); err != nil {
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
			if _, exists := az.PolicyDefinitions[name]; exists {
				return nil
			}
			resp, err := pdclient.GetBuiltIn(ctx, name, nil)
			if err != nil {
				return err
			}
			az.PolicyDefinitions[name] = &resp.Definition
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
			if _, exists := az.PolicySetDefinitions[name]; exists {
				return nil
			}
			resp, err := psclient.GetBuiltIn(ctxErrGroup, name, nil)
			if err != nil {
				return err
			}
			// Add set definition to the AlzLib
			az.PolicySetDefinitions[name] = &resp.SetDefinition
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
		for _, ref := range az.PolicySetDefinitions[name].Properties.PolicyDefinitions {
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
		if _, exists := az.PolicyDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.PolicyDefinitions[k] = v
	}
	for k, v := range res.PolicySetDefinitions {
		if _, exists := az.PolicySetDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.PolicySetDefinitions[k] = v
	}
	for k, v := range res.PolicyAssignments {
		if _, exists := az.PolicyAssignments[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("policy assignment %s already exists in the library", k)
		}
		az.PolicyAssignments[k] = v
	}
	for k, v := range res.RoleDefinitions {
		if _, exists := az.RoleDefinitions[k]; exists && !az.Options.AllowOverwrite {
			return fmt.Errorf("role definition %s already exists in the library", k)
		}
		az.RoleDefinitions[k] = v
	}
	return nil
}

// generateArchetypes generates the archetypes from the result of the processor.
// The archetypes are stored in the AlzLib instance.
func (az *AlzLib) generateArchetypes(res *processor.Result) error {
	for k, v := range res.LibArchetypes {
		if _, exists := az.Archetypes[k]; exists {
			return fmt.Errorf("archetype %s already exists in the library", v.Name)
		}
		arch := &Archetype{
			PolicyDefinitions:    make(map[string]*armpolicy.Definition),
			PolicyAssignments:    make(map[string]*armpolicy.Assignment),
			PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
			RoleDefinitions:      make(map[string]*armauthorization.RoleDefinition),
		}
		for _, pd := range v.PolicyDefinitions {
			if _, ok := az.PolicyDefinitions[pd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy definition %s does not exist in the library", k, pd)
			}
			arch.PolicyDefinitions[pd] = az.PolicyDefinitions[pd]
		}
		for _, psd := range v.PolicySetDefinitions {
			if _, ok := az.PolicySetDefinitions[psd]; !ok {
				return fmt.Errorf("error processing archetype %s, policy set definition %s does not exist in the library", k, psd)
			}
			arch.PolicySetDefinitions[psd] = az.PolicySetDefinitions[psd]
		}
		for _, pa := range v.PolicyAssignments {
			if _, ok := az.PolicyAssignments[pa]; !ok {
				return fmt.Errorf("error processing archetype %s, policy assignment %s does not exist in the library", k, pa)
			}
			arch.PolicyAssignments[pa] = az.PolicyAssignments[pa]
		}
		for _, rd := range v.RoleDefinitions {
			if _, ok := az.RoleDefinitions[rd]; !ok {
				return fmt.Errorf("error processing archetype %s, role definition %s does not exist in the library", k, rd)
			}
			arch.RoleDefinitions[rd] = az.RoleDefinitions[rd]
		}
		az.Archetypes[v.Name] = arch
	}
	return nil
}

// WithWellKnownPolicyParameters adds the well known policy parameters to the archetype
// ready for the caller to further customize, before sending back as a parameter to
// the Deployment.AddManagementGroup method
func (arch *Archetype) WithWellKnownPolicyParameters(opts *DeploymentOptions) *Archetype {
	result := new(Archetype)
	*result = *arch
	wk := getWellKnownPolicyAssignmentParameterValues(opts)
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

	return result
}

// lastSegment returns the last segment of a string separated by "/"
func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

// lastButOneSegment returns the last but one segment of a string separated by "/"
func lastButOneSegment(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-2]
}
