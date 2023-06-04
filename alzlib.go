package alzlib

import (
	"embed"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/matt-FFFFFF/alzlib/processor"
)

//go:embed lib
var lib embed.FS

// AlzLib is the structure that gets built from the the library files
// do not create this directly, use NewAlzLib instead.
type AlzLib struct {
	Archetypes           map[string]*Archetype
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	PolicyAssignments    map[string]*armpolicy.Assignment
	RoleDefinitions      map[string]*armauthorization.RoleDefinition
	AllowOverwrite       bool
	libdir               string
}

// Archetype represents an archetype definition that hasn't been assigned to a management group
type Archetype struct {
	//AlzLib               *AlzLib
	PolicyDefinitions    map[string]*armpolicy.Definition
	PolicyAssignments    map[string]*armpolicy.Assignment
	PolicySetDefinitions map[string]*armpolicy.SetDefinition
	RoleDefinitions      map[string]*armauthorization.RoleDefinition
	//RoleAssignments      map[string]*armauthorization.RoleAssignment
}

// AlzManagementGroup represents an Azure Management Group, with links to parent and children.
type AlzManagementGroup struct {
	Name                 string
	DisplayName          string
	PolicyDefinitions    map[string]armpolicy.Definition
	PolicySetDefinitions map[string]armpolicy.SetDefinition
	PolicyAssignments    map[string]armpolicy.Assignment
	RoleAssignments      map[string]armauthorization.RoleAssignment
	children             []*AlzManagementGroup
	parent               *AlzManagementGroup
}

// NewAlzLib returns a new instance of the alzlib library, optionally using the supplied directory
// for additional policy (set) definitions.
func NewAlzLib(dir string) (*AlzLib, error) {
	if dir != "" {
		if err := checkDirExists(dir); err != nil {
			return nil, err
		}
	}

	az := &AlzLib{
		Archetypes:           make(map[string]*Archetype),
		PolicyAssignments:    make(map[string]*armpolicy.Assignment),
		PolicyDefinitions:    make(map[string]*armpolicy.Definition),
		PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
		AllowOverwrite:       false,
		libdir:               dir,
	}
	return az, nil
}

// Init processes the built-in library and optionally the local library
// It populates the struct with the results of the processing
func (az *AlzLib) Init() error {
	res := new(processor.Result)
	pc := processor.NewProcessorClient(lib)
	if err := pc.Process(res); err != nil {
		return fmt.Errorf("error processing built-in library: %s", err)
	}

	// Put results into the AlzLib
	if err := az.addProcessedResult(res); err != nil {
		return err
	}
	if err := az.generateArchetypes(res); err != nil {
		return err
	}

	// If we have a directory, process that too
	if az.libdir == "" {
		return nil
	}

	localLib := os.DirFS(az.libdir)
	pc = processor.NewProcessorClient(localLib)
	res = new(processor.Result)
	if err := pc.Process(res); err != nil {
		return fmt.Errorf("error processing local library (%s): %s", az.libdir, err)
	}
	res.PolicyAssignments = nil
	res.LibArchetypes = nil
	// Put the results into the AlzLib
	az.addProcessedResult(res)

	return nil
}

// addProcessedResult adds the results of a processed library to the AlzLib
func (az *AlzLib) addProcessedResult(res *processor.Result) error {
	for k, v := range res.PolicyDefinitions {
		if _, exists := az.PolicyDefinitions[k]; exists && !az.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.PolicyDefinitions[k] = v
	}
	for k, v := range res.PolicySetDefinitions {
		if _, exists := az.PolicySetDefinitions[k]; exists && !az.AllowOverwrite {
			return fmt.Errorf("policy definition %s already exists in the library", k)
		}
		az.PolicySetDefinitions[k] = v
	}
	for k, v := range res.PolicyAssignments {
		if _, exists := az.PolicyAssignments[k]; exists && !az.AllowOverwrite {
			return fmt.Errorf("policy assignment %s already exists in the library", k)
		}
		az.PolicyAssignments[k] = v
	}
	for k, v := range res.RoleDefinitions {
		if _, exists := az.RoleDefinitions[k]; exists && !az.AllowOverwrite {
			return fmt.Errorf("role definition %s already exists in the library", k)
		}
		az.RoleDefinitions[k] = v
	}
	return nil
}

func (az *AlzLib) generateArchetypes(res *processor.Result) error {
	for k, v := range res.LibArchetypes {
		if _, exists := az.Archetypes[k]; exists {
			return fmt.Errorf("archetype %s already exists in the library", v.Name)
		}
		arch := &Archetype{
			PolicyDefinitions:    make(map[string]*armpolicy.Definition),
			PolicyAssignments:    make(map[string]*armpolicy.Assignment),
			PolicySetDefinitions: make(map[string]*armpolicy.SetDefinition),
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
		az.Archetypes[v.Name] = arch
	}
	return nil
}

// checkDirExists checks if the supplied directory exists and is a directory
func checkDirExists(dir string) error {
	fs, err := os.Stat(dir)
	if err == os.ErrNotExist {
		return fmt.Errorf("the supplied lib directory does not exist: %s. %s", dir, err)
	}
	if err != nil {
		return fmt.Errorf("error checking lib dir exists: %s. %s", dir, err)
	}
	// The error is nil, so let's check if it's actually a directory
	if !fs.IsDir() {
		return fmt.Errorf("%s is not a directory and it should be", dir)
	}
	return nil
}
