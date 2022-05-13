package alzlib

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// These are the file prefixes for the resource types
const archetypeDefinitionPrefix = "archetype_definition_"
const policyAssignmentPrefix = "policy_assignment_"
const policyDefinitionPrefix = "policy_definition_"
const policySetDefinitionPrefix = "policy_set_definition_"

// New returns a new instance of the alzlib library
func New(dir string) (*AlzLib, error) {

	if err := checkDirExists(dir); err != nil {
		return nil, err
	}

	alzlib := &AlzLib{}

	// Walk the directory and process files
	if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("Error walking directory %s: %s", dir, err)
		}
		// Skip directories
		if info.IsDir() {
			return nil
		}
		return alzlib.processLibFile(path, info)
	}); err != nil {
		return nil, err
	}

	return alzlib, nil
}

// checkDirExists checks if the supplied directory exists and is a directory
func checkDirExists(dir string) error {
	fs, err := os.Stat(dir)
	if err != nil {
		return err
	}
	// The error is nil, so let's check if it's actually a directory
	if !fs.IsDir() {
		return fmt.Errorf("%s is not a directory and it should be", dir)
	}
	return nil
}

// processLibFile processes the supplied file and adds the processed contents to the struct for validation later
func (alzlib *AlzLib) processLibFile(path string, info fs.FileInfo) error {
	err := error(nil)
	// process by file type
	switch n := strings.ToLower(info.Name()); {

	// if the file is a policy definition
	case strings.HasPrefix(n, policyDefinitionPrefix):
		err = readAndProcessFile(alzlib, path, processPolicyDefinition)

	// if the file is a policy set definition
	case strings.HasPrefix(n, policySetDefinitionPrefix):
		err = readAndProcessFile(alzlib, path, processPolicySetDefinition)
	}

	// If there's an error, wrap it with the file path
	if err != nil {
		err = fmt.Errorf("error processing file %s: %s", path, err)
	}
	return err
}

// readAndProcessFile reads the file at the supplied path and processes it using the supplied processFunc
func readAndProcessFile(alzlib *AlzLib, path string, processFn processFunc) error {
	// open the file and read the contents
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	// pass the  data to the supplied process function
	if err := processFn(alzlib, data); err != nil {
		return err
	}

	return nil
}
