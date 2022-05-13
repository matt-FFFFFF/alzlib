package alzlib

import (
	"errors"
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
			return errors.New(fmt.Sprintf("Error walking directory %s: %s", dir, err))
		}
		// Skip directories
		if info.IsDir() {
			return nil
		}
		return alzlib.processLibFile(path, info)
	}); err != nil {
		return nil, err
	}

	return &AlzLib{}, nil
}

// checkDirExists checks if the supplied directory exists and is a directory
func checkDirExists(dir string) error {
	fs, err := os.Stat(dir)
	if err != nil {
		return err
	}
	// The error is nil, so let's check if it's actually a directory
	if !fs.IsDir() {
		return errors.New(fmt.Sprintf("%s is not a directory and it should be.", dir))
	}
	return nil
}

// processLibFile processes the supplied file and adds the processed contents to the struct for validation later
func (alzlib *AlzLib) processLibFile(path string, info fs.FileInfo) error {
	err := error(nil)
	switch n := strings.ToLower(info.Name()); {
	case strings.HasPrefix(n, archetypeDefinitionPrefix):
		err = readAndProcessFile(alzlib, path, processPolicyDefinition)
	}
	if err != nil {
		err = errors.New(fmt.Sprintf("Error processing file %s: %s", path, err))
	}
	return nil
}

// readAndProcessFile reads the file at the supplied path and processes it using the supplied processFunc
func readAndProcessFile(alzlib *AlzLib, path string, processFn processFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	if err := processFn(alzlib, data); err != nil {
		return err
	}

	return nil
}
