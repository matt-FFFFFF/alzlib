package alzlib

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func processPolicyDefinition(alzlib *AlzLib, data []byte) error {
	pd := &armpolicy.Definition{}
	if err := json.Unmarshal(data, pd); err != nil {
		return errors.New(fmt.Sprintf("Error unmarshalling policy definition: %s", err))
	}
	alzlib.policyDefinitions = append(alzlib.policyDefinitions, *pd)
	return nil
}
