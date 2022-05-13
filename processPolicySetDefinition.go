package alzlib

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func processPolicySetDefinition(alzlib *AlzLib, data []byte) error {
	psd := &armpolicy.SetDefinition{}
	if err := json.Unmarshal(data, psd); err != nil {
		return fmt.Errorf("error unmarshalling policy set definition: %s", err)
	}
	alzlib.policySetDefinitions = append(alzlib.policySetDefinitions, *psd)
	return nil
}
