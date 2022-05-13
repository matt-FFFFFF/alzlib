package alzlib

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func processPolicySetDefinition(az *AlzLib, data []byte) error {
	psd := &armpolicy.SetDefinition{}
	if err := json.Unmarshal(data, psd); err != nil {
		return fmt.Errorf("error unmarshalling policy set definition: %s", err)
	}
	if *psd.Name == "" {
		return fmt.Errorf("policy set definition name is empty")
	}
	az.PolicySetDefinitions[*psd.Name] = psd
	return nil
}
