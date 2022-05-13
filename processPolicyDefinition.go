package alzlib

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func processPolicyDefinition(az *AlzLib, data []byte) error {
	pd := &armpolicy.Definition{}
	if err := json.Unmarshal(data, pd); err != nil {
		return fmt.Errorf("error unmarshalling policy definition: %s", err)
	}
	if *pd.Name == "" {
		return fmt.Errorf("policy definition name is empty")
	}
	az.PolicyDefinitions[*pd.Name] = pd
	return nil
}
