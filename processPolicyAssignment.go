package alzlib

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func processPolicyAssignment(az *AlzLib, data []byte) error {
	pa := &armpolicy.Assignment{}
	if err := json.Unmarshal(data, pa); err != nil {
		return fmt.Errorf("error unmarshalling policy assignment: %s", err)
	}
	az.PolicyAssignments = append(az.PolicyAssignments, *pa)
	return nil
}
