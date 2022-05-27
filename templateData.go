package alzlib

import "fmt"

func NewTemplateDataAtScope(currentScopeId string, az *AlzLib) (*TemplateData, error) {
	td := TemplateData{}
	td.Root_scope_id = az.RootScopeId
	td.Default_location = az.DefaultLocation
	td.Private_dns_zone_prefix = ""

	rid, err := getManagementGroupResourceId(az.RootScopeId)
	if err != nil {
		return nil, fmt.Errorf("error getting resource id for management group %s: %s", az.RootScopeId, err)
	}
	td.Root_scope_resource_id = rid.String()

	cid, err := getManagementGroupResourceId(currentScopeId)
	if err != nil {
		return nil, fmt.Errorf("error getting resource id for management group %s: %s", currentScopeId, err)
	}
	td.Current_scope_resource_id = cid.String()
	return &td, nil
}
