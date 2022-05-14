# alzlib - a go module for reading Azure Landing Zones Terraform module lib definitions

This module provides a go library for reading [Azure Landing Zones](https://github.com/Azure/terraform-azurerm-caf-enterprise-scale) Terraform module lib definitions.

It uses the Azure SDK for Go to get the data types required:

* [github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/resourcemanager/resources/armpolicy)

The key data types it returns are:

```go
type AlzLib struct {
  Archetypes              map[string]Archetype
  PolicyDefinitions       map[string]*armpolicy.Definition
  PolicySetDefinitions    map[string]*armpolicy.SetDefinition
  PolicyAssignments       map[string]*armpolicy.Assignment
  // This is not exported and only used on the initial load
  libArchetypeDefinitions []libArchetypeDefinition
}

type Archetype struct {
  PolicyDefinitions    map[string]*armpolicy.Definition
  PolicyAssignments    map[string]*armpolicy.Assignment
  PolicySetDefinitions map[string]*armpolicy.SetDefinition
}
```

## Usage

```go
package main

import (
  "fmt"
  "log"

  "github.com/matt-FFFFFF/alzlib"
)

func main() {
  lib, err := alzlib.New("./lib")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Printf("Found %d archetypes!", len(lib.Archetypes))
}
```
