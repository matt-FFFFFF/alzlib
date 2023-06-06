# alzlib - a go module for reading Azure Landing Zones Terraform module lib definitions

[![Go test](https://github.com/matt-FFFFFF/alzlib/actions/workflows/go-test.yml/badge.svg)](https://github.com/matt-FFFFFF/alzlib/actions/workflows/go-test.yml) [![codecov](https://codecov.io/gh/matt-FFFFFF/alzlib/branch/main/graph/badge.svg?token=8A28XRERB2)](https://codecov.io/gh/matt-FFFFFF/alzlib)

This module provides a go library for reading [Azure Landing Zones](https://github.com/Azure/terraform-azurerm-caf-enterprise-scale) Terraform module lib definitions.

It uses the Azure SDK for Go to get the data types required:

* [github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/resourcemanager/resources/armpolicy)

## Usage

```go
package main

import (
  "fmt"
  "context"
  "log"

  "github.com/matt-FFFFFF/alzlib"
  "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
  "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
)

func main() {
  lib, err := alzlib.New("")

  // Set up Azure clients
  cred, _ := azidentity.NewDefaultAzureCredential(nil)
  cf, _ := armpolicy.NewClientFactory("", cred, nil)
  az.AddPolicyClient(cf)

  // Initialize the library, and fetch required data from Azure
  if err := lib.Init(context.TODO()); err != nil {
    log.Fatal(err)
  }

  fmt.Printf("Found %d archetypes!", len(lib.Archetypes))
}
```
