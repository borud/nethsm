# Go library for NetHSM

This is a Go library for working with the NetHSM.  It provides a wrapper around the API types that are generated from the OpenAPI specification to make life a bit easier for those using NetHSM.

## WARNING

**Note that this is a work in progress**. The API will have breaking changes  before this reaches release version v1.0.0 so use this at your own risk.

### Generated Types

Where it makes sense we use the generated types in the API rather than create our own.  This results in less code to maintain, but may break things when new versions of the OpenAPI spec is published.

## Usage example

This example shows how to get information about the NetHSM instance, create a key, get its public key and then remove it.  Examples can be found in the [examples](examples/) directory.

```go
package main

import (
    "log/slog"

    "github.com/borud/nethsm"
    "github.com/borud/nethsm/api"
)

func main() {
    session := nethsm.Session{
        Username:      "admin",
        Password:      "verysecret",
        APIURL:        "https://127.0.0.1:8443/api/v1",
        TLSMode:  nethsm.TLSModeSkipVerify,
    }

    // Get information about vendor and product
    info, err := session.GetInfo()
    if err != nil {
        slog.Error("error getting info", "err", err)
        return
    }
    slog.Info("Information about NetHSM", "product", info.Product, "vendor", info.Vendor)

    // Create an RSA key
    rsaKeyID := "myRSAKey"
    err = session.GenerateKey(
        rsaKeyID,
        api.KEYTYPE_RSA,
        []api.KeyMechanism{api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA512},
        2048)
    if err != nil {
        slog.Error("error creating key", "keyID", rsaKeyID, "err", err)
        return
    }
    slog.Info("created key", "keyID", rsaKeyID)

    // Get public key
    pub, err := session.GetPublicKey(rsaKeyID)
    if err != nil {
        slog.Error("error fetching public key", "keyID", rsaKeyID, "err", err)
        return
    }
    slog.Info("fetched public key", "keyID", rsaKeyID, "publicKey", pub)

    // Delete key
    err = session.DeleteKey(rsaKeyID)
    if err != nil {
        slog.Error("failed to delete key", "keyID", rsaKeyID, "err", err)
    }
    slog.Info("deleted key", "keyID", rsaKeyID)
}
```

## Completeness

This library does not support

- Tags
- Network configuration
- Reboot
- Software update
