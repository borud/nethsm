// Package main contains a basic example of how to use the NetHSM library.
package main

import (
	"log/slog"

	"github.com/borud/nethsm"
	"github.com/borud/nethsm/api"
)

func main() {
	// Create a session
	session := nethsm.Session{
		Username:      "admin",
		Password:      "verysecret",
		APIURL:        "https://127.0.0.1:8443/api/v1",
		SkipTLSVerify: true,
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
