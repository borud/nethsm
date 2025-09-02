// Package main contains code demonstrating how to encrypt/decrypt with RSA
// key.
//
// This demo assumes that you have a provisioned NetHSM with:
//   - an admin user named "admin"
//   - an operator user named "operator"
//   - both have the password "verysecret"
//   - there is a NetHSM instance running at https://127.0.0.1:8443/api/v1
//
// To run this demo you can build it with:
//
//	go build
//
// And then run it:
//
//	./crypt
//
// The output should be something like this:
//
//	025/09/02 13:18:41 INFO created key keyName=rsaDemoKey1756811920899
//	2025/09/02 13:18:41 INFO testing RSA RAW, PKCS1 and OAEP encrypt/decrypt
//	2025/09/02 13:18:41 INFO   RAW: round-trip OK
//	2025/09/02 13:18:41 INFO   PKCS1: round-trip OK
//	2025/09/02 13:18:41 INFO   OAEP-SHA256: round-trip OK
//	2025/09/02 13:18:41 INFO removed key keyName=rsaDemoKey1756811920899
package main

import (
	"log"
	"log/slog"

	"github.com/borud/nethsm"
)

const (
	adminPassword    = "verysecret"
	operatorPassword = "verysecret"
	apiURL           = "https://127.0.0.1:8443/api/v1"
)

func main() {
	// Create admin session
	adminSession, err := nethsm.NewSession(nethsm.Config{
		Username: "admin",
		Password: adminPassword,
		APIURL:   apiURL,
		TLSMode:  nethsm.TLSModeSkipVerify,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create operator session
	operatorSession, err := nethsm.NewSession(nethsm.Config{
		Username: "operator",
		Password: operatorPassword,
		APIURL:   apiURL,
		TLSMode:  nethsm.TLSModeSkipVerify,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create new demo instance
	demo := NewDemo(adminSession, operatorSession)

	// Create the RSA key
	err = demo.createKey()
	if err != nil {
		slog.Error("error creating key", "err", err)
		return
	}
	slog.Info("created key", "keyName", demo.getKeyName())

	// Make sure we clean up after ourselves
	defer func() {
		err := demo.cleanup()
		if err != nil {
			slog.Error("error removing key", "keyName", demo.getKeyName(), "err", err)
		}
		slog.Info("removed key", "keyName", demo.getKeyName())
	}()

	slog.Info("testing RSA RAW, PKCS1 and OAEP encrypt/decrypt")

	err = demo.messageRaw()
	if err != nil {
		slog.Error("error encrypting/decrypting raw", "err", err)
	}

	err = demo.messagePKCS1()
	if err != nil {
		slog.Error("error encrypting/decrypting PKCS1", "err", err)
	}

	err = demo.messageOAEP()
	if err != nil {
		slog.Error("error encrypting/decrypting OAEP", "err", err)
	}
}
