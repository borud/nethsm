package nethsm

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path"
	"testing"
	"time"

	"github.com/borud/nethsm/api"
	"github.com/borud/nethsm/dockerhsm"
	"github.com/stretchr/testify/require"
)

var (
	bogusTLSCertificate = []byte(`
-----BEGIN CERTIFICATE-----
MIICMzCCAZygAwIBAgIJALiPnVsvq8dsMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV
BAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNVBAcTA2ZvbzEMMAoGA1UEChMDZm9v
MQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2ZvbzAeFw0xMzAzMTkxNTQwMTlaFw0x
ODAzMTgxNTQwMTlaMFMxCzAJBgNVBAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNV
BAcTA2ZvbzEMMAoGA1UEChMDZm9vMQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2Zv
bzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdGfxi9CNbMf1UUcvDQh7MYB
OveIHyc0E0KIbhjK5FkCBU4CiZrbfHagaW7ZEcN0tt3EvpbOMxxc/ZQU2WN/s/wP
xph0pSfsfFsTKM4RhTWD2v4fgk+xZiKd1p0+L4hTtpwnEw0uXRVd0ki6muwV5y/P
+5FHUeldq+pgTcgzuK8CAwEAAaMPMA0wCwYDVR0PBAQDAgLkMA0GCSqGSIb3DQEB
BQUAA4GBAJiDAAtY0mQQeuxWdzLRzXmjvdSuL9GoyT3BF/jSnpxz5/58dba8pWen
v3pj4P3w5DoOso0rzkZy2jEsEitlVM2mLSbQpMM+MUVQCQoiG6W9xuCFuxSrwPIS
pAqEAuV4DNoxQKKWmhVv+J0ptMWD25Pnpxeq5sXzghfJnslJlQND
-----END CERTIFICATE-----`)
)

// TestSession tests everything.
//
// TODO(borud): This test is awfully long and ugly.  Rewrite it and chop it
// into managable pieces.
func TestSession(t *testing.T) {
	if os.Getenv("TEST_TAG") != "slowtest" {
		t.Skip("Skipping test because TEST_TAG is not set to slowtest")
	}

	if !dockerhsm.DockerAvailable() {
		t.Skip("docker not available, skipping test")
	}

	dh, err := dockerhsm.Create()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dh.Shutdown())
	})

	session, err := NewSession(Config{
		Username: "admin",
		Password: dh.AdminPassword(),
		APIURL:   dh.APIURL(),
		TLSMode:  TLSModeSkipVerify,
	})
	require.NoError(t, err)

	// Provision the NetHSM
	slog.Info("Provisioning; this may take some time", "apiURL", dh.APIURL())
	err = session.Provision(dh.UnlockPassword(), dh.AdminPassword())
	require.NoError(t, err)
	slog.Info("Provision succeeded")

	// Test GetInfo
	info, err := session.GetInfo()
	require.NoError(t, err)
	require.Equal(t, info.Product, "NetHSM")
	require.Equal(t, info.Vendor, "Nitrokey GmbH")
	slog.Info("GetInfo succeeded")

	// Test GetUser
	userData, err := session.GetUser("admin")
	require.NoError(t, err)
	require.Equal(t, userData.RealName, "admin")
	require.Equal(t, userData.Role, api.USERROLE_ADMINISTRATOR)
	slog.Info("GetUser succeeded")

	// Test ListUsers
	users, err := session.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)
	slog.Info("ListUsers succeeded")

	// Test adding users
	require.NoError(t, session.AddUser("temporary", "The Temporary User", "Operator", "verysecret"))
	slog.Info("AddUser succeeded")

	// Test removing user
	require.NoError(t, session.DeleteUser("temporary"))
	slog.Info("DeleteUser succeeded")

	// Test adding namespace
	require.NoError(t, session.AddNamespace("tempo"))
	slog.Info("AddNamespace succeeded")

	// Test listing namespaces
	namespaces, err := session.ListNamespaces()
	require.NoError(t, err)
	require.Len(t, namespaces, 1)
	slog.Info("ListNamespaces succeeded")

	// Test removing namespaces
	require.NoError(t, session.DeleteNamespace("tempo"))
	slog.Info("DeleteNamespace succeeded")

	// Test generating a key
	require.NoError(t, session.GenerateKey("keyA", api.KEYTYPE_RSA, []api.KeyMechanism{api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA512}, 2048))
	require.NoError(t, session.GenerateKey("keyB", api.KEYTYPE_CURVE25519, []api.KeyMechanism{api.KEYMECHANISM_ED_DSA_SIGNATURE}, 2048))
	require.NoError(t, session.GenerateKey("keyC", api.KEYTYPE_EC_P384, []api.KeyMechanism{api.KEYMECHANISM_ECDSA_SIGNATURE}, 384))
	require.NoError(t, session.GenerateKey("keyD", api.KEYTYPE_EC_P521, []api.KeyMechanism{api.KEYMECHANISM_ECDSA_SIGNATURE}, 521))
	slog.Info("GenerateKey succeeded")

	// Make sure we can handle RSA public key
	pubA, err := session.GetPublicKey("keyA")
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, pubA)
	slog.Info("GetPublicKey succeeded")

	_, err = session.GetKey("keyA")
	require.NoError(t, err)
	slog.Info("GetKey succeeded")

	// Make sure we can handle ED25519 public key
	pubB, err := session.GetPublicKey("keyB")
	require.NoError(t, err)
	require.IsType(t, ed25519.PublicKey{}, pubB)
	slog.Info("GetPublicKey for ed25519 succeeded")

	_, err = session.GetKey("keyB")
	require.NoError(t, err)

	// Make sure we can handle ECDSA P_384 public key
	pubC, err := session.GetPublicKey("keyC")
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PublicKey{}, pubC)
	slog.Info("GetPublicKey for P_384 succeeded")

	_, err = session.GetKey("keyC")
	require.NoError(t, err)

	// Make sure we can handle ECDSA P_521 public key
	pubD, err := session.GetPublicKey("keyD")
	require.NoError(t, err)
	require.IsType(t, &ecdsa.PublicKey{}, pubD)
	slog.Info("GetPublicKey for P_521 succeeded")

	_, err = session.GetKey("keyD")
	require.NoError(t, err)

	// Generate CSR and check the result
	subject := pkix.Name{
		Country:            []string{"NO"},
		Organization:       []string{"Company"},
		OrganizationalUnit: []string{"Org unit 1", "Org unit 2"},
		Locality:           []string{"Trondheim"},
		Province:           []string{"Trondelag"},
		CommonName:         "common name",
	}
	email := "pki@example.com"

	// test for each of the keys
	keyACSR := generateCSR(t, session, "keyA", subject, email)
	keyBCSR := generateCSR(t, session, "keyB", subject, email)
	keyCCSR := generateCSR(t, session, "keyC", subject, email)
	keyDCSR := generateCSR(t, session, "keyD", subject, email)

	// For signing we need an operator user
	require.NoError(t, session.AddUser("operator", "The Operator", "Operator", "verysecret"))

	operatorSession, err := NewSession(Config{
		Username: "operator",
		Password: "verysecret",
		APIURL:   dh.APIURL(),
		TLSMode:  TLSModeSkipVerify,
	})
	require.NoError(t, err)

	// test local CSR generation.  Must be done by operator.
	generateCSRLocal(t, operatorSession, "keyA", subject, email, x509.SHA512WithRSAPSS)
	generateCSRLocal(t, operatorSession, "keyB", subject, email, x509.PureEd25519)
	generateCSRLocal(t, operatorSession, "keyC", subject, email, x509.ECDSAWithSHA384)
	generateCSRLocal(t, operatorSession, "keyD", subject, email, x509.ECDSAWithSHA512)

	someData := []byte("This is some data that we want to sign")
	digestA := sha512.Sum512(someData)
	digestC := sha512.Sum384(someData)
	digestD := sha512.Sum512(someData)

	// Sign data using RSA key
	signedA, err := operatorSession.Sign("keyA", x509.SHA512WithRSAPSS, digestA[:])
	require.NoError(t, err)
	require.NotEmpty(t, signedA)
	// TODO(borud): use Verify when implemented

	// Sign data using Ed25519
	signedB, err := operatorSession.Sign("keyB", x509.PureEd25519, someData)
	require.NoError(t, err)
	require.NotEmpty(t, signedB)
	// TODO(borud): use Verify when implemented

	signedC, err := operatorSession.Sign("keyC", x509.ECDSAWithSHA384, digestC[:])
	require.NoError(t, err)
	require.NotEmpty(t, signedC)
	// TODO(borud): use Verify when implemented

	signedD, err := operatorSession.Sign("keyD", x509.ECDSAWithSHA512, digestD[:])
	require.NoError(t, err)
	require.NotEmpty(t, signedD)
	// TODO(borud): use Verify when implemented

	// Self signing RSA
	keyACert, err := operatorSession.CreateCertificate(CSRSigningParameters{
		SelfSign:           true,
		SignatureAlgorithm: x509.SHA512WithRSAPSS,
		SigningKeyID:       "keyA",
		CSRPEM:             keyACSR,
		KeyUsage:           x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		IsCA:               true,
		MaxPathLen:         1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, keyACert)
	slog.Info("CreateCertificate succeeded")

	require.NoError(t, session.SetCertificate("keyA", []byte(keyACert)))
	slog.Info("SetCertificate succeeded")

	_, err = operatorSession.GetCertificate("keyA")
	require.NoError(t, err)
	slog.Info("GetCertificate succeeded")

	// Self signing ED25519
	keyBCert, err := operatorSession.CreateCertificate(CSRSigningParameters{
		SelfSign:           true,
		SignatureAlgorithm: x509.PureEd25519,
		SigningKeyID:       "keyB",
		CSRPEM:             keyBCSR,
		KeyUsage:           x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		IsCA:               true,
		MaxPathLen:         2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, keyBCert)
	require.NoError(t, session.SetCertificate("keyB", []byte(keyBCert)))

	_, err = operatorSession.GetCertificate("keyB")
	require.NoError(t, err)

	// Self signing EC_P384
	keyCCert, err := operatorSession.CreateCertificate(CSRSigningParameters{
		SelfSign:           true,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		SigningKeyID:       "keyC",
		CSRPEM:             keyCCSR,
		KeyUsage:           x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		IsCA:               true,
		MaxPathLen:         2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, keyCCert)
	require.NoError(t, session.SetCertificate("keyC", []byte(keyCCert)))

	_, err = operatorSession.GetCertificate("keyC")
	require.NoError(t, err)

	// Self signing EC_P384
	keyDCert, err := operatorSession.CreateCertificate(CSRSigningParameters{
		SelfSign:           true,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		SigningKeyID:       "keyD",
		CSRPEM:             keyDCSR,
		KeyUsage:           x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		IsCA:               true,
		MaxPathLen:         2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, keyDCert)
	require.NoError(t, session.SetCertificate("keyD", []byte(keyDCert)))

	_, err = operatorSession.GetCertificate("keyD")
	require.NoError(t, err)

	// test listing keys
	keyNames, err := session.ListKeys()
	require.NoError(t, err)
	require.NotEmpty(t, keyNames)

	// test deleting certificate
	require.NoError(t, session.DeleteCertificate("keyA"))

	// test deleting key
	require.NoError(t, session.DeleteKey("keyB"))

	// Test symmetric key encrypt/decrypt
	require.NoError(t, session.GenerateKey("key256",
		api.KEYTYPE_GENERIC,
		[]api.KeyMechanism{api.KEYMECHANISM_AES_ENCRYPTION_CBC, api.KEYMECHANISM_AES_DECRYPTION_CBC},
		256))

	require.NoError(t, session.GenerateKey("key128",
		api.KEYTYPE_GENERIC,
		[]api.KeyMechanism{api.KEYMECHANISM_AES_ENCRYPTION_CBC, api.KEYMECHANISM_AES_DECRYPTION_CBC},
		128))

	secretMessage := []byte("This is a secret message")
	initialVector := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	encryptedData, err := operatorSession.EncryptSymmetric("key256", secretMessage, initialVector)
	require.NoError(t, err)
	slog.Info("EncryptSymmetric AES256 succeeded")

	decryptedData, err := operatorSession.DecryptSymmetric("key256", encryptedData, initialVector)
	require.NoError(t, err)
	require.Equal(t, secretMessage, decryptedData)
	slog.Info("DecryptSymmetric AES265 succeeded")

	encryptedData2, err := operatorSession.EncryptSymmetric("key128", secretMessage, initialVector)
	require.NoError(t, err)
	slog.Info("EncryptSymmetric AES128 succeeded")

	decryptedData2, err := operatorSession.DecryptSymmetric("key128", encryptedData2, initialVector)
	require.NoError(t, err)
	require.Equal(t, secretMessage, decryptedData2)
	slog.Info("DecryptSymmetric AES128 succeeded")

	// Test that overriding the Subject works
	//
	csrSubjectOverrideKeyName := "csrSubjectOverrideKey"
	require.NoError(t, session.GenerateKey(csrSubjectOverrideKeyName, api.KEYTYPE_EC_P384, []api.KeyMechanism{api.KEYMECHANISM_ECDSA_SIGNATURE}, 384))
	// Generate CSR and check the result
	overrideTestCSR := generateCSR(t, session, csrSubjectOverrideKeyName, pkix.Name{CommonName: "the CSR subject"}, "test@example.com")
	overrideTestCert, err := operatorSession.CreateCertificate(CSRSigningParameters{
		SelfSign:           false,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		SigningKeyID:       "keyD",
		CSRPEM:             overrideTestCSR,
		Subject:            &pkix.Name{CommonName: "overridden"},
		KeyUsage:           x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		IsCA:               false,
	})
	require.NoError(t, err)
	require.NotEmpty(t, overrideTestCert)

	block, _ := pem.Decode([]byte(overrideTestCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Now make sure the subject was overridden.
	require.Equal(t, "overridden", cert.Subject.CommonName)
	slog.Info("Subject override succeeded")

	// Test using TLS certificate from NetHSM
	tlsCertificate, err := session.GetTLSCertificate()
	require.NoError(t, err)
	slog.Info("GetTLSCertificate succeeded")

	tlsTestSession, err := NewSession(Config{
		Username:          "admin",
		Password:          dh.AdminPassword(),
		APIURL:            dh.APIURL(),
		ServerCertificate: []byte(tlsCertificate),
		TLSMode:           TLSModeWithoutSANCheck,
	})
	require.NoError(t, err)

	_, err = tlsTestSession.GetInfo()
	require.NoError(t, err)

	// Now we modify the certificate and see if that triggers the correct error
	bogusTLSTestSession, err := NewSession(Config{
		Username:          "admin",
		Password:          dh.AdminPassword(),
		APIURL:            dh.APIURL(),
		ServerCertificate: []byte(bogusTLSCertificate),
		TLSMode:           TLSModeWithoutSANCheck,
	})
	require.NoError(t, err)
	_, err = bogusTLSTestSession.GetInfo()
	require.ErrorIs(t, err, ErrTLSCertificateMismatch)
	slog.Info("Bogus TLS Certificate detection succeeded")

	// ====== Encryption and decryption

	rsaDecryptTestKeyName := "rsaDecryptTestKey"
	require.NoError(t, session.GenerateKey(
		rsaDecryptTestKeyName,
		api.KEYTYPE_RSA,
		[]api.KeyMechanism{
			api.KEYMECHANISM_RSA_DECRYPTION_RAW,
			api.KEYMECHANISM_RSA_DECRYPTION_PKCS1,
			api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA256,
		},
		2048))

	pubKeyTemp, err := operatorSession.GetPublicKey(rsaDecryptTestKeyName)
	require.NoError(t, err)

	pubKey, ok := pubKeyTemp.(*rsa.PublicKey)
	require.True(t, ok, "not an RSA key")

	plainText := []byte("hello from PKCS#1 v1.5")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	require.NoError(t, err)

	clearText, err := operatorSession.Decrypt(rsaDecryptTestKeyName, api.DECRYPTMODE_PKCS1, ciphertext)
	require.NoError(t, err)
	require.Equal(t, clearText, plainText)

	slog.Info("Decrypt successful (PKCS1 round-trip OK)")

	// ====== Test backup

	// Create a user that can perform backups.
	require.NoError(t, session.AddUser("backup", "Backup User", string(api.USERROLE_BACKUP), "verysecret"))

	// Set backup passphrase.
	require.NoError(t, session.SetBackupPassword("backupPassword", ""))
	slog.Info("SetBackupPassword succeeded")

	// Create a session with the backup user.
	backupSession, err := NewSession(Config{
		Username:          "backup",
		Password:          "verysecret",
		APIURL:            dh.APIURL(),
		ServerCertificate: []byte(tlsCertificate),
		TLSMode:           TLSModeWithoutSANCheck,
	})
	require.NoError(t, err)

	// Perform backup
	f, err := backupSession.Backup()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	// Read the backup and verify that it is not empty
	backup, err := io.ReadAll(f)
	require.NoError(t, err)
	require.NotEmpty(t, backup)
	slog.Info("Backup succeeded")

	// write the backup to temporary file
	tempDir := t.TempDir()
	backupFileName := path.Join(tempDir, "hsmbackup")
	require.NoError(t, os.WriteFile(backupFileName, backup, 0644))

	// Create docker with unprovisioned NetHSM
	restoreDH, err := dockerhsm.Create()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, restoreDH.Shutdown())
	})

	backupFile, err := os.Open(backupFileName)
	require.NoError(t, err)

	// Create session on NetHSM
	restoreSession, err := NewSession(Config{
		APIURL:  restoreDH.APIURL(),
		TLSMode: TLSModeSkipVerify,
	})
	require.NoError(t, err)

	// Restore from the backup
	require.NoError(t, restoreSession.Restore("backupPassword", backupFile))
	slog.Info("Restore succeeded")

	// Create an admin session on the restored instance.
	restoredAdminSession, err := NewSession(Config{
		Username: "admin",
		Password: dh.AdminPassword(), // use admin password from the restored NetHSM
		APIURL:   restoreDH.APIURL(),
		TLSMode:  TLSModeSkipVerify,
	})
	require.NoError(t, err)

	// Unlock the restored
	require.NoError(t, restoredAdminSession.UnLock(dh.UnlockPassword()))
	slog.Info("Unlock on restored HSM succeeded")

	// List keys
	keys, err := restoredAdminSession.ListKeys()
	require.NoError(t, err)
	require.NotEmpty(t, keys)
}

func generateCSR(t *testing.T, session *Session, keyID string, subject pkix.Name, email string) string {
	csrPEM, err := session.GenerateCSR(keyID, subject, email)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	require.NoError(t, csr.CheckSignature())
	return csrPEM
}

func generateCSRLocal(t *testing.T, session *Session, keyID string, subject pkix.Name, email string, algo x509.SignatureAlgorithm) string {
	csrPEM, err := session.GenerateCSRUsingGoStdlib(keyID, subject, email, algo)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	require.NoError(t, csr.CheckSignature())
	return csrPEM
}
