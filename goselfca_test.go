package goselfca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseIPs(t *testing.T) {
	tests := []struct {
		name        string
		ips         []string
		wantErr     bool
		expectedLen int
	}{
		{"Valid IPs", []string{"192.168.1.1", "10.0.0.1"}, false, 2},
		{"Invalid IP", []string{"192.168.1.1", "invalid-ip"}, true, 0},
		{"Empty slice", []string{}, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseIPs(tt.ips)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIPs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(parsed) != tt.expectedLen {
				t.Errorf("parseIPs() len = %v, wantLen %v", len(parsed), tt.expectedLen)
			}
		})
	}
}

func TestMakeKey(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		alg         x509.PublicKeyAlgorithm
		keyFileName string
		checkType   func(crypto.Signer) bool
	}{
		{
			name:        "RSA Key",
			alg:         x509.RSA,
			keyFileName: "rsa.pem",
			checkType: func(k crypto.Signer) bool {
				_, ok := k.(*rsa.PrivateKey)
				return ok
			},
		},
		{
			name:        "ECDSA Key",
			alg:         x509.ECDSA,
			keyFileName: "ecdsa.pem",
			checkType: func(k crypto.Signer) bool {
				_, ok := k.(*ecdsa.PrivateKey)
				return ok
			},
		},
		{
			name:        "Ed25519 Key",
			alg:         x509.Ed25519,
			keyFileName: "ed25519.pem",
			checkType: func(k crypto.Signer) bool {
				_, ok := k.(ed25519.PrivateKey)
				return ok
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(tempDir, tt.keyFileName)
			key, err := MakeKey(keyPath, tt.alg)
			if err != nil {
				t.Fatalf("makeKey() error = %v", err)
			}
			if !tt.checkType(key) {
				t.Errorf("makeKey() returned wrong key type")
			}
			if _, err := os.Stat(keyPath); os.IsNotExist(err) {
				t.Errorf("makeKey() did not create file at %s", keyPath)
			}
		})
	}
}

func TestMakeRootCert(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "ca-key.pem")
	certPath := filepath.Join(tempDir, "ca-cert.pem")

	key, err := MakeKey(keyPath, x509.Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validity := 24 * time.Hour
	cert, err := MakeRootCert(key, certPath, validity, "", "")
	if err != nil {
		t.Fatalf("makeRootCert() error = %v", err)
	}

	if !cert.IsCA {
		t.Errorf("Root cert is not a CA")
	}

	expectedExpiration := time.Now().Add(validity)
	// Check if NotAfter is within a reasonable bound (1 minute tolerance)
	if cert.NotAfter.After(expectedExpiration.Add(1*time.Minute)) || cert.NotAfter.Before(expectedExpiration.Add(-1*time.Minute)) {
		t.Errorf("Root cert validity incorrect: got %v, expected ~%v", cert.NotAfter, expectedExpiration)
	}
}

func TestSignProfiles(t *testing.T) {
	// 1. Setup a CA first
	tempDir := t.TempDir()
	caKeyPath := filepath.Join(tempDir, "ca-key.pem")
	caCertPath := filepath.Join(tempDir, "ca-cert.pem")

	err := makeIssuer(caKeyPath, caCertPath, x509.Ed25519, 24*time.Hour, "", "")
	if err != nil {
		t.Fatalf("Failed to setup issuer: %v", err)
	}

	iss, err := GetIssuer(caKeyPath, caCertPath, x509.Ed25519, false, 24*time.Hour, "", "")
	if err != nil {
		t.Fatalf("Failed to retrieve issuer: %v", err)
	}

	tests := []struct {
		name                 string
		profile              string
		domain               string
		expectedExtKeyUsages []x509.ExtKeyUsage
	}{
		{
			name:                 "Server Profile",
			profile:              "server",
			domain:               "server.local",
			expectedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:                 "Client Profile",
			profile:              "client",
			domain:               "client.local",
			expectedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:                 "Peer Profile",
			profile:              "peer",
			domain:               "peer.local",
			expectedExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
	}

	validity := 1 * time.Hour

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := Sign(iss, []string{tt.domain}, nil, x509.Ed25519, false, tt.profile, validity, "", "", filepath.Join(tempDir, tt.domain))
			if err != nil {
				t.Fatalf("sign() error = %v", err)
			}

			// Validate ExtKeyUsage
			if len(cert.ExtKeyUsage) != len(tt.expectedExtKeyUsages) {
				t.Errorf("Expected %d ExtKeyUsages, got %d", len(tt.expectedExtKeyUsages), len(cert.ExtKeyUsage))
			} else {
				for i, expected := range tt.expectedExtKeyUsages {
					if cert.ExtKeyUsage[i] != expected {
						t.Errorf("ExtKeyUsage[%d] = %v, expected %v", i, cert.ExtKeyUsage[i], expected)
					}
				}
			}

			// Validate Common Name
			if cert.Subject.CommonName != tt.domain {
				t.Errorf("Expected Subject.CommonName = %v, got %v", tt.domain, cert.Subject.CommonName)
			}
		})
	}
}

func TestSignOrgUnit(t *testing.T) {
	tempDir := t.TempDir()
	caKeyPath := filepath.Join(tempDir, "ca-key.pem")
	caCertPath := filepath.Join(tempDir, "ca-cert.pem")

	org := "My Test Org"
	unit := "My Test Unit"

	err := makeIssuer(caKeyPath, caCertPath, x509.Ed25519, 24*time.Hour, org, unit)
	if err != nil {
		t.Fatalf("Failed to setup issuer: %v", err)
	}

	iss, err := GetIssuer(caKeyPath, caCertPath, x509.Ed25519, false, 24*time.Hour, org, unit)
	if err != nil {
		t.Fatalf("Failed to retrieve issuer: %v", err)
	}

	cert, err := Sign(iss, []string{"test.local"}, nil, x509.Ed25519, false, "server", 1*time.Hour, org, unit, filepath.Join(tempDir, "test.local"))
	if err != nil {
		t.Fatalf("sign() error = %v", err)
	}

	// Verify Leaf Certificate Subject
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != org {
		t.Errorf("Leaf Subject Organization = %v, want %v", cert.Subject.Organization, []string{org})
	}
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != unit {
		t.Errorf("Leaf Subject OrganizationalUnit = %v, want %v", cert.Subject.OrganizationalUnit, []string{unit})
	}

	// Verify Root CA Certificate Subject (since it was passed to makeIssuer)
	if len(iss.Cert.Subject.Organization) != 1 || iss.Cert.Subject.Organization[0] != org {
		t.Errorf("Root Subject Organization = %v, want %v", iss.Cert.Subject.Organization, []string{org})
	}
	if len(iss.Cert.Subject.OrganizationalUnit) != 1 || iss.Cert.Subject.OrganizationalUnit[0] != unit {
		t.Errorf("Root Subject OrganizationalUnit = %v, want %v", iss.Cert.Subject.OrganizationalUnit, []string{unit})
	}
}

func TestSignIntermediate(t *testing.T) {
	tempDir := t.TempDir()
	caKeyPath := filepath.Join(tempDir, "ca-key.pem")
	caCertPath := filepath.Join(tempDir, "ca-cert.pem")

	// 1. Create Root CA
	err := makeIssuer(caKeyPath, caCertPath, x509.Ed25519, 24*time.Hour, "Root Org", "Root Unit")
	if err != nil {
		t.Fatalf("Failed to setup root issuer: %v", err)
	}

	rootIss, err := GetIssuer(caKeyPath, caCertPath, x509.Ed25519, false, 24*time.Hour, "Root Org", "Root Unit")
	if err != nil {
		t.Fatalf("Failed to retrieve root issuer: %v", err)
	}

	// 2. Mint Intermediate CA
	subCaDir := filepath.Join(tempDir, "subca")
	subCaCert, err := SignIntermediate(rootIss, "My Intermediate CA", x509.Ed25519, false, 12*time.Hour, "Sub Org", "Sub Unit", subCaDir)
	if err != nil {
		t.Fatalf("SignIntermediate() error = %v", err)
	}

	// Validate Intermediate CA cert
	if !subCaCert.IsCA {
		t.Errorf("Intermediate cert is not a CA (IsCA is false)")
	}
	if !subCaCert.BasicConstraintsValid {
		t.Errorf("Intermediate cert BasicConstraintsValid is false")
	}
	if subCaCert.MaxPathLenZero != true {
		t.Errorf("Intermediate cert MaxPathLenZero should be true to prevent further sub-CAs")
	}
	if subCaCert.Subject.CommonName != "My Intermediate CA" {
		t.Errorf("Intermediate cert CommonName = %v, want 'My Intermediate CA'", subCaCert.Subject.CommonName)
	}

	// 3. Mint a leaf cert from the Intermediate CA
	subCaKeyPath := filepath.Join(subCaDir, "key.pem")
	subCaCertPath := filepath.Join(subCaDir, "cert.pem")

	subIss, err := GetIssuer(subCaKeyPath, subCaCertPath, x509.Ed25519, true, 12*time.Hour, "Sub Org", "Sub Unit")
	if err != nil {
		t.Fatalf("Failed to retrieve intermediate issuer: %v", err)
	}

	leafDir := filepath.Join(tempDir, "leaf")
	leafCert, err := Sign(subIss, []string{"leaf.local"}, nil, x509.Ed25519, false, "server", 1*time.Hour, "Leaf Org", "Leaf Unit", leafDir)
	if err != nil {
		t.Fatalf("Sign() from intermediate error = %v", err)
	}

	if leafCert.IsCA {
		t.Errorf("Leaf cert from intermediate incorrectly has IsCA = true")
	}
	if leafCert.Subject.CommonName != "leaf.local" {
		t.Errorf("Leaf cert CommonName = %v, want 'leaf.local'", leafCert.Subject.CommonName)
	}
}
