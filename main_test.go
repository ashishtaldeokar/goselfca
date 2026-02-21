package main

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
			key, err := makeKey(keyPath, tt.alg)
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

	key, err := makeKey(keyPath, x509.Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validity := 24 * time.Hour
	cert, err := makeRootCert(key, certPath, validity)
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

	// Store original working directory to restore later
	originalWD, _ := os.Getwd()
	defer os.Chdir(originalWD)
	// Change to temp dir because `sign` creates a directory based on the domain name
	os.Chdir(tempDir)

	err := makeIssuer(caKeyPath, caCertPath, x509.Ed25519, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to setup issuer: %v", err)
	}

	iss, err := getIssuer(caKeyPath, caCertPath, x509.Ed25519, false, 24*time.Hour)
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
			cert, err := sign(iss, []string{tt.domain}, nil, x509.Ed25519, false, tt.profile, validity)
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
