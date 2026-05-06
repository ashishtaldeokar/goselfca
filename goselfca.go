// goselfca is a simple CA intended for use in situations where the CA operator
// also operates each host where a certificate will be used. It automatically
// generates both a key and a certificate when asked to produce a certificate.
// It does not offer OCSP or CRL services. goselfca is appropriate, for instance,
// for generating certificates for RPC systems or microservices.
//
// On first run, goselfca will generate a keypair and a root certificate in the
// current directory, and will reuse that same keypair and root certificate
// unless they are deleted.
//
// On each run, goselfca will generate a new keypair and sign an end-entity (leaf)
// certificate for that keypair. The certificate will contain a list of DNS names
// and/or IP addresses from the command line flags. The key and certificate are
// placed in a new directory whose name is chosen as the first domain name from
// the certificate, or the first IP address if no domain names are present. It
//
// The command-line tool wraps this package.
package goselfca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Issuer represents the CA's private key and certificate required to sign new leaf certificates.
type Issuer struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

// GetIssuer reads an existing keypair for a CA, or generates a new one if it doesn't exist.
func GetIssuer(keyFile, certFile string, alg x509.PublicKeyAlgorithm, reuseKey bool, caValidity time.Duration, org, unit string) (*Issuer, error) {
	keyContents, keyErr := os.ReadFile(keyFile)
	certContents, certErr := os.ReadFile(certFile)
	if os.IsNotExist(keyErr) && os.IsNotExist(certErr) {
		err := makeIssuer(keyFile, certFile, alg, caValidity, org, unit)
		if err != nil {
			return nil, err
		}
		return GetIssuer(keyFile, certFile, alg, false, caValidity, org, unit)
	} else if keyErr != nil {
		return nil, fmt.Errorf("%v (but %s exists)", keyErr, certFile)
	} else if certErr != nil {
		if reuseKey {
			key, err := readPrivateKey(keyContents)
			if err != nil {
				return nil, fmt.Errorf("reading private key from %s: %w", keyFile, err)
			}
			_, err = MakeRootCert(key, certFile, caValidity, org, unit)
			if err != nil {
				return nil, err
			}
			return GetIssuer(keyFile, certFile, alg, false, caValidity, org, unit)
		}
		return nil, fmt.Errorf("%v (but %s exists)", certErr, keyFile)
	}
	key, err := readPrivateKey(keyContents)
	if err != nil {
		return nil, fmt.Errorf("reading private key from %s: %w", keyFile, err)
	}

	cert, err := readCert(certContents)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate from %s: %w", certFile, err)
	}

	equal, err := publicKeysEqual(key.Public(), cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("comparing public keys: %w", err)
	} else if !equal {
		return nil, fmt.Errorf("public key in CA certificate %s doesn't match private key in %s",
			certFile, keyFile)
	}
	return &Issuer{key, cert}, nil
}

func readPrivateKey(keyContents []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyContents)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if block.Type == "PRIVATE KEY" {
		signer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8: %w", err)
		}
		switch t := signer.(type) {
		case *rsa.PrivateKey:
			return signer.(*rsa.PrivateKey), nil
		case *ecdsa.PrivateKey:
			return signer.(*ecdsa.PrivateKey), nil
		case ed25519.PrivateKey:
			return signer.(ed25519.PrivateKey), nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %t", t)
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "EC PRIVATE KEY" || block.Type == "ECDSA PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
}

func readCert(certContents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certContents)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func makeIssuer(keyFile, certFile string, alg x509.PublicKeyAlgorithm, caValidity time.Duration, org, unit string) error {
	key, err := MakeKey(keyFile, alg)
	if err != nil {
		return err
	}
	_, err = MakeRootCert(key, certFile, caValidity, org, unit)
	if err != nil {
		return err
	}
	return nil
}

// MakeKey generates a new cryptographic keypair using the specified algorithm and saves it to a file.
func MakeKey(filename string, alg x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	var key crypto.Signer
	var err error
	switch {
	case alg == x509.RSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	case alg == x509.ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case alg == x509.Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// MakeRootCert creates a new, self-signed Root CA certificate using the provided private key.
func MakeRootCert(key crypto.Signer, filename string, validity time.Duration, org, unit string) (*x509.Certificate, error) {
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	skid, err := calculateSKID(key.Public())
	if err != nil {
		return nil, err
	}

	subjectName := pkix.Name{
		CommonName: "GoSelfCA Root CA " + hex.EncodeToString(serial.Bytes()[:3]),
	}
	if org != "" {
		subjectName.Organization = []string{org}
	}
	if unit != "" {
		subjectName.OrganizationalUnit = []string{unit}
	}

	template := &x509.Certificate{
		Subject:      subjectName,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),

		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func parseIPs(ipAddresses []string) ([]net.IP, error) {
	var parsed []net.IP
	for _, s := range ipAddresses {
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP address %s", s)
		}
		parsed = append(parsed, p)
	}
	return parsed, nil
}

func publicKeysEqual(a, b interface{}) (bool, error) {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false, err
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(aBytes, bBytes), nil
}

func calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:], nil
}

// Sign generates an end-entity (leaf) certificate signed by the Root CA's private key.
func Sign(iss *Issuer, commonName string, domains []string, ipAddresses []string, alg x509.PublicKeyAlgorithm, reuseKey bool, profile string, validity time.Duration, org, unit string, outDir string) (*x509.Certificate, error) {
	cn := commonName
	if cn == "" {
		if len(domains) > 0 {
			cn = domains[0]
		} else if len(ipAddresses) > 0 {
			cn = ipAddresses[0]
		} else {
			return nil, fmt.Errorf("either commonName or at least one domain name or IP address is required")
		}
	}
	if outDir == "" {
		if len(domains) > 0 {
			outDir = strings.Replace(domains[0], "*", "_", -1)
		} else if len(ipAddresses) > 0 {
			outDir = strings.Replace(ipAddresses[0], "*", "_", -1)
		} else {
			outDir = strings.Replace(cn, "*", "_", -1)
		}
	}
	err := os.MkdirAll(outDir, 0700)
	if err != nil {
		return nil, err
	}
	var keyFile = filepath.Join(outDir, "key.pem")
	var key crypto.Signer
	if reuseKey {
		keyContents, keyErr := os.ReadFile(keyFile)
		if keyErr == nil {
			key, err = readPrivateKey(keyContents)
			if err != nil {
				return nil, fmt.Errorf("reading private key from %s: %w", keyFile, err)
			}
		}
	}
	if key == nil {
		key, err = MakeKey(keyFile, alg)
		if err != nil {
			return nil, err
		}
	}
	parsedIPs, err := parseIPs(ipAddresses)
	if err != nil {
		return nil, err
	}
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if alg == x509.RSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	var extKeyUsage []x509.ExtKeyUsage
	switch profile {
	case "server":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "peer":
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("unrecognized profile: %s", profile)
	}
	subjectName := pkix.Name{
		CommonName: cn,
	}
	if org != "" {
		subjectName.Organization = []string{org}
	}
	if unit != "" {
		subjectName.OrganizationalUnit = []string{unit}
	}

	template := &x509.Certificate{
		DNSNames:     domains,
		IPAddresses:  parsedIPs,
		Subject:      subjectName,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),

		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, iss.Cert, key.Public(), iss.Key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(outDir, "cert.pem"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// SignIntermediate generates an intermediate CA certificate signed by the Root CA's private key.
// It sets IsCA to true and enforces MaxPathLenZero so it can only sign leaf certificates.
func SignIntermediate(iss *Issuer, commonName string, alg x509.PublicKeyAlgorithm, reuseKey bool, validity time.Duration, org, unit string, outDir string) (*x509.Certificate, error) {
	if commonName == "" {
		return nil, fmt.Errorf("must specify a common name for the intermediate CA")
	}
	if outDir == "" {
		outDir = strings.Replace(commonName, " ", "_", -1)
		outDir = strings.Replace(outDir, "*", "_", -1)
	}
	err := os.MkdirAll(outDir, 0700)
	if err != nil {
		return nil, err
	}
	var keyFile = filepath.Join(outDir, "key.pem")
	var key crypto.Signer
	if reuseKey {
		keyContents, keyErr := os.ReadFile(keyFile)
		if keyErr == nil {
			key, err = readPrivateKey(keyContents)
			if err != nil {
				return nil, fmt.Errorf("reading private key from %s: %w", keyFile, err)
			}
		}
	}
	if key == nil {
		key, err = MakeKey(keyFile, alg)
		if err != nil {
			return nil, err
		}
	}
	serial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	skid, err := calculateSKID(key.Public())
	if err != nil {
		return nil, err
	}

	subjectName := pkix.Name{
		CommonName: commonName,
	}
	if org != "" {
		subjectName.Organization = []string{org}
	}
	if unit != "" {
		subjectName.OrganizationalUnit = []string{unit}
	}

	template := &x509.Certificate{
		Subject:      subjectName,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),

		SubjectKeyId:          skid,
		AuthorityKeyId:        iss.Cert.SubjectKeyId,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, iss.Cert, key.Public(), iss.Key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(outDir, "cert.pem"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// end of goselfca.go
