package main

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
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
}

type issuer struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func getIssuer(keyFile, certFile string, alg x509.PublicKeyAlgorithm, reuseKey bool, caValidity time.Duration, org, unit string) (*issuer, error) {
	keyContents, keyErr := os.ReadFile(keyFile)
	certContents, certErr := os.ReadFile(certFile)
	if os.IsNotExist(keyErr) && os.IsNotExist(certErr) {
		err := makeIssuer(keyFile, certFile, alg, caValidity, org, unit)
		if err != nil {
			return nil, err
		}
		return getIssuer(keyFile, certFile, alg, false, caValidity, org, unit)
	} else if keyErr != nil {
		return nil, fmt.Errorf("%s (but %s exists)", keyErr, certFile)
	} else if certErr != nil {
		if reuseKey {
			key, err := readPrivateKey(keyContents)
			if err != nil {
				return nil, fmt.Errorf("reading private key from %s: %s", keyFile, err)
			}
			_, err = makeRootCert(key, certFile, caValidity, org, unit)
			if err != nil {
				return nil, err
			}
			return getIssuer(keyFile, certFile, alg, false, caValidity, org, unit)
		}
		return nil, fmt.Errorf("%s (but %s exists)", certErr, keyFile)
	}
	key, err := readPrivateKey(keyContents)
	if err != nil {
		return nil, fmt.Errorf("reading private key from %s: %s", keyFile, err)
	}

	cert, err := readCert(certContents)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate from %s: %s", certFile, err)
	}

	equal, err := publicKeysEqual(key.Public(), cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("comparing public keys: %s", err)
	} else if !equal {
		return nil, fmt.Errorf("public key in CA certificate %s doesn't match private key in %s",
			certFile, keyFile)
	}
	return &issuer{key, cert}, nil
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
	key, err := makeKey(keyFile, alg)
	if err != nil {
		return err
	}
	_, err = makeRootCert(key, certFile, caValidity, org, unit)
	if err != nil {
		return err
	}
	return nil
}

func makeKey(filename string, alg x509.PublicKeyAlgorithm) (crypto.Signer, error) {
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

func makeRootCert(key crypto.Signer, filename string, validity time.Duration, org, unit string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
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

func sign(iss *issuer, domains []string, ipAddresses []string, alg x509.PublicKeyAlgorithm, reuseKey bool, profile string, validity time.Duration, org, unit string) (*x509.Certificate, error) {
	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ipAddresses) > 0 {
		cn = ipAddresses[0]
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}
	var cnFolder = strings.Replace(cn, "*", "_", -1)
	err := os.Mkdir(cnFolder, 0700)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	var keyFile = fmt.Sprintf("%s/key.pem", cnFolder)
	var key crypto.Signer
	if reuseKey {
		keyContents, keyErr := os.ReadFile(keyFile)
		if keyErr == nil {
			key, err = readPrivateKey(keyContents)
			if err != nil {
				return nil, fmt.Errorf("reading private key from %s: %s", keyFile, err)
			}
		}
	}
	if key == nil {
		key, err = makeKey(keyFile, alg)
		if err != nil {
			return nil, err
		}
	}
	parsedIPs, err := parseIPs(ipAddresses)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
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
	der, err := x509.CreateCertificate(rand.Reader, template, iss.cert, key.Public(), iss.key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(fmt.Sprintf("%s/cert.pem", cnFolder), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
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

func split(s string) (results []string) {
	if len(s) > 0 {
		return strings.Split(s, ",")
	}
	return nil
}

func main2() error {
	var caKey = flag.String("ca-key", "goselfca-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "goselfca.pem", "Root certificate filename, PEM encoded.")
	var caAlg = flag.String("ca-alg", "ed25519", "Algorithm for any new keypairs: RSA, ECDSA, or Ed25519.")
	var profile = flag.String("profile", "server", "Certificate profile: server, client, or peer.")
	var reuseKeys = flag.Bool("reuse-keys", false, "If only the key file exists, reuse it to generate the certificate")
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")
	var org = flag.String("org", "", "Organization (O) to include in the certificate subject.")
	var unit = flag.String("unit", "", "Organizational Unit (OU) to include in the certificate subject.")
	var validityStr = flag.String("validity", "", "Validity period for the generated certificate (e.g., 8760h for 1 year). Defaults to 2 years and 30 days.")
	var caValidityStr = flag.String("ca-validity", "", "Validity period for the root CA certificate. Defaults to 100 years.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
goselfca is a simple CA intended for use in situations where the CA operator
also operates each host where a certificate will be used. It automatically
generates both a key and a certificate when asked to produce a certificate.
It does not offer OCSP or CRL services. goselfca is appropriate, for instance,
for generating certificates for RPC systems or microservices.

On first run, goselfca will generate a keypair and a root certificate in the
current directory, and will reuse that same keypair and root certificate
unless they are deleted.

On each run, goselfca will generate a new keypair and sign an end-entity (leaf)
certificate for that keypair. The certificate will contain a list of DNS names
and/or IP addresses from the command line flags. The key and certificate are
placed in a new directory whose name is chosen as the first domain name from
the certificate, or the first IP address if no domain names are present. It
will not overwrite existing keys or certificates.

`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *domains == "" && *ipAddresses == "" {
		flag.Usage()
		os.Exit(1)
	}
	if *profile != "server" && *profile != "client" && *profile != "peer" {
		fmt.Printf("Unrecognized profile: %s (use server, client, or peer)\n", *profile)
		os.Exit(1)
	}
	alg := x509.RSA
	if strings.ToLower(*caAlg) == "ecdsa" {
		alg = x509.ECDSA
	} else if strings.ToLower(*caAlg) == "ed25519" {
		alg = x509.Ed25519
	} else if strings.ToLower(*caAlg) != "rsa" {
		fmt.Printf("Unrecognized algorithm: %s (use RSA, ECDSA, or Ed25519)\n", *caAlg)
		os.Exit(1)
	}
	if len(flag.Args()) > 0 {
		fmt.Printf("Extra arguments: %s (maybe there are spaces in your domain list?)\n", flag.Args())
		os.Exit(1)
	}
	domainSlice := split(*domains)
	domainRe := regexp.MustCompile("^[A-Za-z0-9.*-]+$")
	for _, d := range domainSlice {
		if !domainRe.MatchString(d) {
			fmt.Printf("Invalid domain name %q\n", d)
			os.Exit(1)
		}
	}
	ipSlice := split(*ipAddresses)
	for _, ip := range ipSlice {
		if net.ParseIP(ip) == nil {
			fmt.Printf("Invalid IP address %q\n", ip)
			os.Exit(1)
		}
	}
	// Parse validity and caValidity durations
	var validity time.Duration
	if *validityStr != "" {
		var err error
		validity, err = time.ParseDuration(*validityStr)
		if err != nil {
			fmt.Printf("Invalid validity duration %q: %v\n", *validityStr, err)
			os.Exit(1)
		}
	} else {
		// Default: 2 years and 30 days
		// 365 days * 2 + 30 days = 760 days = 18240 hours
		validity = 18240 * time.Hour
	}

	var caValidity time.Duration
	if *caValidityStr != "" {
		var err error
		caValidity, err = time.ParseDuration(*caValidityStr)
		if err != nil {
			fmt.Printf("Invalid CA validity duration %q: %v\n", *caValidityStr, err)
			os.Exit(1)
		}
	} else {
		// Default: 100 years
		// 365 days * 100 = 36500 days = 876000 hours
		caValidity = 876000 * time.Hour
	}

	issuer, err := getIssuer(*caKey, *caCert, alg, *reuseKeys, caValidity, *org, *unit)
	if err != nil {
		return err
	}
	_, err = sign(issuer, domainSlice, ipSlice, alg, *reuseKeys, *profile, validity, *org, *unit)
	return err
}
