package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ashishtaldeokar/goselfca"
)

func split(s string) (results []string) {
	if len(s) > 0 {
		return strings.Split(s, ",")
	}
	return nil
}

func main() {
	err := executeCLI()
	if err != nil {
		log.Fatal(err)
	}
}

func executeCLI() error {
	var caKey = flag.String("ca-key", "goselfca-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "goselfca.pem", "Root certificate filename, PEM encoded.")
	var caAlg = flag.String("ca-alg", "ed25519", "Algorithm for any new keypairs: RSA, ECDSA, or Ed25519.")
	var profile = flag.String("profile", "server", "Certificate profile: server, client, or peer.")
	var intermediate = flag.Bool("intermediate", false, "Generate an intermediate CA certificate instead of a leaf certificate.")
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

Use the --intermediate flag to generate a Sub-CA certificate instead of a leaf.
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
		fmt.Printf("Extra arguments: %v (maybe there are spaces in your domain list?)\n", flag.Args())
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

	issuer, err := goselfca.GetIssuer(*caKey, *caCert, alg, *reuseKeys, caValidity, *org, *unit)
	if err != nil {
		return err
	}

	if *intermediate {
		var cn string
		if len(domainSlice) > 0 {
			cn = domainSlice[0]
		} else if len(ipSlice) > 0 {
			cn = ipSlice[0]
		} else if *org != "" {
			cn = *org
		} else {
			return fmt.Errorf("must specify a domain name or organization for the intermediate CA common name")
		}
		_, err = goselfca.SignIntermediate(issuer, cn, alg, *reuseKeys, validity, *org, *unit, "")
		return err
	}

	_, err = goselfca.Sign(issuer, domainSlice, ipSlice, alg, *reuseKeys, *profile, validity, *org, *unit, "")
	return err
}
