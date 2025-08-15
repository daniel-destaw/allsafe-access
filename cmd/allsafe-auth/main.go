package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// AuthConfig defines the structure for auth.yaml configuration
type AuthConfig struct {
	CertsDir                   string `mapstructure:"certs_dir"`
	RootCALifetimeYears        int    `mapstructure:"root_ca_lifetime_years"`
	RootCAKeySize              int    `mapstructure:"root_ca_key_size"`
	ComponentCertLifetimeYears int    `mapstructure:"component_cert_lifetime_years"`
	ComponentCertKeySize       int    `mapstructure:"component_cert_key_size"`
}

var authCfg AuthConfig
var cfgFile string

// CertDetails holds information for certificate generation
type CertDetails struct {
	Organization  []string
	Country       []string
	Province      []string
	Locality      []string
	StreetAddress []string
	PostalCode    []string
	CommonName    string
	DNSNames      []string
	IPAddresses   []net.IP
}

var (
	// Flags for CA generation
	caOrg        string
	caCountry    string
	caProvince   string
	caLocality   string
	caStreet     string
	caPostal     string
	caCommonName string
	forceRewrite bool

	// New flags for external CA import
	externalCACertPath string
	externalCAKeyPath  string
)

// Global variables to hold the loaded CA certificate and key
var (
	loadedCACert    *x509.Certificate
	loadedCAPrivKey *rsa.PrivateKey
)

func initConfig(appName string) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(fmt.Sprintf("/etc/%s", appName))
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, fmt.Sprintf(".%s", appName)))
		}
		viper.AddConfigPath(".")
		viper.SetConfigName(appName)
	}

	viper.SetConfigType("yaml")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("No config file found for %s. Using defaults or flags. Error: %v\n", appName, err)
		} else {
			log.Fatalf("Error reading config file for %s: %v\n", appName, err)
		}
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "allsafe-auth",
	Short: "Allsafe Auth Service manages identity, policies, and certificates.",
	Long: `The Allsafe Auth Service is the central authority for managing
identity, access policies, and issuing short-lived certificates for
all Allsafe Access components (CLI, Proxy, Agent).`,
}

var initCACmd = &cobra.Command{
	Use:   "init-ca",
	Short: "Initialize the Root Certificate Authority for Allsafe Access",
	Long: `Generates a self-signed Root CA certificate and key, or loads them if they already exist.
If --external-ca-cert and --external-ca-key are provided, it will load that CA instead.
This CA will be used to sign all subsequent certificates for Allsafe Access components.`,
	Run: func(cmd *cobra.Command, args []string) {
		cobra.OnInitialize(func() { initConfig("allsafe-auth") })

		// Unmarshal the configuration into the struct
		if err := viper.Unmarshal(&authCfg); err != nil {
			log.Fatalf("Unable to decode config into struct: %v", err)
		}

		// Use the configured directory
		certsDir := authCfg.CertsDir
		rootCACertPath := filepath.Join(certsDir, "rootCA.crt")
		rootCAKeyPath := filepath.Join(certsDir, "rootCA.key")

		fmt.Println("Allsafe Auth Service: Initializing Root CA...")

		if err := os.MkdirAll(certsDir, 0755); err != nil {
			log.Fatalf("Failed to create certs directory: %v", err)
		}

		if externalCACertPath != "" && externalCAKeyPath != "" {
			fmt.Printf("Loading external CA from %s and %s...\n", externalCACertPath, externalCAKeyPath)
			var err error
			loadedCACert, loadedCAPrivKey, err = loadExternalCA(externalCACertPath, externalCAKeyPath)
			if err != nil {
				log.Fatalf("Failed to load external CA: %v", err)
			}
			fmt.Println("External Root CA loaded successfully.")
			if err := copyFile(externalCACertPath, rootCACertPath); err != nil {
				log.Fatalf("Failed to copy external CA cert: %v", err)
			}
			if err := copyFile(externalCAKeyPath, rootCAKeyPath); err != nil {
				log.Fatalf("Failed to copy external CA key: %v", err)
			}
			fmt.Println("External CA copied to local certs directory.")
		} else {
			if _, err := os.Stat(rootCACertPath); err == nil && !forceRewrite {
				fmt.Println("Root CA certificate already exists. Use --force-rewrite to regenerate.")
				confirm := false
				prompt := &survey.Confirm{
					Message: "Root CA already exists. Do you want to use the existing one? (Otherwise, it will exit)",
					Default: true,
				}
				survey.AskOne(prompt, &confirm)
				if confirm {
					fmt.Println("Using existing Root CA.")
					var err error
					loadedCACert, loadedCAPrivKey, err = loadExternalCA(rootCACertPath, rootCAKeyPath)
					if err != nil {
						log.Fatalf("Failed to load existing self-signed CA: %v", err)
					}
					issueSampleCerts()
					return
				} else {
					fmt.Println("Aborting CA initialization.")
					os.Exit(0)
				}
			}

			// Collect CA details for self-signed CA
			var questions []*survey.Question
			if !cmd.Flags().Changed("org") {
				questions = append(questions, &survey.Question{
					Name: "org",
					Prompt: &survey.Input{
						Message: "Organization (e.g., Allsafe Access):",
						Default: "Allsafe Access",
					},
				})
			}
			if !cmd.Flags().Changed("country") {
				questions = append(questions, &survey.Question{
					Name: "country",
					Prompt: &survey.Input{
						Message: "Country Code (e.g., US, ET):",
						Default: "ET",
					},
					Validate: survey.Required,
				})
			}
			if !cmd.Flags().Changed("province") {
				questions = append(questions, &survey.Question{
					Name: "province",
					Prompt: &survey.Input{
						Message: "Province/State:",
						Default: "Addis Ababa",
					},
				})
			}
			if !cmd.Flags().Changed("locality") {
				questions = append(questions, &survey.Question{
					Name: "locality",
					Prompt: &survey.Input{
						Message: "Locality/City:",
						Default: "Addis Ababa",
					},
				})
			}
			if !cmd.Flags().Changed("street") {
				questions = append(questions, &survey.Question{
					Name: "street",
					Prompt: &survey.Input{
						Message: "Street Address:",
						Default: "Example St",
					},
				})
			}
			if !cmd.Flags().Changed("postal") {
				questions = append(questions, &survey.Question{
					Name: "postal",
					Prompt: &survey.Input{
						Message: "Postal Code:",
						Default: "1000",
					},
				})
			}
			if !cmd.Flags().Changed("common-name") {
				questions = append(questions, &survey.Question{
					Name: "common-name",
					Prompt: &survey.Input{
						Message: "Common Name for Root CA (e.g., Allsafe Root CA):",
						Default: "Allsafe Root CA",
					},
					Validate: survey.Required,
				})
			}

			answers := struct {
				Org        string `survey:"org"`
				Country    string `survey:"country"`
				Province   string `survey:"province"`
				Locality   string `survey:"locality"`
				Street     string `survey:"street"`
				Postal     string `survey:"postal"`
				CommonName string `survey:"common-name"`
			}{}

			if len(questions) > 0 {
				fmt.Println("\nPlease provide the following details for your Root CA:")
				err := survey.Ask(questions, &answers)
				if err != nil {
					log.Fatalf("Failed to get user input: %v", err)
				}

				if !cmd.Flags().Changed("org") {
					caOrg = answers.Org
				}
				if !cmd.Flags().Changed("country") {
					caCountry = answers.Country
				}
				if !cmd.Flags().Changed("province") {
					caProvince = answers.Province
				}
				if !cmd.Flags().Changed("locality") {
					caLocality = answers.Locality
				}
				if !cmd.Flags().Changed("street") {
					caStreet = answers.Street
				}
				if !cmd.Flags().Changed("postal") {
					caPostal = answers.Postal
				}
				if !cmd.Flags().Changed("common-name") {
					caCommonName = answers.CommonName
				}
			}

			details := CertDetails{
				Organization:  []string{caOrg},
				Country:       []string{caCountry},
				Province:      []string{caProvince},
				Locality:      []string{caLocality},
				StreetAddress: []string{caStreet},
				PostalCode:    []string{caPostal},
				CommonName:    caCommonName,
			}

			var err error
			loadedCACert, loadedCAPrivKey, err = generateNewRootCA(details)
			if err != nil {
				log.Fatalf("Failed to generate Root CA: %v", err)
			}
			fmt.Println("Self-signed Root CA generated.")
		}

		if loadedCACert == nil || loadedCAPrivKey == nil {
			log.Fatal("Root CA was not loaded or generated. Aborting.")
		}

		fmt.Println("Root CA is ready.")
		issueSampleCerts()
		fmt.Println("\nCertificates managed. The Auth service would typically start its API listener now.")
	},
}

func generateNewRootCA(details CertDetails) (*x509.Certificate, *rsa.PrivateKey, error) {
	fmt.Println("Generating new Root CA certificate and key...")

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:  details.Organization,
			Country:       details.Country,
			Province:      details.Province,
			Locality:      details.Locality,
			StreetAddress: details.StreetAddress,
			PostalCode:    details.PostalCode,
			CommonName:    details.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(authCfg.RootCALifetimeYears, 0, 0), // Use configurable lifetime
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, authCfg.RootCAKeySize) // Use configurable key size
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certsDir := authCfg.CertsDir
	rootCACertPath := filepath.Join(certsDir, "rootCA.crt")
	rootCAKeyPath := filepath.Join(certsDir, "rootCA.key")

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err := os.WriteFile(rootCACertPath, caCertPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}

	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})
	if err := os.WriteFile(rootCAKeyPath, caKeyPEM, 0600); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA private key: %w", err)
	}

	return ca, caPrivKey, nil
}

func loadExternalCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate from %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA private key from %s: %w", keyPath, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing CA certificate from %s", certPath)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate from %s: %w", certPath, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing CA private key from %s", keyPath)
	}

	var privateKey interface{}
	privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CA private key (neither PKCS#8 nor PKCS#1) from %s: %w", keyPath, err)
		}
	}

	caPrivKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("loaded private key is not an RSA private key (unexpected type)")
	}

	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("provided certificate is not a CA certificate: %s", certPath)
	}

	return caCert, caPrivKey, nil
}

func parseCommonNameInput(input string) (string, []string, []net.IP) {
	parts := strings.Split(input, ",")
	var commonName string
	var dnsNames []string
	var ipAddresses []net.IP

	if len(parts) > 0 {
		commonName = strings.TrimSpace(parts[0])
	}

	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if trimmedPart == "" {
			continue
		}
		ip := net.ParseIP(trimmedPart)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, trimmedPart)
		}
	}
	return commonName, dnsNames, ipAddresses
}

func issueSampleCerts() {
	fmt.Println("\nIssuing sample certificates for demonstration...")

	caCountry := ""
	if len(loadedCACert.Subject.Country) > 0 {
		caCountry = loadedCACert.Subject.Country[0]
	}
	caProvince := ""
	if len(loadedCACert.Subject.Province) > 0 {
		caProvince = loadedCACert.Subject.Province[0]
	}

	// --- Proxy Certificate ---
	var proxyCommonNameInput string
	promptProxyCN := &survey.Input{
		Message: "Common Name for Proxy Certificate (e.g., 127.0.0.1 or proxy.allsafe.com):",
		Default: "127.0.0.1",
	}
	survey.AskOne(promptProxyCN, &proxyCommonNameInput, survey.WithValidator(survey.Required))

	proxyCN, proxyDNS, proxyIPs := parseCommonNameInput(proxyCommonNameInput)

	proxyCertDetails := CertDetails{
		CommonName:    proxyCN,
		Organization:  []string{"Allsafe Access Proxy"},
		Country:       []string{caCountry},
		Province:      []string{caProvince},
		DNSNames:      proxyDNS,
		IPAddresses:   proxyIPs,
	}
	if err := issueCert("proxy", proxyCertDetails); err != nil {
		log.Fatalf("Failed to issue proxy server cert: %v", err)
	}
	fmt.Println("Issued proxy.crt and .key")
	if err := copyFile(filepath.Join(authCfg.CertsDir, "rootCA.crt"), filepath.Join(authCfg.CertsDir, "proxy_ca.crt")); err != nil {
		log.Printf("Warning: Failed to copy rootCA.crt for proxy: %v", err)
	}

	// --- Agent Certificate ---
	var agentCommonNameInput string
	promptAgentCN := &survey.Input{
		Message: "Common Name for Agent Certificate (e.g., agent-001 or agent.allsafe.com):",
		Default: "127.0.0.1",
	}
	survey.AskOne(promptAgentCN, &agentCommonNameInput, survey.WithValidator(survey.Required))

	agentCN, agentDNS, agentIPs := parseCommonNameInput(agentCommonNameInput)

	agentCertDetails := CertDetails{
		CommonName:    agentCN,
		Organization:  []string{"Allsafe Access Agent"},
		Country:       []string{caCountry},
		Province:      []string{caProvince},
		DNSNames:      agentDNS,
		IPAddresses:   agentIPs,
	}
	if err := issueCert("agent", agentCertDetails); err != nil {
		log.Fatalf("Failed to issue agent cert: %v", err)
	}
	fmt.Println("Issued agent.crt and .key")
	if err := copyFile(filepath.Join(authCfg.CertsDir, "rootCA.crt"), filepath.Join(authCfg.CertsDir, "agent_ca.crt")); err != nil {
		log.Printf("Warning: Failed to copy rootCA.crt for agent: %v", err)
	}
}

func issueCert(name string, details CertDetails) error {
	if loadedCACert == nil || loadedCAPrivKey == nil {
		return fmt.Errorf("CA is not loaded; cannot issue certificate")
	}

	privKey, err := rsa.GenerateKey(rand.Reader, authCfg.ComponentCertKeySize) // Use configurable key size
	if err != nil {
		return fmt.Errorf("failed to generate private key for %s: %w", name, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:    details.CommonName,
			Organization:  details.Organization,
			Country:       details.Country,
			Province:      details.Province,
			Locality:      details.Locality,
			StreetAddress: details.StreetAddress,
			PostalCode:    details.PostalCode,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(authCfg.ComponentCertLifetimeYears, 0, 0), // Use configurable lifetime
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    details.DNSNames,
		IPAddresses: details.IPAddresses,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, loadedCACert, &privKey.PublicKey, loadedCAPrivKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate for %s: %w", name, err)
	}

	certsDir := authCfg.CertsDir
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err := os.WriteFile(filepath.Join(certsDir, name+".crt"), certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate for %s: %w", name, err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	if err := os.WriteFile(filepath.Join(certsDir, name+".key"), keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key for %s: %w", name, err)
	}

	return nil
}

func init() {
	cobra.OnInitialize(func() { initConfig("allsafe-auth") })
	rootCmd.AddCommand(initCACmd)

	initCACmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/allsafe-auth/allsafe-auth.yaml or $HOME/.allsafe-auth/allsafe-auth.yaml)")

	initCACmd.Flags().StringVar(&caOrg, "org", "Allsafe Access", "Organization name for the CA certificate")
	initCACmd.Flags().StringVar(&caCountry, "country", "ET", "Country code for the CA certificate (e.g., US, ET)")
	initCACmd.Flags().StringVar(&caProvince, "province", "Addis Ababa", "Province/State for the CA certificate")
	initCACmd.Flags().StringVar(&caLocality, "locality", "Addis Ababa", "Locality/City for the CA certificate")
	initCACmd.Flags().StringVar(&caStreet, "street", "Example St", "Street Address for the CA certificate")
	initCACmd.Flags().StringVar(&caPostal, "postal", "1000", "Postal Code for the CA certificate")
	initCACmd.Flags().StringVar(&caCommonName, "common-name", "Allsafe Root CA", "Common Name for the CA certificate")
	initCACmd.Flags().BoolVar(&forceRewrite, "force-rewrite", false, "Force regeneration of the Root CA if it already exists.")

	initCACmd.Flags().StringVar(&externalCACertPath, "external-ca-cert", "", "Path to an existing external Root/Intermediate CA certificate file (PEM)")
	initCACmd.Flags().StringVar(&externalCAKeyPath, "external-ca-key", "", "Path to the private key for the external CA certificate file (PEM)")

	// NEW: Add flags for configurable certificate parameters
	initCACmd.Flags().Int("root-ca-lifetime-years", 10, "Lifetime of the Root CA certificate in years")
	viper.BindPFlag("root_ca_lifetime_years", initCACmd.Flags().Lookup("root-ca-lifetime-years"))

	initCACmd.Flags().Int("root-ca-key-size", 4096, "Key size (in bits) for the Root CA private key")
	viper.BindPFlag("root_ca_key_size", initCACmd.Flags().Lookup("root-ca-key-size"))

	initCACmd.Flags().Int("component-cert-lifetime-years", 1, "Lifetime of component certificates (proxy, cli, agent) in years")
	viper.BindPFlag("component_cert_lifetime_years", initCACmd.Flags().Lookup("component-cert-lifetime-years"))

	initCACmd.Flags().Int("component-cert-key-size", 2048, "Key size (in bits) for component certificates")
	viper.BindPFlag("component_cert_key_size", initCACmd.Flags().Lookup("component-cert-key-size"))

	initCACmd.Flags().String("certs-dir", "configs/certs", "The directory to store generated certificates")
	viper.BindPFlag("certs_dir", initCACmd.Flags().Lookup("certs-dir"))

	// Set default values for all configuration options
	viper.SetDefault("certs_dir", "configs/certs")
	viper.SetDefault("root_ca_lifetime_years", 10)
	viper.SetDefault("root_ca_key_size", 4096)
	viper.SetDefault("component_cert_lifetime_years", 1)
	viper.SetDefault("component_cert_key_size", 2048)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory for %s: %w", dst, err)
	}

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("failed to copy file from %s to %s: %w", src, dst, err)
	}
	return nil
}