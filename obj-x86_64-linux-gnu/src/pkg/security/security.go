// pkg/security/security.go
package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadKeyPair loads a TLS certificate and key from specified paths.
func LoadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load key pair from %s and %s: %w", certPath, keyPath, err)
	}
	return cert, nil
}

// LoadCACertPool loads a CA certificate from a path and returns it as an x509.CertPool.
func LoadCACertPool(caCertPath string) (*x509.CertPool, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to append CA certificate from %s", caCertPath)
	}
	return caCertPool, nil
}

// CreateClientTLSConfig creates a TLS configuration for a client.
func CreateClientTLSConfig(clientCertPath, clientKeyPath, caCertPath string) (*tls.Config, error) {
	// Load client certificate and key
	clientCert, err := LoadKeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client key pair: %w", err)
	}

	// Load CA certificate for server verification
	caCertPool, err := LoadCACertPool(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert pool for client: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12, // Ensure modern TLS version
	}, nil
}

// CreateServerTLSConfig creates a TLS configuration for a server requiring client authentication.
func CreateServerTLSConfig(serverCertPath, serverKeyPath, caCertPath string) (*tls.Config, error) {
	// Load server certificate and key
	serverCert, err := LoadKeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %w", err)
	}

	// Load CA certificate for client authentication
	caCertPool, err := LoadCACertPool(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert pool for server: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Crucial for mTLS
		MinVersion:   tls.VersionTLS12,                // Ensure modern TLS version
	}, nil
}