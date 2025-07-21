package config

import (
    "fmt"
    "os"
    "path/filepath"

    "gopkg.in/yaml.v3"
)

const AppConfigFile = "allsafe-access.yaml"

type ServerConfig struct {
    Address     string `yaml:"address"`
    TLSCertFile string `yaml:"tls_cert_file"`
    TLSKeyFile  string `yaml:"tls_key_file"`
    Secure      bool   `yaml:"secure"`
}

type RedisConfig struct {
    Address string `yaml:"address"`
}

type AppConfig struct {
    Server ServerConfig `yaml:"server"`
    Redis  RedisConfig  `yaml:"redis"`
}

// SetupEnvironment creates dirs, config files, TLS certs (conditionally), and writes app config
func SetupEnvironment(secure bool) error {
    dirs := []string{"config", "logs", "recordings"}
    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            return fmt.Errorf("failed to create %s: %w", dir, err)
        }
    }

    detailedRoles := `# Roles define what users can do in the system.
# Permissions are granular and control access to resources.

admin:
  options:
    max_session_ttl: 24h0m0s
    port_forwarding: true
    certificate_format: standard
  allow:
    logins: ["root", "admin"]
    node_labels:
      "*": "*"
    rules:
      - resources: ["session", "node", "user", "role", "auth_server"]
        verbs: ["read", "list", "create", "update", "delete"]

developer:
  options:
    max_session_ttl: 8h0m0s
    port_forwarding: false
    certificate_format: standard
  allow:
    logins: ["dev", "ubuntu"]
    node_labels:
      "env": "development"
    rules:
      - resources: ["session", "node"]
        verbs: ["read", "list", "create"]

auditor:
  options:
    max_session_ttl: 4h0m0s
    port_forwarding: false
  allow:
    logins: ["audit"]
    node_labels:
      "*": "*"
    rules:
      - resources: ["session", "node", "user"]
        verbs: ["read", "list"]
`

    if err := os.WriteFile("config/roles.yaml", []byte(detailedRoles), 0644); err != nil {
        return fmt.Errorf("failed to write roles.yaml: %w", err)
    }

    detailedServers := `# Server definitions with metadata and access restrictions.

- name: localhost
  addr: 127.0.0.1:22
  labels:
    env: "local"
    region: "us-east-1"
    os: "linux"
  allowed_roles: ["admin", "developer", "auditor"]

- name: dev-server-1
  addr: 192.168.10.20:22
  labels:
    env: "development"
    region: "us-west-2"
    os: "linux"
  allowed_roles: ["developer", "admin"]

- name: prod-db-server
  addr: 10.0.5.4:22
  labels:
    env: "production"
    region: "us-east-1"
    os: "linux"
  allowed_roles: ["admin"]

- name: windows-host
  addr: 192.168.100.50:22
  labels:
    env: "production"
    os: "windows"
  allowed_roles: ["admin"]
`

    if err := os.WriteFile("config/servers.yaml", []byte(detailedServers), 0644); err != nil {
        return fmt.Errorf("failed to write servers.yaml: %w", err)
    }

    var certFile, keyFile string
    if secure {
        if err := GenerateTLS(); err != nil {
            return fmt.Errorf("TLS generation failed: %w", err)
        }
        certFile = "config/cert.pem"
        keyFile = "config/key.pem"
    } else {
        // Use sample cert/key paths without generating
        certFile = "config/sample-cert.pem"
        keyFile = "config/sample-key.pem"
    }

    // Write allsafe-access.yaml with server & redis config
    if err := writeAppConfig(certFile, keyFile, secure, "localhost:6379"); err != nil {
        return err
    }

    return nil
}

// writeAppConfig writes the allsafe-access.yaml config file with TLS and Redis info
func writeAppConfig(certFile, keyFile string, secure bool, redisAddr string) error {
    cfg := AppConfig{
        Server: ServerConfig{
            Address:     "0.0.0.0:8443",
            TLSCertFile: certFile,
            TLSKeyFile:  keyFile,
            Secure:      secure,
        },
        Redis: RedisConfig{
            Address: redisAddr,
        },
    }

    data, err := yaml.Marshal(&cfg)
    if err != nil {
        return fmt.Errorf("failed to marshal app config: %w", err)
    }

    if err := os.WriteFile(AppConfigFile, data, 0644); err != nil {
        return fmt.Errorf("failed to write app config: %w", err)
    }

    absPath, _ := filepath.Abs(AppConfigFile)
    fmt.Printf("Allsafe Access config file created at: %s\n", absPath)
    return nil
}
