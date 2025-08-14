package role

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path/filepath"
)

// Permission represents a single permission rule within a role.
// This is now a public, top-level struct so other packages can use it.
type Permission struct {
	Node   string   `yaml:"node"`
	Logins []string `yaml:"logins"`
}

// Role represents the structure of a role configuration YAML file.
type Role struct {
	Kind    string `yaml:"kind"`
	Version string `yaml:"version"`
	Metadata struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"metadata"`
	Spec struct {
		Options struct {
			MaxSessionTTL string `yaml:"max_session_ttl"`
			SSHFileCopy   bool   `yaml:"ssh_file_copy"`
		} `yaml:"options"`
		Permissions []Permission `yaml:"permissions"`
	} `yaml:"spec"`
}

// RoleManager manages a collection of loaded roles.
type RoleManager struct {
	roles map[string]Role
}

// NewRoleManager creates and initializes a RoleManager by reading all YAML files
// from the specified directory.
func NewRoleManager(configDir string) (*RoleManager, error) {
	manager := &RoleManager{
		roles: make(map[string]Role),
	}

	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read role config directory %s: %w", configDir, err)
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".yaml" {
			continue
		}

		filePath := filepath.Join(configDir, file.Name())
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read role file %s: %w", filePath, err)
		}

		var r Role
		if err := yaml.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("failed to unmarshal role file %s: %w", filePath, err)
		}

		manager.roles[r.Metadata.Name] = r
	}

	return manager, nil
}

// GetRole retrieves a role by its name.
func (rm *RoleManager) GetRole(name string) (Role, bool) {
	role, found := rm.roles[name]
	return role, found
}
