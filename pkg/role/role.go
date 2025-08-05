package role

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"gopkg.in/yaml.v2"
)

// Role represents a role from roles/*.yaml
type Role struct {
	Kind     string `yaml:"kind"`
	Version  string `yaml:"version"`
	Metadata struct {
		Description string `yaml:"description"`
	} `yaml:"metadata"`
	Spec struct {
		Options struct {
			MaxSessionTTL string `yaml:"max_session_ttl"`
			SSHFileCopy   bool   `yaml:"ssh_file_copy"`
		} `yaml:"options"`
		Allow struct {
			Logins    []string            `yaml:"logins"`
			NodeLabels []map[string]interface{} `yaml:"node_labels"`
			Rules     []Rule              `yaml:"rules"`
		} `yaml:"allow"`
		Deny struct {
			Logins []string `yaml:"logins"`
			Rules  []Rule   `yaml:"rules"`
		} `yaml:"deny"`
	} `yaml:"spec"`
}

// Rule represents an allow/deny rule within a role
type Rule struct {
	Resources []string            `yaml:"resources"`
	Verbs     []string            `yaml:"verbs"`
	NodeLabels map[string]interface{} `yaml:"node_labels,omitempty"`
}

// LoadRolesFromDirectory reads all YAML files in the specified directory
// and parses them into a map of Role objects, keyed by their filename (without extension).
func LoadRolesFromDirectory(dir string) (map[string]Role, error) {
	loadedRoles := make(map[string]Role)

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read roles directory %s: %w", dir, err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}

		filePath := filepath.Join(dir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("ERROR: Failed to read role file %s: %v", filePath, err)
			continue
		}

		var role Role
		if err := yaml.Unmarshal(data, &role); err != nil {
			log.Printf("ERROR: Failed to parse role file %s. YAML content:\n---\n%s\n---\nUnmarshal Error: %v", filePath, string(data), err)
			continue
		}

		roleName := strings.TrimSuffix(file.Name(), ".yaml")
		loadedRoles[roleName] = role
		log.Printf("Loaded role: %s from %s", roleName, filePath)
	}

	return loadedRoles, nil
}