package rbac

import (
	"errors"
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

// Role holds RBAC role info
type Role struct {
	Permissions   []string `yaml:"permissions"`
	AllowedLogins []string `yaml:"allowed_logins"`
	NodeLabels    []string `yaml:"node_labels"`
}

// Server holds server access info
type Server struct {
	Name         string   `yaml:"name"`
	Address      string   `yaml:"address"`       // hostname, IP, domain, localhost
	AllowedRoles []string `yaml:"allowed_roles"` // roles allowed to access server
}

// RBACConfig stores all roles and servers loaded from config files
type RBACConfig struct {
	Roles   map[string]Role
	Servers []Server
}

// LoadRoles reads and validates roles.yaml
func LoadRoles(path string) (map[string]Role, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read roles file: %w", err)
	}
	roles := make(map[string]Role)
	if err := yaml.Unmarshal(data, &roles); err != nil {
		return nil, fmt.Errorf("failed to parse roles yaml: %w", err)
	}

	for roleName, role := range roles {
		if len(role.Permissions) == 0 {
			return nil, fmt.Errorf("role '%s' must have at least one permission", roleName)
		}
		if len(role.AllowedLogins) == 0 {
			return nil, fmt.Errorf("role '%s' must have at least one allowed_login", roleName)
		}
		if len(role.NodeLabels) == 0 {
			return nil, fmt.Errorf("role '%s' must have at least one node_label", roleName)
		}
	}
	return roles, nil
}

// LoadServers reads and validates servers.yaml
func LoadServers(path string) ([]Server, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read servers file: %w", err)
	}

	var servers []Server
	if err := yaml.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("failed to parse servers yaml: %w", err)
	}

	for i, srv := range servers {
		if srv.Name == "" {
			return nil, fmt.Errorf("server entry #%d missing name", i+1)
		}
		if srv.Address == "" {
			return nil, fmt.Errorf("server '%s' missing address", srv.Name)
		}
		if len(srv.AllowedRoles) == 0 {
			return nil, fmt.Errorf("server '%s' must specify allowed_roles", srv.Name)
		}
	}
	return servers, nil
}

// LoadRBACConfig loads and validates roles and servers, checks allowed_roles exist
func LoadRBACConfig(rolesPath, serversPath string) (*RBACConfig, error) {
	roles, err := LoadRoles(rolesPath)
	if err != nil {
		return nil, err
	}
	servers, err := LoadServers(serversPath)
	if err != nil {
		return nil, err
	}

	for _, srv := range servers {
		for _, role := range srv.AllowedRoles {
			if _, ok := roles[role]; !ok {
				return nil, fmt.Errorf("server '%s' references unknown role '%s'", srv.Name, role)
			}
		}
	}

	return &RBACConfig{
		Roles:   roles,
		Servers: servers,
	}, nil
}

// Query methods:

func (c *RBACConfig) GetRoleNames() []string {
	names := make([]string, 0, len(c.Roles))
	for name := range c.Roles {
		names = append(names, name)
	}
	return names
}

func (c *RBACConfig) GetPermissions(roleName string) ([]string, error) {
	role, ok := c.Roles[roleName]
	if !ok {
		return nil, errors.New("role not found")
	}
	return role.Permissions, nil
}

func (c *RBACConfig) GetServers() []Server {
	return c.Servers
}

func (c *RBACConfig) GetAllowedRolesForServer(serverName string) ([]string, error) {
	for _, srv := range c.Servers {
		if srv.Name == serverName {
			return srv.AllowedRoles, nil
		}
	}
	return nil, errors.New("server not found")
}
