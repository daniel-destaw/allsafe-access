package auth

import (
	"fmt"
	"time"

	"allsafe-access/pkg/role"
	"allsafe-access/pkg/user"
)

// UserPermissions is a flattened view of all permissions granted to a user.
type UserPermissions struct {
	MaxSessionTTL time.Duration
	SSHFileCopy   bool
	Permissions   []role.Permission
}

// Permission is a simplified struct for permission rules.
type Permission struct {
	Node   string
	Logins []string
}

// AuthChecker is the main authentication and authorization component.
type AuthChecker struct {
	userManager *user.UserManager
	roleManager *role.RoleManager
}

// NewAuthChecker initializes the AuthChecker with user and role managers.
func NewAuthChecker(userFilePath, roleConfigDir string) (*AuthChecker, error) {
	userManager, err := user.NewUserManager(userFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create UserManager: %w", err)
	}

	roleManager, err := role.NewRoleManager(roleConfigDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create RoleManager: %w", err)
	}

	return &AuthChecker{
		userManager: userManager,
		roleManager: roleManager,
	}, nil
}

// VerifyUserAndGetPermissions checks a user's password and aggregates their permissions.
func (ac *AuthChecker) VerifyUserAndGetPermissions(username, password string) (*user.User, *UserPermissions, error) {
	u, found := ac.userManager.GetUser(username)
	if !found {
		return nil, nil, fmt.Errorf("user not found: %s", username)
	}

	if u.Password != password {
		return nil, nil, fmt.Errorf("invalid password for user: %s", username)
	}

	// Initialize with default, safe permissions.
	userPerms := &UserPermissions{
		MaxSessionTTL: 0,
		SSHFileCopy:   false,
		Permissions:   make([]role.Permission, 0),
	}

	for _, roleName := range u.Roles {
		r, found := ac.roleManager.GetRole(roleName)
		if !found {
			return nil, nil, fmt.Errorf("role '%s' not found for user '%s'", roleName, username)
		}

		// Aggregate permissions. We will take the max TTL and logical OR for ssh_file_copy.
		if r.Spec.Options.MaxSessionTTL != "" {
			d, err := time.ParseDuration(r.Spec.Options.MaxSessionTTL)
			if err == nil && d > userPerms.MaxSessionTTL {
				userPerms.MaxSessionTTL = d
			}
		}
		if r.Spec.Options.SSHFileCopy {
			userPerms.SSHFileCopy = true
		}

		// Aggregate all permission rules.
		for _, p := range r.Spec.Permissions {
			userPerms.Permissions = append(userPerms.Permissions, p)
		}
	}

	return &u, userPerms, nil
}
