package auth

import (
	"fmt"
	"time"

	"allsafe-access/pkg/role"
	"allsafe-access/pkg/user"
	"golang.org/x/crypto/bcrypt"
)

// UserPermissions is a flattened view of all permissions granted to a user.
type UserPermissions struct {
	MaxSessionTTL time.Duration
	SSHFileCopy   bool
	Permissions   []role.Permission
}

// AuthChecker is the main authentication and authorization component.
type AuthChecker struct {
	userManager *user.UserManager
	roleManager *role.RoleManager
}

// NewAuthChecker initializes the AuthChecker with user and role managers.
// The userPath should now be the path to the SQLite database file.
func NewAuthChecker(userDBPath, roleConfigDir string) (*AuthChecker, error) {
	userManager, err := user.NewUserManager(userDBPath)
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

	// Check if the password hash is valid before comparing
	if !u.PasswordHash.Valid {
		return nil, nil, fmt.Errorf("user '%s' has not set a password", username)
	}

	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, nil, fmt.Errorf("invalid password for user: %s", username)
		}
		return nil, nil, fmt.Errorf("failed to verify password: %w", err)
	}

	userPerms := &UserPermissions{
		MaxSessionTTL: 0,
		SSHFileCopy:   false,
		Permissions:   make([]role.Permission, 0),
	}

	// Corrected to use the single role from the User struct
	r, found := ac.roleManager.GetRole(u.Role)
	if !found {
		return nil, nil, fmt.Errorf("role '%s' not found for user '%s'", u.Role, username)
	}

	if r.Spec.Options.MaxSessionTTL != "" {
		d, err := time.ParseDuration(r.Spec.Options.MaxSessionTTL)
		if err == nil && d > userPerms.MaxSessionTTL {
			userPerms.MaxSessionTTL = d
		}
	}
	if r.Spec.Options.SSHFileCopy {
		userPerms.SSHFileCopy = true
	}

	for _, p := range r.Spec.Permissions {
		userPerms.Permissions = append(userPerms.Permissions, p)
	}

	return &u, userPerms, nil
}