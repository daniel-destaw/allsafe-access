package auth

import (
	"fmt"
	"log"
	"sync"

	"allsafe-access/pkg/role" // <--- IMPORTANT: Update this import path to your Go module name
	"allsafe-access/pkg/user" // <--- IMPORTANT: Update this import path to your Go module name
)

// UserPermissions holds the combined and effective permissions for a user across all their assigned roles.
type UserPermissions struct {
	MaxSessionTTL string
	SSHFileCopy   bool
	AllowedLogins []string
	// FIX: Changed NodeLabels to []map[string]interface{} to match pkg/role/role.go
	AllowedNodeLabels []map[string]interface{}
	AllowedRules  []role.Rule
	DeniedLogins  []string
	DeniedRules   []role.Rule
}

// AuthChecker orchestrates user authentication and permission retrieval.
type AuthChecker struct {
	userManager *user.UserManager // Reference to the user manager
	roles       map[string]role.Role // Map of loaded roles
	rolesMu     sync.RWMutex        // Mutex for the roles map
}

// NewAuthChecker creates and initializes the AuthChecker.
// It takes directories for user and role configurations.
func NewAuthChecker(usersConfigDir, rolesConfigDir string) (*AuthChecker, error) {
	ac := &AuthChecker{}

	// Initialize UserManager
	var err error
	ac.userManager, err = user.NewUserManager(usersConfigDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create user manager: %w", err)
	}

	// Load roles using the pkg/role package
	loadedRoles, err := role.LoadRolesFromDirectory(rolesConfigDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}
	ac.rolesMu.Lock()
	ac.roles = loadedRoles
	ac.rolesMu.Unlock()

	log.Printf("AuthChecker: Initialized with %d users and %d roles.", ac.userManager.UserCount(), len(ac.roles))

	return ac, nil
}

// VerifyUserAndGetPermissions authenticates a user by username and password,
// and if successful, returns their effective permissions.
func (ac *AuthChecker) VerifyUserAndGetPermissions(username, password string) (*user.User, *UserPermissions, error) {
	// 1. Get user from UserManager
	userObj, ok := ac.userManager.GetUserByUsername(username)
	if !ok {
		return nil, nil, fmt.Errorf("user '%s' not found", username)
	}

	// 2. Authenticate user (password check)
	// IMPORTANT: Replace with password hashing (e.g., bcrypt) in production!
	if userObj.Password != password {
		return userObj, nil, fmt.Errorf("invalid password for user '%s'", username)
	}

	// 3. Get effective permissions based on roles
	permissions, err := ac.GetUserEffectivePermissions(userObj)
	if err != nil {
		return userObj, nil, fmt.Errorf("failed to get effective permissions for user '%s': %w", username, err)
	}

	return userObj, permissions, nil
}


// GetUserEffectivePermissions aggregates all permissions for a given user based on their assigned roles.
// This is a private helper used by VerifyUserAndGetPermissions.
func (ac *AuthChecker) GetUserEffectivePermissions(userObj *user.User) (*UserPermissions, error) {
	if userObj == nil {
		return nil, fmt.Errorf("user object cannot be nil")
	}

	permissions := &UserPermissions{
		AllowedLogins:     []string{},
		// FIX: Initialize AllowedNodeLabels with the correct type
		AllowedNodeLabels: []map[string]interface{}{},
		AllowedRules:      []role.Rule{},
		DeniedLogins:      []string{},
		DeniedRules:       []role.Rule{},
	}

	// Start with the user's direct logins from users.json
	if userObj.Logins != nil {
		permissions.AllowedLogins = append(permissions.AllowedLogins, userObj.Logins...)
	}

	ac.rolesMu.RLock() // Read lock for accessing ac.roles map
	defer ac.rolesMu.RUnlock()

	for _, roleName := range userObj.Roles {
		currentRole, ok := ac.roles[roleName]
		if !ok {
			log.Printf("Warning: User '%s' is assigned to unknown role '%s'. Skipping this role.", userObj.Username, roleName)
			continue
		}

		// Aggregate options (simplistic: last one wins for MaxSessionTTL, true if any for SSHFileCopy)
		if currentRole.Spec.Options.MaxSessionTTL != "" {
			permissions.MaxSessionTTL = currentRole.Spec.Options.MaxSessionTTL
		}
		if currentRole.Spec.Options.SSHFileCopy {
			permissions.SSHFileCopy = true
		}

		// Aggregate allow rules
		if currentRole.Spec.Allow.Logins != nil {
			permissions.AllowedLogins = append(permissions.AllowedLogins, currentRole.Spec.Allow.Logins...)
		}
		// FIX: Now this append operation will work because types match
		if currentRole.Spec.Allow.NodeLabels != nil {
			permissions.AllowedNodeLabels = append(permissions.AllowedNodeLabels, currentRole.Spec.Allow.NodeLabels...)
		}
		if currentRole.Spec.Allow.Rules != nil {
			permissions.AllowedRules = append(permissions.AllowedRules, currentRole.Spec.Allow.Rules...)
		}

		// Aggregate deny rules
		if currentRole.Spec.Deny.Logins != nil {
			permissions.DeniedLogins = append(permissions.DeniedLogins, currentRole.Spec.Deny.Logins...)
		}
		if currentRole.Spec.Deny.Rules != nil {
			permissions.DeniedRules = append(permissions.DeniedRules, currentRole.Spec.Deny.Rules...)
		}
	}

	// Deduplicate logins (both allowed and denied)
	permissions.AllowedLogins = uniqueStrings(permissions.AllowedLogins)
	permissions.DeniedLogins = uniqueStrings(permissions.DeniedLogins)

	return permissions, nil
}

// uniqueStrings is a helper to deduplicate string slices.
func uniqueStrings(slice []string) []string {
	keys := make(map[string]struct{})
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = struct{}{}
			list = append(list, entry)
		}
	}
	return list
}