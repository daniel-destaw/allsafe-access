package session

import (
    "allsafe-access/pkg/auth" // Adjust import path
    "allsafe-access/pkg/user" // Adjust import path
)

// SessionTokenContent defines the data that will be stored in a session.
// In a real JWT-based system, this would be the payload of the token.
type SessionTokenContent struct {
    User        *user.User          `json:"user"`
    Permissions *auth.UserPermissions `json:"permissions"`
    ProxyURL    string              `json:"proxy_url"` // <--- ADD THIS LINE
    // Add fields like Expiry time, IssuedAt time, etc., for a more robust session
    // Expiry int64 `json:"exp"` // Unix timestamp for expiration
}