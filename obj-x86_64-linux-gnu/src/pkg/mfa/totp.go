package mfa

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret generates a new TOTP secret for a user.
func GenerateTOTPSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Allsafe Access",
		AccountName: "User", // Placeholder, will be replaced with actual username
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// GenerateTOTPQRCodeURL generates a URL for the QR code image using a pre-existing secret.
func GenerateTOTPQRCodeURL(issuer, user, secret string) (string, error) {
	// Manually construct the otpauth URL to avoid the missing function.
	// This ensures the provided secret is always used.

	// We escape the issuer and user strings to make sure they're safe for a URL.
	escapedIssuer := url.QueryEscape(issuer)
	escapedUser := url.QueryEscape(user)

	// Construct the URL string using the secret provided to this function.
	url := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		escapedIssuer,
		escapedUser,
		secret,
		escapedIssuer,
	)

	return url, nil
}

// ValidateTOTP checks if the given TOTP code is valid.
func ValidateTOTP(code, secret string) bool {
	log.Printf("Validating TOTP: code=%s, secret=%s", code, secret)
	return totp.Validate(code, secret)
}

// IsTOTPEnabledForUser checks the database if a user has an enabled TOTP device.
func IsTOTPEnabledForUser(db *sql.DB, userID int64) (bool, string, error) {
	var config string
	var isEnabled int // Use int for INTEGER NOT NULL DEFAULT 1
	query := `SELECT config, is_enabled FROM mfa_devices WHERE user_id = ?`
	err := db.QueryRow(query, userID).Scan(&config, &isEnabled)

	if err != nil {
		if err == sql.ErrNoRows {
			// No MFA device found, so it's not enabled.
			return false, "", nil
		}
		return false, "", fmt.Errorf("database query failed: %w", err)
	}

	// If a device is found, return its enabled status and config.
	return isEnabled == 1, config, nil
}