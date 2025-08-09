package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// dbPath is the hardcoded path to the SQLite database file.
var dbPath = "./allsafe_admin.db"

// role will hold the value of the --role flag for user creation.
var role string

// servePort is the port for the web server, configurable via a flag.
var servePort string

// passwordPolicy will hold the value of the --policy flag for user creation.
var passwordPolicy string

// secretKey is used for signing the invitation token. In a real application,
// this should be a long, randomly generated value read from a config file.
var secretKey = []byte("a-very-long-and-secure-secret-key-for-signing-tokens")

// tokenPayload is the structure for the invitation token payload.
type tokenPayload struct {
	Username      string `json:"username"`
	PasswordPolicy string `json:"policy"`
	Nonce         string `json:"nonce"`
}

// passwordPolicyDetails defines the requirements for each policy level.
var passwordPolicyDetails = map[string]struct {
	MinLength    int
	HasUppercase bool
	HasNumber    bool
	HasSpecial   bool
}{
	"none": {MinLength: 0},
	"medium": {
		MinLength:    8,
		HasUppercase: true,
		HasNumber:    true,
	},
	"hard": {
		MinLength:    12,
		HasUppercase: true,
		HasNumber:    true,
		HasSpecial:   true,
	},
}

// rootCmd represents the base command for the admin CLI.
var rootCmd = &cobra.Command{
	Use:   "allsafe-admin",
	Short: "A CLI to manage Allsafe Access users and services",
	Long: `allsafe-admin is a command-line tool for administrators to manage
users, view audit logs, and control active sessions on the Allsafe Access
proxy.`,
}

// userCmd is the parent command for all user-related actions.
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage user accounts",
	Long:  "Commands for adding, deleting, and managing users.",
}

// userAddCmd adds a new user with a generated invitation token.
var userAddCmd = &cobra.Command{
	Use:   "add [username]",
	Short: "Add a new user with an invitation URL",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		log.Printf("Attempting to add new user: %s with role: %s and policy: %s\n", username, role, passwordPolicy)

		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()

		// Generate a new, unique nonce for the token.
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			log.Fatalf("Failed to generate nonce: %v", err)
		}
		nonce := base64.URLEncoding.EncodeToString(nonceBytes)

		// Create a signed token that includes the policy.
		token, err := createSignedToken(username, passwordPolicy, nonce)
		if err != nil {
			log.Fatalf("Failed to create signed token: %v", err)
		}

		insertSQL := `INSERT INTO users (username, role, invite_token) VALUES (?, ?, ?)`
		_, err = db.Exec(insertSQL, username, role, token)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
				log.Fatalf("Error: User '%s' already exists.", username)
			}
			log.Fatalf("Failed to insert new user: %v", err)
		}

		auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
		actorUsername := "admin"
		details := fmt.Sprintf(`{"invite_token": "%s", "role": "%s", "password_policy": "%s"}`, token, role, passwordPolicy)
		_, err = db.Exec(auditLogSQL, "user_add", actorUsername, username, details)
		if err != nil {
			log.Printf("Warning: Failed to write to audit logs: %v", err)
		}

		// The invitation URL now points to our new web server.
		inviteURL := fmt.Sprintf("http://localhost:%s/invite?token=%s", servePort, token)

		fmt.Printf("User '%s' added successfully with role '%s' and password policy '%s'!\n", username, role, passwordPolicy)
		fmt.Printf("Invitation URL: %s\n", inviteURL)
		fmt.Println("\nTo start the web server, run: go run cmd/allsafe-admin/main.go serve")
	},
}

// userDeleteCmd deletes a user.
var userDeleteCmd = &cobra.Command{
	Use:   "delete [username]",
	Short: "Delete a user account",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		log.Printf("Attempting to delete user: %s\n", username)

		// Confirmation prompt
		fmt.Printf("Are you sure you want to delete user '%s'? This action cannot be undone. (yes/no): ", username)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(response)) != "yes" {
			fmt.Println("User deletion canceled.")
			return
		}

		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()

		// Delete the user from the 'users' table.
		deleteSQL := `DELETE FROM users WHERE username = ?`
		result, err := db.Exec(deleteSQL, username)
		if err != nil {
			log.Fatalf("Failed to delete user: %v", err)
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			log.Fatalf("Error: User '%s' not found.", username)
		}

		// Log the action in the 'audit_logs' table.
		auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
		actorUsername := "admin"
		_, err = db.Exec(auditLogSQL, "user_delete", actorUsername, username, "{}")
		if err != nil {
			log.Printf("Warning: Failed to write to audit logs: %v", err)
		}

		fmt.Printf("User '%s' deleted successfully.\n", username)
	},
}

// userResetPasswordCmd resets a user's password by generating a new invite token.
var userResetPasswordCmd = &cobra.Command{
	Use:   "reset-password [username]",
	Short: "Generate a new password reset URL for a user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		log.Printf("Attempting to reset password for user: %s\n", username)

		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()

		// Check if the user exists first.
		var exists bool
		querySQL := `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`
		err = db.QueryRow(querySQL, username).Scan(&exists)
		if err != nil || !exists {
			log.Fatalf("Error: User '%s' not found.", username)
		}
		
		// Generate a new, unique nonce for the token.
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			log.Fatalf("Failed to generate nonce: %v", err)
		}
		nonce := base64.URLEncoding.EncodeToString(nonceBytes)

		// Create a new signed token. Note: The policy for a reset is hardcoded to "none" for simplicity
		// but could be an optional flag as well.
		token, err := createSignedToken(username, "none", nonce)
		if err != nil {
			log.Fatalf("Failed to create signed token: %v", err)
		}

		// Update the user's record with the new token and null password hash.
		updateSQL := `UPDATE users SET password_hash = NULL, invite_token = ? WHERE username = ?`
		_, err = db.Exec(updateSQL, token, username)
		if err != nil {
			log.Fatalf("Failed to reset password for user: %v", err)
		}

		// Log the action in the 'audit_logs' table.
		auditLogSQL := `INSERT INTO audit_logs (action, actor_username, target_username, details) VALUES (?, ?, ?, ?)`
		actorUsername := "admin"
		details := fmt.Sprintf(`{"invite_token": "%s"}`, token)
		_, err = db.Exec(auditLogSQL, "password_reset", actorUsername, username, details)
		if err != nil {
			log.Printf("Warning: Failed to write to audit logs: %v", err)
		}

		inviteURL := fmt.Sprintf("http://localhost:%s/invite?token=%s", servePort, token)

		fmt.Printf("Password reset successfully for user '%s'!\n", username)
		fmt.Printf("New password reset URL: %s\n", inviteURL)
	},
}

// userListCmd lists all users in the database.
var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Attempting to list all users...")

		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()

		rows, err := db.Query(`SELECT id, username, role FROM users`)
		if err != nil {
			log.Fatalf("Failed to query users: %v", err)
		}
		defer rows.Close()

		fmt.Printf("ID\tUsername\tRole\n")
		fmt.Println("--------------------------------")

		for rows.Next() {
			var id int
			var username, role string
			if err := rows.Scan(&id, &username, &role); err != nil {
				log.Fatalf("Failed to scan row: %v", err)
			}
			fmt.Printf("%d\t%s\t\t%s\n", id, username, role)
		}

		if err := rows.Err(); err != nil {
			log.Fatalf("Error during rows iteration: %v", err)
		}
	},
}

// userGetCmd retrieves and displays detailed information about a single user.
var userGetCmd = &cobra.Command{
	Use:   "get [username]",
	Short: "Get details for a specific user",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		log.Printf("Attempting to get user details for: %s\n", username)

		db, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		defer db.Close()

		var id int
		var passwordHash, inviteToken sql.NullString
		var role, createdAt string

		querySQL := `SELECT id, role, password_hash, invite_token, created_at FROM users WHERE username = ?`
		err = db.QueryRow(querySQL, username).Scan(&id, &role, &passwordHash, &inviteToken, &createdAt)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Fatalf("Error: User '%s' not found.", username)
			}
			log.Fatalf("Failed to get user details: %v", err)
		}

		fmt.Printf("User Details for '%s'\n", username)
		fmt.Println("--------------------------------")
		fmt.Printf("ID:\t\t%d\n", id)
		fmt.Printf("Username:\t%s\n", username)
		fmt.Printf("Role:\t\t%s\n", role)
		fmt.Printf("Created At:\t%s\n", createdAt)

		if passwordHash.Valid {
			fmt.Printf("Password Hash:\t(Set)\n")
		} else {
			fmt.Printf("Password Hash:\t(Not set)\n")
		}

		if inviteToken.Valid {
			fmt.Printf("Invite Token:\t(Set)\n") // Don't print the full token for security
		} else {
			fmt.Printf("Invite Token:\t(NULL - Password is set)\n")
		}
	},
}

// serveCmd starts the web server for handling invitation and password reset links.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the web server for user invitations",
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Starting web server on port %s...", servePort)

		// Handler for the invitation link.
		http.HandleFunc("/invite", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "Invitation token is missing.", http.StatusBadRequest)
				return
			}

			// Validate and decode the signed token.
			payload, err := validateAndDecodeToken(token)
			if err != nil {
				http.Error(w, "Invalid or expired invitation token.", http.StatusForbidden)
				log.Printf("Token validation failed: %v", err)
				return
			}

			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				log.Printf("Failed to open database: %v", err)
				return
			}
			defer db.Close()

			var storedToken string
			querySQL := `SELECT invite_token FROM users WHERE username = ? AND password_hash IS NULL`
			err = db.QueryRow(querySQL, payload.Username).Scan(&storedToken)
			if err != nil {
				if err == sql.ErrNoRows || storedToken != token {
					http.Error(w, "Invalid or expired invitation token.", http.StatusForbidden)
				} else {
					http.Error(w, "Database error", http.StatusInternalServerError)
					log.Printf("Failed to query user by token: %v", err)
				}
				return
			}

			// Serve the HTML form to set the password.
			tmpl, err := template.New("invite").Parse(inviteFormHTML)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				log.Printf("Failed to parse template: %v", err)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			// Pass the username to the template along with the token and policy.
			tmpl.Execute(w, struct{ Token, PasswordPolicy, Username string }{Token: token, PasswordPolicy: payload.PasswordPolicy, Username: payload.Username})
		})

		// Handler for submitting the new password.
		http.HandleFunc("/set-password", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.ParseForm()
			token := r.FormValue("token")
			password := r.FormValue("password")
			confirmPassword := r.FormValue("confirm_password")

			if token == "" || password == "" || confirmPassword == "" {
				http.Error(w, "Token, password, or confirm password missing.", http.StatusBadRequest)
				return
			}

			// CRITICAL: Perform server-side validation to ensure passwords match.
			if password != confirmPassword {
				http.Error(w, "Passwords do not match.", http.StatusBadRequest)
				return
			}
			
			// Validate and decode the signed token.
			payload, err := validateAndDecodeToken(token)
			if err != nil {
				http.Error(w, "Invalid or expired invitation token.", http.StatusForbidden)
				log.Printf("Token validation failed: %v", err)
				return
			}

			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				log.Printf("Failed to open database: %v", err)
				return
			}
			defer db.Close()

			var storedToken string
			querySQL := `SELECT invite_token FROM users WHERE username = ? AND password_hash IS NULL`
			err = db.QueryRow(querySQL, payload.Username).Scan(&storedToken)
			if err != nil || storedToken != token {
				http.Error(w, "Invalid token or password already set.", http.StatusForbidden)
				return
			}

			// CRITICAL: Perform server-side validation against the password policy from the token.
			if err := validatePasswordComplexity(password, payload.PasswordPolicy); err != nil {
				log.Printf("Password validation failed for user '%s': %v", payload.Username, err)
				http.Error(w, fmt.Sprintf("Password validation failed: %v", err), http.StatusBadRequest)
				return
			}

			// Password hashing and database update logic.
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Failed to hash password", http.StatusInternalServerError)
				log.Printf("Failed to hash password: %v", err)
				return
			}

			updateSQL := `UPDATE users SET password_hash = ?, invite_token = NULL WHERE username = ? AND invite_token = ? AND password_hash IS NULL`
			result, err := db.Exec(updateSQL, hashedPassword, payload.Username, token)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				log.Printf("Failed to update password: %v", err)
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				http.Error(w, "Invalid token or password already set.", http.StatusForbidden)
				return
			}

			fmt.Fprintf(w, `
				<!DOCTYPE html>
				<html>
				<head>
					<title>Success</title>
					<script src="https://cdn.tailwindcss.com"></script>
				</head>
				<body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
					<div class="max-w-md w-full bg-white rounded-lg shadow-xl p-8 text-center">
						<h1 class="text-3xl font-bold text-green-600 mb-4">Success!</h1>
						<p class="text-gray-700">Your password has been set. You can now close this page and log in.</p>
					</div>
				</body>
				</html>
			`)
		})

		if err := http.ListenAndServe(":"+servePort, nil); err != nil {
			log.Fatalf("Failed to start web server: %v", err)
		}
	},
}

// createSignedToken generates a base64-encoded, HMAC-signed token.
func createSignedToken(username, policy, nonce string) (string, error) {
	payload := tokenPayload{
		Username: username,
		PasswordPolicy: policy,
		Nonce: nonce,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, secretKey)
	h.Write(payloadBytes)
	signature := h.Sum(nil)

	// Concatenate payload and signature with a dot separator.
	token := fmt.Sprintf("%s.%s",
		base64.URLEncoding.EncodeToString(payloadBytes),
		base64.URLEncoding.EncodeToString(signature))

	return token, nil
}

// validateAndDecodeToken validates the HMAC signature and decodes the token payload.
func validateAndDecodeToken(token string) (*tokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	signature, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	h := hmac.New(sha256.New, secretKey)
	h.Write(payloadBytes)
	expectedSignature := h.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return nil, fmt.Errorf("invalid token signature")
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &payload, nil
}

// inviteFormHTML is the embedded HTML for the password creation page.
const inviteFormHTML = `
<!DOCTYPE html>
<html>
<head>
	<title>Set Your Password</title>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" xintegrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ96j3JpBqL0zS7rM3k1g2tYvK2z5x5wTq8g8f/1a8m9/4e3p5Pz/2t6/f5e5w==" crossorigin="anonymous" referrerpolicy="no-referrer" />
	<script src="https://cdn.tailwindcss.com"></script>
	<style>
		@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
		body { font-family: 'Inter', sans-serif; }
		.error-message { color: #ef4444; font-size: 0.875rem; margin-top: 0.25rem; }
		.policy-list li { display: flex; align-items: center; }
		.policy-list li i { margin-right: 0.5rem; }
	</style>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
	<div class="max-w-md w-full bg-white rounded-lg shadow-xl p-8">
		<div class="text-center mb-6">
			<i class="fa-solid fa-lock text-5xl text-blue-600"></i>
			<h1 class="mt-4 text-2xl font-bold text-gray-800">Set Your Password</h1>
			<p class="text-sm text-gray-500 mt-2">Create a new password for <strong class="text-blue-600">{{.Username}}</strong>.</p>
		</div>
		<form action="/set-password" method="post" class="space-y-6" onsubmit="return validatePassword(event)">
			<input type="hidden" name="token" value="{{.Token}}">
			<input type="hidden" id="policy" value="{{.PasswordPolicy}}">
			<div>
				<label for="password" class="block text-sm font-medium text-gray-700">New Password</label>
				<input type="password" id="password" name="password" required class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200" oninput="updatePasswordStrength()">
			</div>
			<div>
				<label for="confirm_password" class="block text-sm font-medium text-gray-700">Confirm New Password</label>
				<input type="password" id="confirm_password" name="confirm_password" required class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition-colors duration-200">
				<p id="match-error" class="error-message hidden">Passwords do not match.</p>
			</div>
			
			{{if ne .PasswordPolicy "none"}}
			<div class="bg-gray-50 p-4 rounded-md shadow-sm">
				<h3 class="text-sm font-semibold text-gray-800 mb-2">Password Requirements:</h3>
				<ul id="password-requirements" class="text-sm text-gray-600 policy-list space-y-1">
					<li id="length-req" class="text-red-500"><i class="fas fa-times-circle"></i> Minimum {{if eq .PasswordPolicy "medium"}}8{{else}}12{{end}} characters</li>
					<li id="uppercase-req" class="text-red-500"><i class="fas fa-times-circle"></i> At least one uppercase letter</li>
					<li id="number-req" class="text-red-500"><i class="fas fa-times-circle"></i> At least one number</li>
					{{if eq .PasswordPolicy "hard"}}
					<li id="special-req" class="text-red-500"><i class="fas fa-times-circle"></i> At least one special character</li>
					{{end}}
				</ul>
			</div>
			{{end}}

			<div>
				<button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-200">
					Set Password
				</button>
			</div>
		</form>
	</div>
	<script>
		const passwordPolicyDetails = {
			"none": { minLength: 0 },
			"medium": { minLength: 8, hasUppercase: true, hasNumber: true, hasSpecial: false },
			"hard": { minLength: 12, hasUppercase: true, hasNumber: true, hasSpecial: true }
		};

		function updatePasswordStrength() {
			const password = document.getElementById('password').value;
			const policy = document.getElementById('policy').value;
			const requirements = passwordPolicyDetails[policy];

			if (policy === "none") {
				return;
			}

			const isLengthValid = password.length >= requirements.minLength;
			const hasUppercase = !requirements.hasUppercase || /[A-Z]/.test(password);
			const hasNumber = !requirements.hasNumber || /[0-9]/.test(password);
			const hasSpecial = !requirements.hasSpecial || /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(password);

			const allValid = isLengthValid && hasUppercase && hasNumber && hasSpecial;

			// Update visual feedback for each requirement
			updateRequirementVisuals('length-req', isLengthValid);
			updateRequirementVisuals('uppercase-req', hasUppercase);
			updateRequirementVisuals('number-req', hasNumber);
			if (requirements.hasSpecial) {
				updateRequirementVisuals('special-req', hasSpecial);
			}

			return allValid;
		}

		function updateRequirementVisuals(elementId, isValid) {
			const element = document.getElementById(elementId);
			if (!element) return;

			const icon = element.querySelector('i');
			if (isValid) {
				element.classList.remove('text-red-500');
				element.classList.add('text-green-600');
				icon.classList.remove('fa-times-circle');
				icon.classList.add('fa-check-circle');
			} else {
				element.classList.remove('text-green-600');
				element.classList.add('text-red-500');
				icon.classList.remove('fa-check-circle');
				icon.classList.add('fa-times-circle');
			}
		}

		function validatePassword(event) {
			const password = document.getElementById('password').value;
			const confirmPassword = document.getElementById('confirm_password').value;
			const matchError = document.getElementById('match-error');

			if (password !== confirmPassword) {
				matchError.classList.remove('hidden');
				event.preventDefault(); // Stop form submission
				return false;
			}
			matchError.classList.add('hidden');

			const policy = document.getElementById('policy').value;
			if (policy !== "none") {
				const isPolicyValid = updatePasswordStrength();
				if (!isPolicyValid) {
					alert("Password does not meet the complexity requirements.");
					event.preventDefault(); // Stop form submission
					return false;
				}
			}

			return true;
		}
	</script>
</body>
</html>
`

// validatePasswordComplexity checks if the given password meets the specified policy requirements.
func validatePasswordComplexity(password, policy string) error {
	details, ok := passwordPolicyDetails[policy]
	if !ok {
		return fmt.Errorf("unknown password policy: %s", policy)
	}
	
	if len(password) < details.MinLength {
		return fmt.Errorf("password must be at least %d characters long", details.MinLength)
	}

	if details.HasUppercase {
		hasUppercase := false
		for _, char := range password {
			if 'A' <= char && char <= 'Z' {
				hasUppercase = true
				break
			}
		}
		if !hasUppercase {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if details.HasNumber {
		hasNumber := false
		for _, char := range password {
			if '0' <= char && char <= '9' {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			return fmt.Errorf("password must contain at least one number")
		}
	}

	if details.HasSpecial {
		hasSpecial := false
		specialChars := `!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`
		for _, char := range password {
			if strings.ContainsRune(specialChars, char) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

// createDatabaseSchema ensures the database and tables exist.
func createDatabaseSchema() {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to open database for schema creation: %v", err)
	}
	defer db.Close()

	usersTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		role TEXT NOT NULL,
		password_hash TEXT,
		invite_token TEXT UNIQUE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`

	auditLogsTableSQL := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action TEXT NOT NULL,
		actor_username TEXT,
		target_username TEXT,
		details TEXT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(usersTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'users' table: %v", err)
	}
	
	_, err = db.Exec(auditLogsTableSQL)
	if err != nil {
		log.Fatalf("Failed to create 'audit_logs' table: %v", err)
	}
}

func init() {
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(serveCmd)

	userCmd.AddCommand(userAddCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userResetPasswordCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userGetCmd)

	// Add the --role and --policy flags to the userAddCmd.
	userAddCmd.Flags().StringVar(&role, "role", "user", "The role of the new user")
	userAddCmd.Flags().StringVar(&passwordPolicy, "policy", "none", "The password complexity policy (none, medium, hard)")

	// Add the --port flag to the serveCmd.
	serveCmd.Flags().StringVar(&servePort, "port", "8081", "The port for the web server to listen on")
}

func main() {
	// Ensure database and schema are ready before running commands.
	createDatabaseSchema()
	
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}