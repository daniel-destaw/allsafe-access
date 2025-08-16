package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"allsafe-access/pkg/mfa" // Replace with your actual project path
)

func main() {
	// These values would be loaded from your database,
	// after they were generated and saved during the user's setup process.

	// TOTP
	const totpSecret = "HJTPGZLVCJJEUJFZTWQVUWK5TTOVK5ZQ"
	fmt.Println("TOTP setup complete. Enter the code from your authenticator app:")
	fmt.Print("> ")

	// Read user input
	reader := bufio.NewReader(os.Stdin)
	userTotpCode, _ := reader.ReadString('\n')
	userTotpCode = strings.TrimSpace(userTotpCode)

	// Verify the TOTP code
	if mfa.VerifyTOTP(userTotpCode, totpSecret) {
		fmt.Printf("TOTP code %s is valid.\n", userTotpCode)
	} else {
		fmt.Printf("TOTP code %s is invalid.\n", userTotpCode)
	}


	fmt.Println("\n--- Verifying HOTP ---")
	// HOTP
	const hotpSecret = "5EZRWUXHUAHU34US"
	var hotpCounter uint64 = 0 // This would be the counter value stored in the database
	
	fmt.Println("HOTP verification. Enter the code from your authenticator app:")
	fmt.Print("> ")

	// Read user input
	userHotpCode, _ := reader.ReadString('\n')
	userHotpCode = strings.TrimSpace(userHotpCode)

	// Verify the HOTP code.
	if mfa.VerifyHOTP(userHotpCode, hotpSecret, hotpCounter) {
		fmt.Printf("HOTP code %s is valid. Incrementing counter from %d to %d.\n", userHotpCode, hotpCounter, hotpCounter+1)
		// In a real app, you would save this new counter value back to the database.
		// For example, updateCounterInDatabase(hotpCounter + 1)
	} else {
		fmt.Printf("HOTP code %s is invalid. Counter remains unchanged at %d.\n", userHotpCode, hotpCounter)
	}
}
