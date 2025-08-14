package main

import (
	"fmt"
	"log"
	"os"

	"allsafe-access/pkg/mfa" // Replace with your actual project path
)

func main() {
	fmt.Println("--- Generating TOTP QR Code ---")
	// 1. Generate a new TOTP key. The secret will be stored in this key object.
	// In a real app, you would save key.Secret() to the database.
	totpKey, err := mfa.GenerateTOTPKey("Allsafe-Access", "john.doe")
	if err != nil {
		log.Fatalf("Error generating TOTP key: %v", err)
	}

	// 2. Generate a QR code image as a byte slice from the key.
	qrCodeBytes, err := mfa.GenerateQRCode(totpKey)
	if err != nil {
		log.Fatalf("Error generating QR code: %v", err)
	}

	// For a real application, you would serve this byte slice directly in an HTTP response.
	// You should NEVER save this to a persistent file in production.
	file, err := os.Create("totp-qrcode.png")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()
	file.Write(qrCodeBytes)

	fmt.Printf("TOTP QR Code saved to totp-qrcode.png. Scan this with your authenticator app.\n")
	fmt.Printf("Secret: %s\n", totpKey.Secret())
	fmt.Printf("URL: %s\n", totpKey.URL())

	fmt.Println("\n--- Generating HOTP Secret ---")
	// 3. Generate a new HOTP key.
	// In a real application, you would save hotpKey.Secret() and the initial counter (0)
	// to your database for the user.
	hotpKey, err := mfa.GenerateHOTPKey("Allsafe-Access", "jane.doe")
	if err != nil {
		log.Fatalf("Error generating HOTP key: %v", err)
	}
	fmt.Printf("HOTP Secret: %s\n", hotpKey.Secret())
	fmt.Printf("Initial Counter: %d\n", 0)
}
