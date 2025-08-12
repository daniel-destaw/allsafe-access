package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "strings"
    
    "allsafe-access/pkg/mfa"
)

func main() {
    fmt.Println("--- Allsafe MFA Package Interactive Usage Demo ---")

    // Step 1: Generate a new TOTP secret.
    fmt.Println("\n1. Generating a new TOTP secret...")
    secret, err := mfa.GenerateTOTPSecret()
    if err != nil {
        log.Fatalf("Failed to generate secret: %v", err)
    }
    fmt.Printf("Generated Secret: %s\n", secret)

    // Step 2: Generate the QR code URL.
    // This URL can be converted into a QR code for the user to scan.
    fmt.Println("\n2. Generating a QR code URL...")
    issuer := "Allsafe Access"
    user := "demo-user@allsafe.com"
    qrCodeURL, err := mfa.GenerateTOTPQRCodeURL(issuer, user, secret)
    if err != nil {
        log.Fatalf("Failed to generate QR code URL: %v", err)
    }
    fmt.Printf("QR Code URL: %s\n", qrCodeURL)
    fmt.Println("\nScan this URL with your authenticator app to add the account. ")
    
    // Step 3: Prompt the user to enter the TOTP code for validation.
    fmt.Println("\n3. Please enter the 6-digit TOTP code from your authenticator app now:")
    
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("> ")
    inputCode, _ := reader.ReadString('\n')
    inputCode = strings.TrimSpace(inputCode)

    // Validate the code entered by the user.
    fmt.Printf("Validating code '%s'...\n", inputCode)
    if mfa.ValidateTOTP(inputCode, secret) {
        fmt.Println("✅ The code is valid! Your MFA setup is working correctly.")
    } else {
        fmt.Println("❌ The code is invalid. Please check the time on your devices or try again with a new code.")
    }
}
