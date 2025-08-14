package session

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Manager defines the interface for session management operations.
// This allows for different storage backends (e.g., file, memory, Redis).
type Manager interface {
	CreateSession(content *SessionTokenContent) error
	LoadSession() (*SessionTokenContent, error)
	ClearSession() error
	GetSessionFilePath() string // Useful for debugging/info
}

// fileSessionManager implements the Manager interface using a local file for storage.
type fileSessionManager struct {
	sessionFilePath string
}

// NewFileSessionManager creates a new file-based session manager.
// It ensures the directory for the session file exists.
func NewFileSessionManager(sessionDir string) (Manager, error) {
	if sessionDir == "" {
		return nil, fmt.Errorf("session directory cannot be empty")
	}

	if err := os.MkdirAll(sessionDir, 0700); err != nil { // Create session directory if it doesn't exist
		return nil, fmt.Errorf("failed to create session directory %s: %w", sessionDir, err)
	}

	return &fileSessionManager{
		sessionFilePath: filepath.Join(sessionDir, "session.json"),
	}, nil
}

// CreateSession marshals the session content and writes it to the session file.
func (fsm *fileSessionManager) CreateSession(content *SessionTokenContent) error {
	if content == nil {
		return fmt.Errorf("session content cannot be nil")
	}

	data, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Write with restrictive permissions (user-only read/write)
	if err := os.WriteFile(fsm.sessionFilePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file %s: %w", fsm.sessionFilePath, err)
	}
	log.Printf("Session saved to %s", fsm.sessionFilePath)
	return nil
}

// LoadSession reads the session content from the session file and unmarshals it.
func (fsm *fileSessionManager) LoadSession() (*SessionTokenContent, error) {
	data, err := os.ReadFile(fsm.sessionFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file %s: %w", fsm.sessionFilePath, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty session file %s", fsm.sessionFilePath)
	}

	var content SessionTokenContent
	if err := json.Unmarshal(data, &content); err != nil {
		// Log the error but don't fail fatally, might be corrupted session file
		log.Printf("Error unmarshalling session data from %s: %v", fsm.sessionFilePath, err)
		return nil, fmt.Errorf("failed to unmarshal session data from %s: %w", fsm.sessionFilePath, err)
	}

	log.Printf("Session loaded from %s", fsm.sessionFilePath)
	return &content, nil
}

// ClearSession removes the session file.
func (fsm *fileSessionManager) ClearSession() error {
	err := os.Remove(fsm.sessionFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("No active session file to clear.")
			return nil // Already cleared or never existed
		}
		return fmt.Errorf("failed to remove session file %s: %w", fsm.sessionFilePath, err)
	}
	log.Println("Session file cleared.")
	return nil
}

// GetSessionFilePath returns the path to the session file.
func (fsm *fileSessionManager) GetSessionFilePath() string {
	return fsm.sessionFilePath
}