package session

import (
    "context"
    "errors"
    "time"

    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
)

var ErrTokenNotFound = errors.New("token not found or expired")

type SessionManager struct {
    rdb      *redis.Client
    ctx      context.Context
    tokenTTL time.Duration
}

// NewSessionManager creates a new SessionManager with Redis connection and token TTL
func NewSessionManager(redisAddr string, tokenTTL time.Duration) *SessionManager {
    rdb := redis.NewClient(&redis.Options{
        Addr: redisAddr,
    })
    return &SessionManager{
        rdb:      rdb,
        ctx:      context.Background(),
        tokenTTL: tokenTTL,
    }
}

// CreateToken generates and stores a session token for a username with issued timestamp
func (sm *SessionManager) CreateToken(username string) (string, error) {
    token := uuid.NewString()
    key := "session:" + token

    data := map[string]interface{}{
        "username":  username,
        "issued_at": time.Now().Unix(),
    }
    if err := sm.rdb.HSet(sm.ctx, key, data).Err(); err != nil {
        return "", err
    }
    if err := sm.rdb.Expire(sm.ctx, key, sm.tokenTTL).Err(); err != nil {
        return "", err
    }
    return token, nil
}

// CreateTokenWithMetadata stores token with username plus arbitrary metadata in Redis hash
func (sm *SessionManager) CreateTokenWithMetadata(username string, metadata map[string]interface{}) (string, error) {
    token := uuid.NewString()
    key := "session:" + token

    data := map[string]interface{}{
        "username": username,
    }
    for k, v := range metadata {
        data[k] = v
    }

    if err := sm.rdb.HSet(sm.ctx, key, data).Err(); err != nil {
        return "", err
    }
    if err := sm.rdb.Expire(sm.ctx, key, sm.tokenTTL).Err(); err != nil {
        return "", err
    }
    return token, nil
}

// ValidateToken checks if token exists and returns associated username
func (sm *SessionManager) ValidateToken(token string) (string, error) {
    key := "session:" + token
    exists, err := sm.rdb.Exists(sm.ctx, key).Result()
    if err != nil {
        return "", err
    }
    if exists == 0 {
        return "", ErrTokenNotFound
    }
    username, err := sm.rdb.HGet(sm.ctx, key, "username").Result()
    if err != nil {
        return "", err
    }
    return username, nil
}

// GetRole returns the 'role' field stored in session token hash
func (sm *SessionManager) GetRole(token string) (string, error) {
    key := "session:" + token
    role, err := sm.rdb.HGet(sm.ctx, key, "role").Result()
    if err != nil {
        return "", err
    }
    return role, nil
}

// GetTokenMetadata returns all fields stored in the session hash (username, role, issued_at, etc.)
func (sm *SessionManager) GetTokenMetadata(token string) (map[string]string, error) {
    key := "session:" + token
    result, err := sm.rdb.HGetAll(sm.ctx, key).Result()
    if err != nil {
        return nil, err
    }
    if len(result) == 0 {
        return nil, ErrTokenNotFound
    }
    return result, nil
}

// RevokeToken deletes the session token from Redis (logs out the session)
func (sm *SessionManager) RevokeToken(token string) error {
    key := "session:" + token
    return sm.rdb.Del(sm.ctx, key).Err()
}

// TokenTTL returns the configured token TTL duration
func (sm *SessionManager) TokenTTL() time.Duration {
    return sm.tokenTTL
}
