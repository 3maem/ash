package ash

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// ContextStore is the interface for context storage backends.
type ContextStore interface {
	// Create creates a new context.
	Create(binding string, ttlMs int64, mode Mode, metadata map[string]interface{}) (*Context, error)

	// Get retrieves a context by ID.
	Get(id string) (*Context, error)

	// Consume marks a context as used.
	Consume(id string) error

	// Cleanup removes expired contexts.
	Cleanup() (int, error)
}

// MemoryStore is an in-memory implementation of ContextStore.
type MemoryStore struct {
	mu       sync.RWMutex
	contexts map[string]*Context
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		contexts: make(map[string]*Context),
	}
}

// Create creates a new context.
func (s *MemoryStore) Create(binding string, ttlMs int64, mode Mode, metadata map[string]interface{}) (*Context, error) {
	id, err := generateContextID()
	if err != nil {
		return nil, err
	}

	var nonce string
	if mode == ModeStrict {
		nonce, err = generateNonce()
		if err != nil {
			return nil, err
		}
	}

	ctx := &Context{
		ID:        id,
		Binding:   binding,
		ExpiresAt: time.Now().UnixMilli() + ttlMs,
		Mode:      mode,
		Used:      false,
		Nonce:     nonce,
		Metadata:  metadata,
	}

	s.mu.Lock()
	s.contexts[id] = ctx
	s.mu.Unlock()

	return ctx, nil
}

// Get retrieves a context by ID.
func (s *MemoryStore) Get(id string) (*Context, error) {
	s.mu.RLock()
	ctx, ok := s.contexts[id]
	s.mu.RUnlock()

	if !ok {
		return nil, nil
	}

	if ctx.IsExpired() {
		s.mu.Lock()
		delete(s.contexts, id)
		s.mu.Unlock()
		return nil, nil
	}

	return ctx, nil
}

// Consume marks a context as used.
func (s *MemoryStore) Consume(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, ok := s.contexts[id]
	if !ok {
		return errors.New("context not found")
	}

	if ctx.Used {
		return errors.New("context already used")
	}

	ctx.Used = true
	return nil
}

// Cleanup removes expired contexts.
func (s *MemoryStore) Cleanup() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	removed := 0

	for id, ctx := range s.contexts {
		if now > ctx.ExpiresAt {
			delete(s.contexts, id)
			removed++
		}
	}

	return removed, nil
}

// Size returns the number of active contexts.
func (s *MemoryStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.contexts)
}

// Clear removes all contexts.
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts = make(map[string]*Context)
}

// RedisStore is a Redis implementation of ContextStore.
type RedisStore struct {
	client    RedisClient
	keyPrefix string
}

// RedisClient is the interface for Redis operations.
type RedisClient interface {
	Get(key string) (string, error)
	SetEx(key string, ttlSeconds int, value string) error
	Del(keys ...string) error
}

// NewRedisStore creates a new Redis store.
func NewRedisStore(client RedisClient, keyPrefix string) *RedisStore {
	if keyPrefix == "" {
		keyPrefix = "ash:ctx:"
	}
	return &RedisStore{
		client:    client,
		keyPrefix: keyPrefix,
	}
}

func (s *RedisStore) key(id string) string {
	return s.keyPrefix + id
}

// Create creates a new context.
func (s *RedisStore) Create(binding string, ttlMs int64, mode Mode, metadata map[string]interface{}) (*Context, error) {
	id, err := generateContextID()
	if err != nil {
		return nil, err
	}

	var nonce string
	if mode == ModeStrict {
		nonce, err = generateNonce()
		if err != nil {
			return nil, err
		}
	}

	ctx := &Context{
		ID:        id,
		Binding:   binding,
		ExpiresAt: time.Now().UnixMilli() + ttlMs,
		Mode:      mode,
		Used:      false,
		Nonce:     nonce,
		Metadata:  metadata,
	}

	data, err := json.Marshal(ctx)
	if err != nil {
		return nil, err
	}

	ttlSeconds := int(ttlMs/1000) + 1
	if err := s.client.SetEx(s.key(id), ttlSeconds, string(data)); err != nil {
		return nil, err
	}

	return ctx, nil
}

// Get retrieves a context by ID.
func (s *RedisStore) Get(id string) (*Context, error) {
	data, err := s.client.Get(s.key(id))
	if err != nil {
		return nil, nil // Not found
	}

	var ctx Context
	if err := json.Unmarshal([]byte(data), &ctx); err != nil {
		return nil, err
	}

	if ctx.IsExpired() {
		s.client.Del(s.key(id))
		return nil, nil
	}

	return &ctx, nil
}

// Consume marks a context as used.
func (s *RedisStore) Consume(id string) error {
	ctx, err := s.Get(id)
	if err != nil || ctx == nil {
		return errors.New("context not found")
	}

	if ctx.Used {
		return errors.New("context already used")
	}

	ctx.Used = true

	data, err := json.Marshal(ctx)
	if err != nil {
		return err
	}

	remainingMs := ctx.ExpiresAt - time.Now().UnixMilli()
	remainingSeconds := int(remainingMs/1000) + 1
	if remainingSeconds < 1 {
		remainingSeconds = 1
	}

	return s.client.SetEx(s.key(id), remainingSeconds, string(data))
}

// Cleanup is handled by Redis TTL.
func (s *RedisStore) Cleanup() (int, error) {
	return 0, nil
}

// Helper functions

func generateContextID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "ctx_" + hex.EncodeToString(bytes), nil
}

func generateNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
