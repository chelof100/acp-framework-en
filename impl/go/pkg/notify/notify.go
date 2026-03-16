// Package notify implements ACP-NOTIFY-1.0 (webhook push notifications).
//
// Provides subscription management, payload building with Ed25519 signatures,
// and payload signature verification for ACP webhook delivery.
package notify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

// ─── Error Sentinels (ACP-NOTIFY-1.0) ────────────────────────────────────────

var (
	ErrEmptyWebhookURL           = errors.New("NOTI-001: webhook_url is required")
	ErrEmptyEvents               = errors.New("NOTI-002: events list must not be empty")
	ErrSubscriptionNotFound      = errors.New("NOTI-003: subscription not found")
	ErrInvalidSig                = errors.New("NOTI-004: payload signature invalid")
	ErrSubscriptionAlreadyExists = errors.New("NOTI-005: subscription_id already exists")
	ErrInvalidVersion            = errors.New("NOTI-010: unsupported version, expected 1.0")
)

// ─── Types ────────────────────────────────────────────────────────────────────

// Subscription represents an active webhook subscription.
type Subscription struct {
	SubscriptionID string   `json:"subscription_id"`
	WebhookURL     string   `json:"webhook_url"`
	Events         []string `json:"events"`
	Secret         string   `json:"secret"`
	InstitutionID  string   `json:"institution_id"`
	Status         string   `json:"status"` // "active" | "paused" | "failed"
	CreatedAt      int64    `json:"created_at"`
	FailureCount   int      `json:"failure_count"`
}

// WebhookPayload is the signed envelope delivered to the webhook URL.
type WebhookPayload struct {
	WebhookID     string                 `json:"webhook_id"`
	EventType     string                 `json:"event_type"`
	EventID       string                 `json:"event_id"`
	Timestamp     int64                  `json:"timestamp"`
	InstitutionID string                 `json:"institution_id"`
	Data          map[string]interface{} `json:"data"`
	Sig           string                 `json:"sig"`
}

// signablePayload is the signing input: all fields with Sig set to "".
type signablePayload struct {
	WebhookID     string                 `json:"webhook_id"`
	EventType     string                 `json:"event_type"`
	EventID       string                 `json:"event_id"`
	Timestamp     int64                  `json:"timestamp"`
	InstitutionID string                 `json:"institution_id"`
	Data          map[string]interface{} `json:"data"`
	Sig           string                 `json:"sig"` // always "" when signing
}

// SubscribeRequest holds the input for creating a new webhook subscription.
type SubscribeRequest struct {
	WebhookURL    string   `json:"webhook_url"`
	Events        []string `json:"events"`
	InstitutionID string   `json:"institution_id"`
}

// ─── Core Functions ───────────────────────────────────────────────────────────

// Subscribe validates the request, generates a SubscriptionID and Secret,
// and returns a new Subscription with Status="active".
func Subscribe(req SubscribeRequest) (Subscription, error) {
	if req.WebhookURL == "" {
		return Subscription{}, ErrEmptyWebhookURL
	}
	if len(req.Events) == 0 {
		return Subscription{}, ErrEmptyEvents
	}

	id, err := newUUID()
	if err != nil {
		return Subscription{}, fmt.Errorf("notify: generate subscription_id: %w", err)
	}

	// Generate a random 32-byte secret encoded as hex.
	var secretBytes [32]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return Subscription{}, fmt.Errorf("notify: generate secret: %w", err)
	}
	secret := hex.EncodeToString(secretBytes[:])

	return Subscription{
		SubscriptionID: id,
		WebhookURL:     req.WebhookURL,
		Events:         req.Events,
		Secret:         secret,
		InstitutionID:  req.InstitutionID,
		Status:         "active",
		CreatedAt:      time.Now().Unix(),
		FailureCount:   0,
	}, nil
}

// BuildPayload constructs a WebhookPayload and signs it using
// Ed25519(SHA-256(JCS(signablePayload with Sig=""))).
func BuildPayload(
	sub Subscription,
	eventType, eventID, institutionID string,
	data map[string]interface{},
	privKey ed25519.PrivateKey,
) (WebhookPayload, error) {
	webhookID, err := newUUID()
	if err != nil {
		return WebhookPayload{}, fmt.Errorf("notify: generate webhook_id: %w", err)
	}

	p := WebhookPayload{
		WebhookID:     webhookID,
		EventType:     eventType,
		EventID:       eventID,
		Timestamp:     time.Now().Unix(),
		InstitutionID: institutionID,
		Data:          data,
	}

	sig, err := signPayload(p, privKey)
	if err != nil {
		return WebhookPayload{}, fmt.Errorf("notify: sign payload: %w", err)
	}
	p.Sig = sig
	return p, nil
}

// VerifyPayloadSig verifies the Ed25519 signature on a WebhookPayload.
func VerifyPayloadSig(p WebhookPayload, pubKey ed25519.PublicKey) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(p.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrInvalidSig, err)
	}

	s := signablePayload{
		WebhookID:     p.WebhookID,
		EventType:     p.EventType,
		EventID:       p.EventID,
		Timestamp:     p.Timestamp,
		InstitutionID: p.InstitutionID,
		Data:          p.Data,
		Sig:           "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("notify: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("notify: jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInvalidSig
	}
	return nil
}

// ─── Signing Helper ───────────────────────────────────────────────────────────

func signPayload(p WebhookPayload, privKey ed25519.PrivateKey) (string, error) {
	s := signablePayload{
		WebhookID:     p.WebhookID,
		EventType:     p.EventType,
		EventID:       p.EventID,
		Timestamp:     p.Timestamp,
		InstitutionID: p.InstitutionID,
		Data:          p.Data,
		Sig:           "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(privKey, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// ─── InMemorySubscriptionStore ────────────────────────────────────────────────

// InMemorySubscriptionStore is a thread-safe in-memory subscription registry.
type InMemorySubscriptionStore struct {
	mu    sync.RWMutex
	store map[string]Subscription // subscription_id → Subscription
}

// NewInMemorySubscriptionStore creates an empty subscription store.
func NewInMemorySubscriptionStore() *InMemorySubscriptionStore {
	return &InMemorySubscriptionStore{
		store: make(map[string]Subscription),
	}
}

// Store persists a subscription. Returns ErrSubscriptionAlreadyExists if the
// subscription_id is already present.
func (s *InMemorySubscriptionStore) Store(sub Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.store[sub.SubscriptionID]; exists {
		return fmt.Errorf("%w: %s", ErrSubscriptionAlreadyExists, sub.SubscriptionID)
	}
	s.store[sub.SubscriptionID] = sub
	return nil
}

// Get retrieves a subscription by ID.
func (s *InMemorySubscriptionStore) Get(id string) (Subscription, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.store[id]
	return sub, ok
}

// GetByInstitution returns all subscriptions for the given institution.
func (s *InMemorySubscriptionStore) GetByInstitution(institutionID string) []Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Subscription
	for _, sub := range s.store {
		if sub.InstitutionID == institutionID {
			result = append(result, sub)
		}
	}
	return result
}

// UpdateStatus updates the status of a subscription.
func (s *InMemorySubscriptionStore) UpdateStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.store[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	sub.Status = status
	s.store[id] = sub
	return nil
}

// IncrementFailure increments the failure counter for a subscription.
func (s *InMemorySubscriptionStore) IncrementFailure(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.store[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	sub.FailureCount++
	s.store[id] = sub
	return nil
}

// RotateSecret generates a new 32-byte hex secret and stores it.
// Returns the new secret string.
func (s *InMemorySubscriptionStore) RotateSecret(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.store[id]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	var secretBytes [32]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return "", fmt.Errorf("notify: rotate secret: %w", err)
	}
	newSecret := hex.EncodeToString(secretBytes[:])
	sub.Secret = newSecret
	s.store[id] = sub
	return newSecret, nil
}

// Delete removes a subscription by ID.
func (s *InMemorySubscriptionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.store[id]; !ok {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	delete(s.store, id)
	return nil
}

// Size returns the number of stored subscriptions.
func (s *InMemorySubscriptionStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.store)
}

// ─── UUID Helper ──────────────────────────────────────────────────────────────

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
