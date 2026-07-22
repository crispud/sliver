// Package encoder provides encoding, encryption, and traffic-mimicking utilities
// for C2 transport layer integration with Sliver C2 1.7.3.
package encoders

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	ErrInvalidKey       = errors.New("encoder: invalid key (must be non-empty)")
	ErrInvalidKeySize   = errors.New("encoder: invalid key size")
	ErrKeyNotFound      = errors.New("encoder: session key not found")
	ErrInvalidSalt      = errors.New("encoder: invalid salt")
	ErrKeyRotationFails = errors.New("encoder: key rotation failed")
)

const (
	// DefaultKeySize is the recommended key length for XOR operations.
	DefaultKeySize = 32
	// MinKeySize is the minimum allowed key length.
	MinKeySize = 16
)

// ---------------------------------------------------------------------------
// XORCipher — symmetric XOR stream (used for both encrypt & decrypt)
// ---------------------------------------------------------------------------

// XORCipher implements reversible XOR encryption/decryption.
// Because XOR is symmetric, Encrypt and Decrypt are the same operation.
type XORCipher struct {
	key []byte
	mu  sync.RWMutex
}

// NewXORCipher creates a new XORCipher with the given key.
// The key is copied internally; the caller may safely reuse the slice.
func NewXORCipher(key []byte) (*XORCipher, error) {
	if len(key) < MinKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrInvalidKeySize, len(key), MinKeySize)
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &XORCipher{key: k}, nil
}

// Encrypt XOR-encrypts the data. The output is a newly allocated slice.
func (x *XORCipher) Encrypt(data []byte) []byte {
	return x.xor(data)
}

// Decrypt XOR-decrypts the data (identical to Encrypt for XOR).
func (x *XORCipher) Decrypt(data []byte) []byte {
	return x.xor(data)
}

// SetKey atomically replaces the internal key.
func (x *XORCipher) SetKey(key []byte) error {
	if len(key) < MinKeySize {
		return fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrInvalidKeySize, len(key), MinKeySize)
	}
	k := make([]byte, len(key))
	copy(k, key)
	x.mu.Lock()
	x.key = k
	x.mu.Unlock()
	return nil
}

// Key returns a copy of the current key.
func (x *XORCipher) Key() []byte {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make([]byte, len(x.key))
	copy(out, x.key)
	return out
}

func (x *XORCipher) xor(data []byte) []byte {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ x.key[i%len(x.key)]
	}
	return out
}

// ---------------------------------------------------------------------------
// KeyManager — per-session keys with automatic rotation
// ---------------------------------------------------------------------------

// KeyManager manages per-session XOR keys and rotates them at a configurable
// interval. All operations are safe for concurrent use.
type KeyManager struct {
	mu               sync.RWMutex
	sessions         map[string]*sessionKey
	rotationInterval time.Duration
}

type sessionKey struct {
	key    []byte
	born   time.Time
	lastRot time.Time
	count  uint64 // number of encrypt/decrypt ops performed
}

// NewKeyManager creates a KeyManager with the given rotation interval.
// Pass 0 to disable automatic rotation (rotate only on-demand).
func NewKeyManager(rotationInterval time.Duration) *KeyManager {
	return &KeyManager{
		sessions:         make(map[string]*sessionKey),
		rotationInterval: rotationInterval,
	}
}

// GetOrCreateKey returns the current key for a session.  If the session does
// not exist, a new random key is generated and stored.
func (km *KeyManager) GetOrCreateKey(sessionID string) []byte {
	km.mu.Lock()
	defer km.mu.Unlock()

	if sk, ok := km.sessions[sessionID]; ok {
		km.maybeRotateLocked(sessionID, sk)
		sk.count++
		out := make([]byte, len(sk.key))
		copy(out, sk.key)
		return out
	}

	// Create new key
	key := make([]byte, DefaultKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Fallback: derive from session ID (still better than nil)
		h := sha256.Sum256([]byte(sessionID))
		key = h[:]
	}
	now := time.Now()
	km.sessions[sessionID] = &sessionKey{
		key:     key,
		born:    now,
		lastRot: now,
	}
	out := make([]byte, len(key))
	copy(out, key)
	return out
}

// GetKey retrieves the key for a session without creating one.
// Returns ErrKeyNotFound if the session does not exist.
func (km *KeyManager) GetKey(sessionID string) ([]byte, error) {
	km.mu.RLock()
	sk, ok := km.sessions[sessionID]
	km.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: session %q", ErrKeyNotFound, sessionID)
	}
	km.mu.Lock()
	km.maybeRotateLocked(sessionID, sk)
	sk.count++
	km.mu.Unlock()
	out := make([]byte, len(sk.key))
	copy(out, sk.key)
	return out, nil
}

// RotateKey forces immediate key rotation for the given session.
// The new key is generated using crypto/rand.
func (km *KeyManager) RotateKey(sessionID string) error {
	newKey := make([]byte, DefaultKeySize)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return fmt.Errorf("%w: %w", ErrKeyRotationFails, err)
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	if sk, ok := km.sessions[sessionID]; ok {
		sk.key = newKey
		sk.lastRot = time.Now()
		sk.count = 0
		return nil
	}
	// Create entry if missing
	now := time.Now()
	km.sessions[sessionID] = &sessionKey{
		key:     newKey,
		born:    now,
		lastRot: now,
	}
	return nil
}

// DeleteKey removes a session and its key.
func (km *KeyManager) DeleteKey(sessionID string) {
	km.mu.Lock()
	delete(km.sessions, sessionID)
	km.mu.Unlock()
}

// SessionCount returns the number of active sessions.
func (km *KeyManager) SessionCount() int {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return len(km.sessions)
}

// maybeRotateLocked checks whether the key should be rotated and does so if
// the rotation interval has elapsed.  Must be called with km.mu write-locked.
func (km *KeyManager) maybeRotateLocked(sessionID string, sk *sessionKey) {
	if km.rotationInterval <= 0 {
		return
	}
	if time.Since(sk.lastRot) >= km.rotationInterval {
		newKey := make([]byte, DefaultKeySize)
		if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
			return // best-effort: keep current key
		}
		sk.key = newKey
		sk.lastRot = time.Now()
		sk.count = 0
	}
}

// ---------------------------------------------------------------------------
// Key derivation helpers
// ---------------------------------------------------------------------------

// DeriveKey derives a 32-byte key from the given password and salt using
// HMAC-SHA256 with a single iteration (suitable for in-memory use).
func DeriveKey(password, salt []byte) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	return mac.Sum(nil)
}

// DeriveKeyFromPassphrase derives a key from a passphrase string and an
// optional hex-encoded salt.  If saltHex is empty, a random salt is generated
// and the caller must store it for future decryption.
func DeriveKeyFromPassphrase(passphrase string, saltHex string) (key []byte, salt []byte, err error) {
	if passphrase == "" {
		return nil, nil, ErrInvalidKey
	}
	if saltHex != "" {
		salt, err = hex.DecodeString(saltHex)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidSalt, err)
		}
	} else {
		salt = make([]byte, 16)
		if _, e := io.ReadFull(rand.Reader, salt); e != nil {
			return nil, nil, e
		}
	}
	key = DeriveKey([]byte(passphrase), salt)
	return key, salt, nil
}

// ---------------------------------------------------------------------------
// Secure helpers
// ---------------------------------------------------------------------------

// RandBytes returns a slice of n cryptographically random bytes.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandHex returns a hex-encoded random string with the given byte length.
func RandHex(n int) (string, error) {
	b, err := RandBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// UUID4 generates a version-4 UUID string (no external deps).
func UUID4() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	// Set version 4
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

// FormatTimestamp returns an RFC3339 UTC timestamp string.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// NowTimestamp returns the current UTC time as an RFC3339 string.
func NowTimestamp() string {
	return FormatTimestamp(time.Now())
}

// ---------------------------------------------------------------------------
// Binary helpers
// ---------------------------------------------------------------------------

// PutUint64 encodes a uint64 into big-endian bytes.
func PutUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// Uint64 decodes a big-endian uint64 from bytes.
func Uint64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b[:8])
}
