// Package encoder provides interfaces and implementations for encoding,
// decoding, and transforming C2 traffic.  It is designed to be compatible
// with the Sliver C2 1.7.3 transport layer.
package encoders

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrUnknownType is returned when an unsupported encoder type is requested.
	ErrUnknownType = errors.New("encoder: unknown encoder type")
	// ErrDecodeFailed is returned when decoding fails.
	ErrDecodeFailed = errors.New("encoder: decode failed")
	// ErrEncodeFailed is returned when encoding fails.
	ErrEncodeFailed = errors.New("encoder: encode failed")
	// ErrInvalidData is returned when the input data is malformed.
	ErrInvalidData = errors.New("encoder: invalid data")
)

// ---------------------------------------------------------------------------
// Type
// ---------------------------------------------------------------------------

// Type enumerates the supported encoder types.
type Type int

const (
	TypeBase64 Type = iota
	TypeHex
	TypeXOR
	TypeMimic
)

// String returns a human-readable name for the encoder type.
func (t Type) String() string {
	switch t {
	case TypeBase64:
		return "base64"
	case TypeHex:
		return "hex"
	case TypeXOR:
		return "xor"
	case TypeMimic:
		return "mimic"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// ParseType parses a string into an encoder Type.
func ParseType(s string) (Type, error) {
	switch s {
	case "base64":
		return TypeBase64, nil
	case "hex":
		return TypeHex, nil
	case "xor":
		return TypeXOR, nil
	case "mimic":
		return TypeMimic, nil
	default:
		return TypeBase64, fmt.Errorf("%w: %q", ErrUnknownType, s)
	}
}

// ---------------------------------------------------------------------------
// Encoding interface
// ---------------------------------------------------------------------------

// Encoding is the core interface that every encoder must implement.
// It mirrors the interface used by Sliver's internal transport encoders.
type Encoding interface {
	// Encode transforms plaintext data into the encoded format.
	Encode(data []byte) ([]byte, error)

	// Decode transforms encoded data back to plaintext.
	Decode(data []byte) ([]byte, error)

	// Type returns the encoder type identifier.
	Type() Type

	// Name returns a human-readable name.
	Name() string
}

// ---------------------------------------------------------------------------
// Base64Encoding
// ---------------------------------------------------------------------------

// Base64Encoding implements standard base64 encoding (RFC 4648).
type Base64Encoding struct{}

// NewBase64Encoding creates a new Base64Encoding.
func NewBase64Encoding() *Base64Encoding {
	return &Base64Encoding{}
}

func (b *Base64Encoding) Encode(data []byte) ([]byte, error) {
	enc := base64.StdEncoding.EncodeToString(data)
	return []byte(enc), nil
}

func (b *Base64Encoding) Decode(data []byte) ([]byte, error) {
	dec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrDecodeFailed, err)
	}
	return dec, nil
}

func (b *Base64Encoding) Type() Type { return TypeBase64 }

func (b *Base64Encoding) Name() string { return "base64" }

// ---------------------------------------------------------------------------
// HexEncoding
// ---------------------------------------------------------------------------

// HexEncoding implements hexadecimal encoding (lowercase).
type HexEncoding struct{}

// NewHexEncoding creates a new HexEncoding.
func NewHexEncoding() *HexEncoding {
	return &HexEncoding{}
}

func (h *HexEncoding) Encode(data []byte) ([]byte, error) {
	enc := hex.EncodeToString(data)
	return []byte(enc), nil
}

func (h *HexEncoding) Decode(data []byte) ([]byte, error) {
	dec, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("%w: hex: %w", ErrDecodeFailed, err)
	}
	return dec, nil
}

func (h *HexEncoding) Type() Type { return TypeHex }

func (h *HexEncoding) Name() string { return "hex" }

// ---------------------------------------------------------------------------
// XOREncoding — wraps XORCipher as an Encoding
// ---------------------------------------------------------------------------

// XOREncoding implements reversible XOR encryption/decryption as an Encoding.
type XOREncoding struct {
	cipher *XORCipher
}

// NewXOREncoding creates a new XOREncoding with the given cipher.
// If cipher is nil, a default key is generated internally.
func NewXOREncoding(cipher *XORCipher) (*XOREncoding, error) {
	if cipher == nil {
		key, err := RandBytes(DefaultKeySize)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		var cErr error
		cipher, cErr = NewXORCipher(key)
		if cErr != nil {
			return nil, cErr
		}
	}
	return &XOREncoding{cipher: cipher}, nil
}

func (x *XOREncoding) Encode(data []byte) ([]byte, error) {
	return x.cipher.Encrypt(data), nil
}

func (x *XOREncoding) Decode(data []byte) ([]byte, error) {
	return x.cipher.Decrypt(data), nil
}

func (x *XOREncoding) Type() Type { return TypeXOR }

func (x *XOREncoding) Name() string { return "xor" }

// Cipher returns the underlying XORCipher (useful for key inspection).
func (x *XOREncoding) Cipher() *XORCipher { return x.cipher }

// ---------------------------------------------------------------------------
// CompositeEncoding — chains multiple encoders
// ---------------------------------------------------------------------------

// CompositeEncoding applies a sequence of encoders in order.
// For example, NewCompositeEncoding(xor, base64) will first XOR then base64
// on Encode, and reverse on Decode.
type CompositeEncoding struct {
	encoders []Encoding
}

// NewCompositeEncoding creates a CompositeEncoding from the given encoder chain.
func NewCompositeEncoding(encoders ...Encoding) *CompositeEncoding {
	return &CompositeEncoding{encoders: encoders}
}

func (c *CompositeEncoding) Encode(data []byte) ([]byte, error) {
	var err error
	out := data
	for _, enc := range c.encoders {
		out, err = enc.Encode(out)
		if err != nil {
			return nil, fmt.Errorf("composite encode at %s: %w", enc.Name(), err)
		}
	}
	return out, nil
}

func (c *CompositeEncoding) Decode(data []byte) ([]byte, error) {
	var err error
	out := data
	// Apply in reverse order
	for i := len(c.encoders) - 1; i >= 0; i-- {
		out, err = c.encoders[i].Decode(out)
		if err != nil {
			return nil, fmt.Errorf("composite decode at %s: %w", c.encoders[i].Name(), err)
		}
	}
	return out, nil
}

func (c *CompositeEncoding) Type() Type { return TypeBase64 } // composite

func (c *CompositeEncoding) Name() string {
	return "composite"
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

// New creates an encoder by Type.  For TypeXOR a random key is generated.
// For TypeMimic, a default config is used; use NewMimicEncoding for full control.
func New(t Type) (Encoding, error) {
	switch t {
	case TypeBase64:
		return NewBase64Encoding(), nil
	case TypeHex:
		return NewHexEncoding(), nil
	case TypeXOR:
		return NewXOREncoding(nil)
	case TypeMimic:
		return NewMimicEncoding(DefaultMimicConfig())
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownType, t)
	}
}

// NewFromName creates an encoder by its string name.
func NewFromName(name string) (Encoding, error) {
	t, err := ParseType(name)
	if err != nil {
		return nil, err
	}
	return New(t)
}
