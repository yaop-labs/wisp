// Package signal defines the signal-neutral durability envelope used between
// sources, the spool, and exporters. Payloads stay opaque here; signal-specific
// adapters own protobuf/model conversion.
package signal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Kind string

const (
	Metrics  Kind = "metrics"
	Logs     Kind = "logs"
	Traces   Kind = "traces"
	Profiles Kind = "profiles"
)

const (
	Version               uint16 = 1
	DefaultMaxPayload            = 256 << 20
	maxHeaderBytes               = 1 << 20
	maxResourceAttrs             = 128
	maxKindBytes                 = 64
	maxSchemaBytes               = 256
	maxEncodingBytes             = 128
	maxResourceKeyBytes          = 256
	maxResourceValueBytes        = 4096
	prefixBytes                  = len(recordMagic) + 4 + 8
	checksumBytes                = sha256.Size
)

var (
	recordMagic           = [8]byte{'W', 'I', 'S', 'P', 'E', 'N', 'V', '1'}
	ErrCorrupt            = errors.New("signal envelope: corrupt record")
	ErrInvalid            = errors.New("signal envelope: invalid")
	ErrTooLarge           = errors.New("signal envelope: payload too large")
	ErrUnsupportedVersion = errors.New("signal envelope: unsupported version")
)

// Envelope is the durable unit for any telemetry signal. Resource contains
// correlation/symbolization identity available at admission time; the complete
// OTLP resource remains in Payload.
type Envelope struct {
	Version            uint16            `json:"version"`
	ID                 string            `json:"id"`
	Kind               Kind              `json:"kind"`
	Schema             string            `json:"schema"`
	Encoding           string            `json:"encoding"`
	CapturedAtUnixNano int64             `json:"captured_at_unix_nano"`
	Resource           map[string]string `json:"resource,omitempty"`
	Payload            []byte            `json:"-"`
}

type header struct {
	Version            uint16            `json:"version"`
	ID                 string            `json:"id"`
	Kind               Kind              `json:"kind"`
	Schema             string            `json:"schema"`
	Encoding           string            `json:"encoding"`
	CapturedAtUnixNano int64             `json:"captured_at_unix_nano"`
	Resource           map[string]string `json:"resource,omitempty"`
}

// New constructs an envelope with a random 128-bit batch ID and clones caller
// owned payload/resource data.
func New(kind Kind, schema, encoding string, payload []byte, resource map[string]string) (Envelope, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Envelope{}, fmt.Errorf("signal envelope: generate id: %w", err)
	}
	e := Envelope{
		Version:            Version,
		ID:                 hex.EncodeToString(id[:]),
		Kind:               kind,
		Schema:             schema,
		Encoding:           encoding,
		CapturedAtUnixNano: time.Now().UnixNano(),
		Resource:           cloneResource(resource),
		Payload:            bytes.Clone(payload),
	}
	if err := e.Validate(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

func (e Envelope) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, e.Version)
	}
	id, err := hex.DecodeString(e.ID)
	if err != nil || len(id) != 16 {
		return fmt.Errorf("%w: id must be 32 lowercase hex characters", ErrInvalid)
	}
	if e.ID != strings.ToLower(e.ID) {
		return fmt.Errorf("%w: id must be lowercase", ErrInvalid)
	}
	if !validKind(e.Kind) {
		return fmt.Errorf("%w: invalid signal kind %q", ErrInvalid, e.Kind)
	}
	if !validText(e.Schema, maxSchemaBytes) {
		return fmt.Errorf("%w: invalid schema", ErrInvalid)
	}
	if !validText(e.Encoding, maxEncodingBytes) {
		return fmt.Errorf("%w: invalid encoding", ErrInvalid)
	}
	if e.CapturedAtUnixNano <= 0 {
		return fmt.Errorf("%w: captured timestamp must be positive", ErrInvalid)
	}
	if len(e.Payload) == 0 {
		return fmt.Errorf("%w: empty payload", ErrInvalid)
	}
	if len(e.Resource) > maxResourceAttrs {
		return fmt.Errorf("%w: too many resource attributes", ErrInvalid)
	}
	for key, value := range e.Resource {
		if !validText(key, maxResourceKeyBytes) || len(value) > maxResourceValueBytes || !validUTF8Text(value) {
			return fmt.Errorf("%w: invalid resource attribute %q", ErrInvalid, key)
		}
	}
	return nil
}

func validKind(kind Kind) bool {
	s := string(kind)
	if len(s) == 0 || len(s) > maxKindBytes {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func validText(value string, max int) bool {
	return value != "" && len(value) <= max && validUTF8Text(value)
}

func validUTF8Text(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func cloneResource(resource map[string]string) map[string]string {
	if len(resource) == 0 {
		return nil
	}
	out := make(map[string]string, len(resource))
	for key, value := range resource {
		out[key] = value
	}
	return out
}

func (e Envelope) recordHeader() header {
	return header{
		Version:            e.Version,
		ID:                 e.ID,
		Kind:               e.Kind,
		Schema:             e.Schema,
		Encoding:           e.Encoding,
		CapturedAtUnixNano: e.CapturedAtUnixNano,
		Resource:           e.Resource,
	}
}

// MarshalBinary encodes an envelope as:
// magic | header_len(u32) | payload_len(u64) | JSON header | payload | SHA-256.
// The checksum covers every preceding byte, including lengths and magic.
func (e Envelope) MarshalBinary() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if len(e.Payload) > DefaultMaxPayload {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooLarge, len(e.Payload), DefaultMaxPayload)
	}
	headerBytes, err := json.Marshal(e.recordHeader())
	if err != nil {
		return nil, fmt.Errorf("signal envelope: encode header: %w", err)
	}
	if len(headerBytes) > maxHeaderBytes {
		return nil, fmt.Errorf("%w: header", ErrTooLarge)
	}

	size := prefixBytes + len(headerBytes) + len(e.Payload) + checksumBytes
	record := make([]byte, size)
	copy(record, recordMagic[:])
	binary.BigEndian.PutUint32(record[len(recordMagic):], uint32(len(headerBytes)))
	binary.BigEndian.PutUint64(record[len(recordMagic)+4:], uint64(len(e.Payload)))
	offset := prefixBytes
	copy(record[offset:], headerBytes)
	offset += len(headerBytes)
	copy(record[offset:], e.Payload)
	sum := sha256.Sum256(record[:size-checksumBytes])
	copy(record[size-checksumBytes:], sum[:])
	return record, nil
}

// UnmarshalBinary verifies bounds and checksum before decoding metadata.
// maxPayload <= 0 applies DefaultMaxPayload.
func UnmarshalBinary(record []byte, maxPayload int) (Envelope, error) {
	if len(record) < prefixBytes+checksumBytes {
		return Envelope{}, fmt.Errorf("%w: record too short", ErrCorrupt)
	}
	if !bytes.Equal(record[:len(recordMagic)], recordMagic[:]) {
		return Envelope{}, fmt.Errorf("%w: bad magic", ErrCorrupt)
	}
	headerLen := uint64(binary.BigEndian.Uint32(record[len(recordMagic):]))
	payloadLen := binary.BigEndian.Uint64(record[len(recordMagic)+4:])
	if headerLen == 0 || headerLen > maxHeaderBytes {
		return Envelope{}, fmt.Errorf("%w: invalid header length", ErrCorrupt)
	}
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayload
	}
	if payloadLen == 0 {
		return Envelope{}, fmt.Errorf("%w: empty payload", ErrCorrupt)
	}
	if payloadLen > uint64(maxPayload) {
		return Envelope{}, fmt.Errorf("%w: %d > %d", ErrTooLarge, payloadLen, maxPayload)
	}
	expected := uint64(prefixBytes+checksumBytes) + headerLen + payloadLen
	if expected != uint64(len(record)) {
		return Envelope{}, fmt.Errorf("%w: length mismatch", ErrCorrupt)
	}
	bodyEnd := len(record) - checksumBytes
	sum := sha256.Sum256(record[:bodyEnd])
	if subtle.ConstantTimeCompare(sum[:], record[bodyEnd:]) != 1 {
		return Envelope{}, fmt.Errorf("%w: checksum mismatch", ErrCorrupt)
	}

	headerEnd := prefixBytes + int(headerLen)
	decoder := json.NewDecoder(bytes.NewReader(record[prefixBytes:headerEnd]))
	decoder.DisallowUnknownFields()
	var h header
	if err := decoder.Decode(&h); err != nil {
		return Envelope{}, fmt.Errorf("%w: header: %v", ErrCorrupt, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Envelope{}, fmt.Errorf("%w: header: %v", ErrCorrupt, err)
	}
	e := Envelope{
		Version:            h.Version,
		ID:                 h.ID,
		Kind:               h.Kind,
		Schema:             h.Schema,
		Encoding:           h.Encoding,
		CapturedAtUnixNano: h.CapturedAtUnixNano,
		Resource:           cloneResource(h.Resource),
		Payload:            bytes.Clone(record[headerEnd:bodyEnd]),
	}
	if err := e.Validate(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// IsRecord reports whether data starts with the v1 envelope magic. It does not
// validate lengths or checksum.
func IsRecord(data []byte) bool {
	return len(data) >= len(recordMagic) && bytes.Equal(data[:len(recordMagic)], recordMagic[:])
}
