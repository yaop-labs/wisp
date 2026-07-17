package signal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func testEnvelope(t *testing.T) Envelope {
	t.Helper()
	e, err := New(
		Metrics,
		"wisp.metric-batch.gob/v1",
		"application/x-gob",
		[]byte("payload"),
		map[string]string{"service.name": "checkout", "host.id": "node-1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnvelopeRoundTripAndOwnership(t *testing.T) {
	payload := []byte("payload")
	resource := map[string]string{"service.name": "checkout"}
	e, err := New(Metrics, "otlp.metrics/v1", "application/x-protobuf", payload, resource)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	resource["service.name"] = "mutated"

	record, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !IsRecord(record) {
		t.Fatal("record magic not detected")
	}
	got, err := UnmarshalBinary(record, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != e.ID || got.Kind != Metrics || got.Schema != e.Schema || got.Encoding != e.Encoding {
		t.Fatalf("round trip metadata mismatch: got=%+v want=%+v", got, e)
	}
	if string(got.Payload) != "payload" || got.Resource["service.name"] != "checkout" {
		t.Fatalf("caller mutation leaked into envelope: %+v", got)
	}
	got.Payload[0] = 'Y'
	if bytes.Equal(got.Payload, e.Payload) {
		t.Fatal("decoded payload aliases original")
	}
}

func TestEnvelopeDetectsCorruptionAndTrailingData(t *testing.T) {
	record, err := testEnvelope(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(record)
	corrupt[len(corrupt)/2] ^= 0xff
	if _, err := UnmarshalBinary(corrupt, 1024); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corruption error=%v", err)
	}
	trailing := append(bytes.Clone(record), 0)
	if _, err := UnmarshalBinary(trailing, 1024); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("trailing data error=%v", err)
	}
	for length := 0; length < len(record); length++ {
		if _, err := UnmarshalBinary(record[:length], 1024); err == nil {
			t.Fatalf("truncated record of length %d accepted", length)
		}
	}
}

func TestEnvelopeEnforcesPayloadLimit(t *testing.T) {
	record, err := testEnvelope(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalBinary(record, 3); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit error=%v", err)
	}
}

func TestEnvelopeKindIsOpenButValidated(t *testing.T) {
	e := testEnvelope(t)
	e.Kind = Kind("vendor.profile-delta")
	if err := e.Validate(); err != nil {
		t.Fatalf("open signal kind rejected: %v", err)
	}
	for _, kind := range []Kind{"", "Profiles", "../logs", "logs/profile", "0invalid"} {
		e.Kind = kind
		if err := e.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("kind %q error=%v", kind, err)
		}
	}
}

func TestEnvelopeRejectsInvalidIdentityAndResource(t *testing.T) {
	e := testEnvelope(t)
	e.ID = "not-an-id"
	if err := e.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("id error=%v", err)
	}
	e = testEnvelope(t)
	e.Resource["bad\nkey"] = "value"
	if err := e.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resource error=%v", err)
	}
}

func TestEnvelopeRejectsUnsupportedVersionWithValidChecksum(t *testing.T) {
	record, err := testEnvelope(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	from, to := []byte(`"version":1`), []byte(`"version":2`)
	index := bytes.Index(record, from)
	if index < 0 {
		t.Fatal("version field not found")
	}
	copy(record[index:], to)
	sum := sha256.Sum256(record[:len(record)-checksumBytes])
	copy(record[len(record)-checksumBytes:], sum[:])
	if _, err := UnmarshalBinary(record, 1024); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version error=%v", err)
	}
}

func FuzzUnmarshalBinary(f *testing.F) {
	envelope, err := New(Metrics, "otlp.metrics/v1", "application/x-protobuf", []byte("seed"), nil)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := envelope.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("not-an-envelope"))
	f.Fuzz(func(t *testing.T, data []byte) {
		envelope, err := UnmarshalBinary(data, 1<<20)
		if err != nil {
			return
		}
		record, err := envelope.MarshalBinary()
		if err != nil {
			t.Fatalf("valid decoded envelope cannot marshal: %v", err)
		}
		if _, err := UnmarshalBinary(record, 1<<20); err != nil {
			t.Fatalf("remarshal does not decode: %v", err)
		}
	})
}
