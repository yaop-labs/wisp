package otlpwire

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func logsRequest(records, bodyBytes int) *collogspb.ExportLogsServiceRequest {
	out := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: "checkout"},
				},
			}}},
			SchemaUrl: "resource-schema",
			ScopeLogs: []*logspb.ScopeLogs{{
				SchemaUrl: "scope-schema",
			}},
		}},
	}
	for i := range records {
		out.ResourceLogs[0].ScopeLogs[0].LogRecords = append(
			out.ResourceLogs[0].ScopeLogs[0].LogRecords,
			&logspb.LogRecord{
				TimeUnixNano: uint64(i + 1),
				Body: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{
						StringValue: fmt.Sprintf("%04d:%s", i, strings.Repeat("x", bodyBytes)),
					},
				},
			},
		)
	}
	return out
}

func TestForEachLogsChunkBoundsOrderAndMetadata(t *testing.T) {
	request := logsRequest(12, 256)
	request.ProtoReflect().SetUnknown([]byte{0x78, 0x01})
	request.ResourceLogs[0].ProtoReflect().SetUnknown([]byte{0x78, 0x02})
	request.ResourceLogs[0].ScopeLogs[0].ProtoReflect().SetUnknown([]byte{0x78, 0x03})
	const limit = 1200

	var (
		chunks  []LogsChunk
		gotTime []uint64
	)
	err := ForEachLogsChunk(request, limit, func(chunk LogsChunk) error {
		chunks = append(chunks, chunk)
		if size := proto.Size(chunk.Request); size > limit {
			t.Fatalf("chunk %d size=%d > limit=%d", chunk.Index, size, limit)
		}
		resource := chunk.Request.ResourceLogs[0]
		if resource.SchemaUrl != "resource-schema" ||
			resource.ScopeLogs[0].SchemaUrl != "scope-schema" ||
			resource.Resource.Attributes[0].Key != "service.name" {
			t.Fatalf("chunk %d lost metadata: %v", chunk.Index, chunk.Request)
		}
		if string(resource.ProtoReflect().GetUnknown()) != string([]byte{0x78, 0x02}) ||
			string(resource.ScopeLogs[0].ProtoReflect().GetUnknown()) != string([]byte{0x78, 0x03}) {
			t.Fatalf("chunk %d lost nested unknown fields", chunk.Index)
		}
		for _, record := range resource.ScopeLogs[0].LogRecords {
			gotTime = append(gotTime, record.TimeUnixNano)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("chunks=%d, want splitting", len(chunks))
	}
	if string(chunks[0].Request.ProtoReflect().GetUnknown()) != string([]byte{0x78, 0x01}) {
		t.Fatal("first chunk lost request unknown fields")
	}
	for _, chunk := range chunks[1:] {
		if len(chunk.Request.ProtoReflect().GetUnknown()) != 0 {
			t.Fatalf("chunk %d duplicated request unknown fields", chunk.Index)
		}
	}
	if len(gotTime) != 12 {
		t.Fatalf("records=%d, want 12", len(gotTime))
	}
	for i, timestamp := range gotTime {
		if timestamp != uint64(i+1) {
			t.Fatalf("record order=%v", gotTime)
		}
	}
}

func TestForEachLogsChunkRejectsSingleOversizedRecord(t *testing.T) {
	request := logsRequest(1, 2048)
	emitted := 0
	err := ForEachLogsChunk(request, 512, func(LogsChunk) error {
		emitted++
		return nil
	})
	if !errors.Is(err, ErrLogRecordTooLarge) {
		t.Fatalf("error=%v, want ErrLogRecordTooLarge", err)
	}
	if emitted != 0 {
		t.Fatalf("emitted=%d, want 0", emitted)
	}
}

func TestForEachLogsChunkKeepsRecordWithItsResourceAndScope(t *testing.T) {
	request := &collogspb.ExportLogsServiceRequest{}
	for i, service := range []string{"checkout", "payments"} {
		request.ResourceLogs = append(request.ResourceLogs, &logspb.ResourceLogs{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{StringValue: service},
				},
			}}},
			ScopeLogs: []*logspb.ScopeLogs{{
				SchemaUrl: service + "-scope",
				LogRecords: []*logspb.LogRecord{{
					TimeUnixNano: uint64(i + 1),
					Body: &commonpb.AnyValue{
						Value: &commonpb.AnyValue_StringValue{
							StringValue: strings.Repeat("x", 256),
						},
					},
				}},
			}},
		})
	}
	got := make(map[uint64]string)
	err := ForEachLogsChunk(request, 500, func(chunk LogsChunk) error {
		for _, resource := range chunk.Request.ResourceLogs {
			service := resource.Resource.Attributes[0].Value.GetStringValue()
			for _, scope := range resource.ScopeLogs {
				for _, record := range scope.LogRecords {
					got[record.TimeUnixNano] = service + "/" + scope.SchemaUrl
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != "checkout/checkout-scope" || got[2] != "payments/payments-scope" {
		t.Fatalf("resource/scope association changed: %v", got)
	}
}

func TestForEachLogsChunkStopsAtEmitterFailure(t *testing.T) {
	request := logsRequest(10, 256)
	sentinel := errors.New("downstream")
	var indexes []int
	err := ForEachLogsChunk(request, 900, func(chunk LogsChunk) error {
		indexes = append(indexes, chunk.Index)
		if chunk.Index == 1 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error=%v, want sentinel", err)
	}
	if len(indexes) != 2 || indexes[0] != 0 || indexes[1] != 1 {
		t.Fatalf("indexes=%v, want [0 1]", indexes)
	}
}

func TestForEachLogsChunkDoesNotMutateInput(t *testing.T) {
	request := logsRequest(8, 128)
	before := proto.Clone(request)
	if err := ForEachLogsChunk(request, 600, func(LogsChunk) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(request, before) {
		t.Fatal("splitter mutated input")
	}
}

func FuzzForEachLogsChunk(f *testing.F) {
	seed, _ := proto.Marshal(logsRequest(6, 64))
	f.Add(seed, uint16(512))
	f.Add([]byte{0x0a, 0x00}, uint16(128))
	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint16) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		var request collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(data, &request); err != nil {
			return
		}
		limit := int(rawLimit%8192) + 64
		records := 0
		err := ForEachLogsChunk(&request, limit, func(chunk LogsChunk) error {
			if size := proto.Size(chunk.Request); size > limit {
				t.Fatalf("chunk size=%d > limit=%d", size, limit)
			}
			records += chunk.Records
			return nil
		})
		if err == nil && records != LogRecordCount(&request) {
			t.Fatalf("records=%d want=%d", records, LogRecordCount(&request))
		}
		if err != nil && !errors.Is(err, ErrLogRecordTooLarge) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
