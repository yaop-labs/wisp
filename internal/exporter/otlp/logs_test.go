package otlp

import (
	"context"
	"errors"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
	"github.com/yaop-labs/wisp/internal/signal"
)

type fakeLogsTransport struct {
	response *collogspb.ExportLogsServiceResponse
	err      error
	calls    int
}

func (t *fakeLogsTransport) sendLogs(context.Context, *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	t.calls++
	return t.response, t.err
}
func (*fakeLogsTransport) close() error { return nil }

func logsTestEnvelope(t *testing.T) signal.Envelope {
	t.Helper()
	payload, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// An empty protobuf request encodes to zero bytes, while durable envelopes
	// intentionally reject empty payloads. Add an unknown field: the exporter
	// still validates protobuf framing and preserves it.
	if len(payload) == 0 {
		payload = []byte{0x78, 0x01}
	}
	envelope, err := signal.New(
		signal.Logs, signal.OTLPLogsSchema, signal.OTLPProtobufEncoding, payload, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestLogsExporterRejectsWrongCapabilityBeforeTransport(t *testing.T) {
	transport := &fakeLogsTransport{response: &collogspb.ExportLogsServiceResponse{}}
	exporter := &LogsExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	envelope := logsTestEnvelope(t)
	envelope.Schema = "wrong"
	err := exporter.Send(context.Background(), envelope)
	if !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("Send error = %v, want ErrPermanent", err)
	}
	if transport.calls != 0 {
		t.Fatalf("transport calls = %d, want 0", transport.calls)
	}
}

func TestLogsExporterAccountsPartialSuccessWithoutRetryError(t *testing.T) {
	transport := &fakeLogsTransport{response: &collogspb.ExportLogsServiceResponse{
		PartialSuccess: &collogspb.ExportLogsPartialSuccess{
			RejectedLogRecords: 2,
			ErrorMessage:       "policy",
		},
	}}
	exporter := &LogsExporter{tr: transport, timeout: time.Second, logger: discardLog()}
	before := selfobs.OTLPLogsRejected.Get()
	if err := exporter.Send(context.Background(), logsTestEnvelope(t)); err != nil {
		t.Fatal(err)
	}
	if delta := selfobs.OTLPLogsRejected.Get() - before; delta != 2 {
		t.Fatalf("rejected delta = %d, want 2", delta)
	}
}
