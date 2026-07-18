// Package otlpwire contains bounded protobuf operations shared by OTLP
// receivers and exporters.
package otlpwire

import (
	"bytes"
	"errors"
	"fmt"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultMaxRequestBytes  = 3 << 20
	MaxReceiverRequestBytes = 16 << 20
)

// ErrLogRecordTooLarge means no semantics-preserving split can make one record
// plus its resource/scope metadata fit the configured request bound.
var ErrLogRecordTooLarge = errors.New("otlp logs: one record and its metadata exceed the request limit")

// LogsChunk is one bounded request in original wire order.
type LogsChunk struct {
	Request *collogspb.ExportLogsServiceRequest
	Index   int
	Records int
}

// ForEachLogsChunk walks records in wire order and emits requests no larger
// than maxBytes. ResourceLogs and ScopeLogs metadata are cloned for every chunk
// that needs them. Request-level unknown fields are retained on the first
// chunk. The input is never mutated.
func ForEachLogsChunk(
	request *collogspb.ExportLogsServiceRequest,
	maxBytes int,
	emit func(LogsChunk) error,
) error {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxRequestBytes
	}
	if proto.Size(request) <= maxBytes {
		records := LogRecordCount(request)
		if records == 0 {
			return nil
		}
		return emit(LogsChunk{Request: request, Records: records})
	}

	var (
		current      *collogspb.ExportLogsServiceRequest
		currentScope *logspb.ScopeLogs
		estimated    int
		records      int
		index        int
	)
	first := true

	newRequest := func() {
		current = &collogspb.ExportLogsServiceRequest{}
		if first {
			current.ProtoReflect().SetUnknown(bytes.Clone(request.ProtoReflect().GetUnknown()))
		}
		estimated = proto.Size(current)
	}
	flush := func() error {
		if records == 0 {
			return nil
		}
		size := proto.Size(current)
		if size > maxBytes {
			return fmt.Errorf("%w: chunk=%d size=%d limit=%d",
				ErrLogRecordTooLarge, index, size, maxBytes)
		}
		if err := emit(LogsChunk{
			Request: current, Index: index, Records: records,
		}); err != nil {
			return err
		}
		index++
		first = false
		current = nil
		currentScope = nil
		estimated = 0
		records = 0
		return nil
	}
	addGroup := func(resource *logspb.ResourceLogs, scope *logspb.ScopeLogs, nextRecordBytes int) error {
		resourceCopy := &logspb.ResourceLogs{SchemaUrl: resource.SchemaUrl}
		resourceCopy.ProtoReflect().SetUnknown(bytes.Clone(resource.ProtoReflect().GetUnknown()))
		if resource.Resource != nil {
			resourceCopy.Resource = proto.Clone(resource.Resource).(*resourcepb.Resource)
		}
		scopeCopy := &logspb.ScopeLogs{SchemaUrl: scope.SchemaUrl}
		scopeCopy.ProtoReflect().SetUnknown(bytes.Clone(scope.ProtoReflect().GetUnknown()))
		if scope.Scope != nil {
			scopeCopy.Scope = proto.Clone(scope.Scope).(*commonpb.InstrumentationScope)
		}
		resourceCopy.ScopeLogs = []*logspb.ScopeLogs{scopeCopy}
		unit := &collogspb.ExportLogsServiceRequest{
			ResourceLogs: []*logspb.ResourceLogs{resourceCopy},
		}
		unitSize := proto.Size(unit)

		if current != nil && records > 0 && estimated+unitSize+nextRecordBytes > maxBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		if current == nil {
			newRequest()
		}
		current.ResourceLogs = append(current.ResourceLogs, resourceCopy)
		currentScope = scopeCopy
		// Adding separately encoded request sizes is a conservative upper bound:
		// it double-counts outer wrappers rather than undercounting them.
		estimated += unitSize
		if proto.Size(current) > maxBytes {
			return fmt.Errorf("%w: resource/scope metadata size=%d limit=%d",
				ErrLogRecordTooLarge, proto.Size(current), maxBytes)
		}
		return nil
	}

	for _, resource := range request.ResourceLogs {
		if resource == nil {
			continue
		}
		for _, scope := range resource.ScopeLogs {
			if scope == nil || len(scope.LogRecords) == 0 {
				continue
			}
			groupAdded := false
			for _, record := range scope.LogRecords {
				if record == nil {
					// A nil repeated message is encoded as an empty log record.
					record = &logspb.LogRecord{}
				}
				// 32 bytes safely cover repeated-field tags and all three nested
				// message-length varints as they cross encoding thresholds.
				contribution := proto.Size(record) + 32
				if !groupAdded {
					if err := addGroup(resource, scope, contribution); err != nil {
						return err
					}
					groupAdded = true
				} else if records > 0 && estimated+contribution > maxBytes {
					if err := flush(); err != nil {
						return err
					}
					if err := addGroup(resource, scope, contribution); err != nil {
						return err
					}
					groupAdded = true
				}
				currentScope.LogRecords = append(currentScope.LogRecords, record)
				estimated += contribution
				records++
				if records == 1 && proto.Size(current) > maxBytes {
					return fmt.Errorf("%w: record size=%d limit=%d",
						ErrLogRecordTooLarge, proto.Size(current), maxBytes)
				}
			}
		}
	}
	return flush()
}

func LogRecordCount(request *collogspb.ExportLogsServiceRequest) int {
	count := 0
	for _, resource := range request.ResourceLogs {
		if resource == nil {
			continue
		}
		for _, scope := range resource.ScopeLogs {
			if scope != nil {
				count += len(scope.LogRecords)
			}
		}
	}
	return count
}
