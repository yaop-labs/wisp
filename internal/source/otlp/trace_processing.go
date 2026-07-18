package otlp

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	TraceValidationOff    = "off"
	TraceValidationReport = "report"
	TraceValidationReject = "reject"

	TraceResourcePreserve = "preserve"
	TraceResourceReplace  = "replace"
	TraceResourceReject   = "reject"

	maxTraceResourceAttributes = 32
	maxTraceResourceKeyBytes   = 256
	maxTraceResourceValueBytes = 4096
)

// TraceOptions configure correlation validation and explicit resource
// enrichment at OTLP admission. Empty validation defaults to report; empty
// resource conflict defaults to preserve.
type TraceOptions struct {
	Validation         string
	ResourceAttributes map[string]string
	ResourceConflict   string
	SamplingMode       string
	SamplingPercentage *float32
	SamplingHashSeed   uint32
}

type traceProcessing struct {
	validation         string
	resourceAttributes map[string]string
	resourceKeys       []string
	resourceConflict   string
	sampling           traceSampling
}

func newTraceProcessing(options TraceOptions) (traceProcessing, error) {
	validation := options.Validation
	if validation == "" {
		validation = TraceValidationReport
	}
	switch validation {
	case TraceValidationOff, TraceValidationReport, TraceValidationReject:
	default:
		return traceProcessing{}, fmt.Errorf(
			"otlp traces: validation must be off, report, or reject",
		)
	}

	if len(options.ResourceAttributes) == 0 &&
		options.ResourceConflict != "" {
		return traceProcessing{}, fmt.Errorf(
			"otlp traces: resource conflict requires enrichment attributes",
		)
	}
	conflict := options.ResourceConflict
	if conflict == "" {
		conflict = TraceResourcePreserve
	}
	switch conflict {
	case TraceResourcePreserve, TraceResourceReplace, TraceResourceReject:
	default:
		return traceProcessing{}, fmt.Errorf(
			"otlp traces: resource conflict must be preserve, replace, or reject",
		)
	}
	if len(options.ResourceAttributes) > maxTraceResourceAttributes {
		return traceProcessing{}, fmt.Errorf(
			"otlp traces: resource enrichment supports at most %d attributes",
			maxTraceResourceAttributes,
		)
	}
	for key, value := range options.ResourceAttributes {
		if key == "" || len(key) > maxTraceResourceKeyBytes ||
			!validTraceResourceText(key) {
			return traceProcessing{}, fmt.Errorf(
				"otlp traces: invalid resource attribute key",
			)
		}
		if len(value) > maxTraceResourceValueBytes ||
			!validTraceResourceText(value) {
			return traceProcessing{}, fmt.Errorf(
				"otlp traces: invalid resource attribute %q value",
				key,
			)
		}
	}
	sampling, err := newTraceSampling(options)
	if err != nil {
		return traceProcessing{}, err
	}
	attributes := maps.Clone(options.ResourceAttributes)
	return traceProcessing{
		validation:         validation,
		resourceAttributes: attributes,
		resourceKeys:       slices.Sorted(maps.Keys(attributes)),
		resourceConflict:   conflict,
		sampling:           sampling,
	}, nil
}

func validTraceResourceText(value string) bool {
	return utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

type traceValidationReport struct {
	spans              int
	invalidSpans       int
	invalidTraceIDs    int
	invalidSpanIDs     int
	invalidParentIDs   int
	invalidLinks       int
	invalidTraceStates int
	duplicateSpanIDs   int
	parentCycleSpans   int
	missingNames       int
	invalidTimestamps  int
}

func (r traceValidationReport) invalid() bool {
	return r.invalidSpans > 0
}

func (r traceValidationReport) message() string {
	return fmt.Sprintf(
		"invalid_spans=%d invalid_trace_ids=%d invalid_span_ids=%d "+
			"invalid_parent_ids=%d invalid_links=%d invalid_tracestates=%d "+
			"duplicate_span_ids=%d "+
			"parent_cycle_spans=%d missing_names=%d invalid_timestamps=%d",
		r.invalidSpans,
		r.invalidTraceIDs,
		r.invalidSpanIDs,
		r.invalidParentIDs,
		r.invalidLinks,
		r.invalidTraceStates,
		r.duplicateSpanIDs,
		r.parentCycleSpans,
		r.missingNames,
		r.invalidTimestamps,
	)
}

type traceCorrelationKey struct {
	traceID string
	spanID  string
}

func validateTraceCorrelation(
	request *coltracepb.ExportTraceServiceRequest,
) traceValidationReport {
	var report traceValidationReport
	if request == nil {
		return report
	}

	invalidSpans := make(map[*tracepb.Span]struct{})
	spansByKey := make(map[traceCorrelationKey]*tracepb.Span)
	ambiguous := make(map[traceCorrelationKey]struct{})
	var spans []*tracepb.Span

	for _, resourceSpans := range request.ResourceSpans {
		if resourceSpans == nil {
			continue
		}
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			if scopeSpans == nil {
				continue
			}
			for _, span := range scopeSpans.Spans {
				report.spans++
				if span == nil {
					report.invalidSpans++
					continue
				}
				spans = append(spans, span)
				invalid := false
				traceIDValid := validTraceID(span.TraceId)
				spanIDValid := validSpanID(span.SpanId)
				if !traceIDValid {
					report.invalidTraceIDs++
					invalid = true
				}
				if !spanIDValid {
					report.invalidSpanIDs++
					invalid = true
				}
				if len(span.ParentSpanId) != 0 &&
					!validSpanID(span.ParentSpanId) {
					report.invalidParentIDs++
					invalid = true
				}
				if !validTraceState(span.TraceState) {
					report.invalidTraceStates++
					invalid = true
				}
				if span.Name == "" {
					report.missingNames++
					invalid = true
				}
				if span.StartTimeUnixNano == 0 ||
					span.EndTimeUnixNano == 0 ||
					span.EndTimeUnixNano < span.StartTimeUnixNano {
					report.invalidTimestamps++
					invalid = true
				}
				for _, link := range span.Links {
					if link == nil ||
						!validTraceID(link.TraceId) ||
						!validSpanID(link.SpanId) {
						report.invalidLinks++
						invalid = true
						continue
					}
					if !validTraceState(link.TraceState) {
						report.invalidTraceStates++
						invalid = true
					}
				}
				if invalid {
					invalidSpans[span] = struct{}{}
				}
				if !traceIDValid || !spanIDValid {
					continue
				}
				key := traceCorrelationKey{
					traceID: string(span.TraceId),
					spanID:  string(span.SpanId),
				}
				if first, duplicate := spansByKey[key]; duplicate {
					report.duplicateSpanIDs++
					invalidSpans[first] = struct{}{}
					invalidSpans[span] = struct{}{}
					ambiguous[key] = struct{}{}
				} else {
					spansByKey[key] = span
				}
			}
		}
	}

	for key := range ambiguous {
		delete(spansByKey, key)
	}
	report.parentCycleSpans = markTraceParentCycles(
		spans,
		spansByKey,
		invalidSpans,
	)
	report.invalidSpans += len(invalidSpans)
	return report
}

func markTraceParentCycles(
	spans []*tracepb.Span,
	spansByKey map[traceCorrelationKey]*tracepb.Span,
	invalidSpans map[*tracepb.Span]struct{},
) int {
	parents := make(map[traceCorrelationKey]traceCorrelationKey)
	for key, span := range spansByKey {
		if len(span.ParentSpanId) == 0 || !validSpanID(span.ParentSpanId) {
			continue
		}
		parent := traceCorrelationKey{
			traceID: key.traceID,
			spanID:  string(span.ParentSpanId),
		}
		if _, exists := spansByKey[parent]; exists {
			parents[key] = parent
		}
	}

	done := make(map[traceCorrelationKey]struct{}, len(spansByKey))
	visiting := make(map[traceCorrelationKey]int)
	var path []traceCorrelationKey
	cycleSpans := make(map[*tracepb.Span]struct{})
	for _, span := range spans {
		if span == nil || !validTraceID(span.TraceId) ||
			!validSpanID(span.SpanId) {
			continue
		}
		start := traceCorrelationKey{
			traceID: string(span.TraceId),
			spanID:  string(span.SpanId),
		}
		if _, exists := spansByKey[start]; !exists {
			continue
		}
		if _, complete := done[start]; complete {
			continue
		}

		path = path[:0]
		current := start
		for {
			if _, complete := done[current]; complete {
				break
			}
			if index, cycle := visiting[current]; cycle {
				for _, key := range path[index:] {
					value := spansByKey[key]
					cycleSpans[value] = struct{}{}
					invalidSpans[value] = struct{}{}
				}
				break
			}
			visiting[current] = len(path)
			path = append(path, current)
			parent, exists := parents[current]
			if !exists {
				break
			}
			current = parent
		}
		for _, key := range path {
			delete(visiting, key)
			done[key] = struct{}{}
		}
	}
	return len(cycleSpans)
}

func validTraceID(value []byte) bool {
	return len(value) == 16 && !allZero(value)
}

func validSpanID(value []byte) bool {
	return len(value) == 8 && !allZero(value)
}

func allZero(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}

func validTraceState(value string) bool {
	if value == "" {
		return true
	}
	members := strings.Split(value, ",")
	if len(members) > 32 {
		return false
	}
	keys := make(map[string]struct{}, len(members))
	for _, member := range members {
		member = trimOptionalWhitespace(member)
		if member == "" {
			continue
		}
		key, stateValue, found := strings.Cut(member, "=")
		if !found || !validTraceStateKey(key) ||
			!validTraceStateValue(stateValue) {
			return false
		}
		if _, duplicate := keys[key]; duplicate {
			return false
		}
		keys[key] = struct{}{}
	}
	return true
}

func trimOptionalWhitespace(value string) string {
	return strings.Trim(value, " \t")
}

func validTraceStateKey(value string) bool {
	if strings.Count(value, "@") > 1 {
		return false
	}
	tenant, system, multiTenant := strings.Cut(value, "@")
	if !multiTenant {
		return len(tenant) >= 1 && len(tenant) <= 256 &&
			asciiLower(tenant[0]) &&
			validTraceStateKeyTail(tenant[1:])
	}
	return len(tenant) >= 1 && len(tenant) <= 241 &&
		(asciiLower(tenant[0]) || asciiDigit(tenant[0])) &&
		validTraceStateKeyTail(tenant[1:]) &&
		len(system) >= 1 && len(system) <= 14 &&
		asciiLower(system[0]) &&
		validTraceStateKeyTail(system[1:])
}

func validTraceStateKeyTail(value string) bool {
	for index := range len(value) {
		char := value[index]
		if !asciiLower(char) && !asciiDigit(char) &&
			char != '_' && char != '-' && char != '*' && char != '/' {
			return false
		}
	}
	return true
}

func validTraceStateValue(value string) bool {
	if len(value) < 1 || len(value) > 256 ||
		value[len(value)-1] == ' ' {
		return false
	}
	for index := range len(value) {
		char := value[index]
		if char < 0x20 || char > 0x7e ||
			char == ',' || char == '=' {
			return false
		}
	}
	return true
}

func asciiLower(value byte) bool {
	return value >= 'a' && value <= 'z'
}

func asciiDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func (p traceProcessing) enrich(
	request *coltracepb.ExportTraceServiceRequest,
) (*coltracepb.ExportTraceServiceRequest, error) {
	if request == nil || len(p.resourceKeys) == 0 {
		return request, nil
	}
	enriched := proto.Clone(request).(*coltracepb.ExportTraceServiceRequest)
	for _, resourceSpans := range enriched.ResourceSpans {
		if resourceSpans == nil || traceResourceSpanCount(resourceSpans) == 0 {
			continue
		}
		if resourceSpans.Resource == nil {
			resourceSpans.Resource = &resourcepb.Resource{}
		}
		if err := p.enrichResource(resourceSpans.Resource); err != nil {
			return nil, err
		}
	}
	return enriched, nil
}

func traceResourceSpanCount(resourceSpans *tracepb.ResourceSpans) int {
	count := 0
	for _, scopeSpans := range resourceSpans.ScopeSpans {
		if scopeSpans != nil {
			count += len(scopeSpans.Spans)
		}
	}
	return count
}

func (p traceProcessing) enrichResource(resource *resourcepb.Resource) error {
	existing := make(map[string][]*commonpb.KeyValue)
	for _, attribute := range resource.Attributes {
		if attribute != nil {
			existing[attribute.Key] = append(existing[attribute.Key], attribute)
		}
	}

	switch p.resourceConflict {
	case TraceResourceReject:
		for _, key := range p.resourceKeys {
			attributes := existing[key]
			for _, attribute := range attributes {
				if attribute.Value == nil {
					return fmt.Errorf(
						"resource attribute conflict for %q",
						key,
					)
				}
				stringValue, ok := attribute.Value.GetValue().(*commonpb.AnyValue_StringValue)
				if !ok ||
					stringValue.StringValue != p.resourceAttributes[key] {
					return fmt.Errorf(
						"resource attribute conflict for %q",
						key,
					)
				}
			}
		}
	case TraceResourceReplace:
		filtered := resource.Attributes[:0]
		for _, attribute := range resource.Attributes {
			if attribute == nil {
				filtered = append(filtered, attribute)
				continue
			}
			if _, replace := p.resourceAttributes[attribute.Key]; !replace {
				filtered = append(filtered, attribute)
			}
		}
		resource.Attributes = filtered
	}

	for _, key := range p.resourceKeys {
		if p.resourceConflict != TraceResourceReplace &&
			len(existing[key]) > 0 {
			continue
		}
		resource.Attributes = append(resource.Attributes, &commonpb.KeyValue{
			Key: key,
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: p.resourceAttributes[key],
				},
			},
		})
	}
	return nil
}
