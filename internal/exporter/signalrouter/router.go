// Package signalrouter dispatches durable envelopes to exporters that
// explicitly advertise support for their signal kind.
package signalrouter

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/signal"
)

type Router struct {
	routes map[signal.Kind]signal.Sender
	kinds  []signal.Kind
}

func New(routes map[signal.Kind]signal.Sender) (*Router, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("signal router: at least one route required")
	}
	cloned := make(map[signal.Kind]signal.Sender, len(routes))
	kinds := make([]signal.Kind, 0, len(routes))
	for kind, sender := range routes {
		if sender == nil {
			return nil, fmt.Errorf("signal router: nil sender for %q", kind)
		}
		cloned[kind] = sender
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return &Router{routes: cloned, kinds: kinds}, nil
}

func (r *Router) Send(ctx context.Context, envelope signal.Envelope) error {
	sender := r.routes[envelope.Kind]
	if sender == nil {
		return fmt.Errorf("%w: signal router: unsupported kind %q",
			pipeline.ErrPermanent, envelope.Kind)
	}
	return sender.Send(ctx, envelope)
}

func (r *Router) Close() error {
	var err error
	for i := len(r.kinds) - 1; i >= 0; i-- {
		err = errors.Join(err, r.routes[r.kinds[i]].Close())
	}
	return err
}
