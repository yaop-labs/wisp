package host

import (
	"errors"
	"fmt"
)

const maxReportedCollectorErrors = 16

// boundedErrors prevents one corrupted high-cardinality kernel file from
// allocating or logging an error for every record.
type boundedErrors struct {
	errs    []error
	omitted int
}

func (b *boundedErrors) Add(err error) {
	if err == nil {
		return
	}
	if len(b.errs) < maxReportedCollectorErrors {
		b.errs = append(b.errs, err)
		return
	}
	b.omitted++
}

func (b *boundedErrors) Empty() bool {
	return len(b.errs) == 0 && b.omitted == 0
}

func (b *boundedErrors) Err() error {
	if b.Empty() {
		return nil
	}
	errs := append([]error(nil), b.errs...)
	if b.omitted > 0 {
		errs = append(
			errs,
			fmt.Errorf("%d additional errors omitted", b.omitted),
		)
	}
	return errors.Join(errs...)
}
