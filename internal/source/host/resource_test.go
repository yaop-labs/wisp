package host

import (
	"slices"
	"testing"

	"github.com/yaop-labs/wisp/internal/model"
)

func TestDetectResourceFromConfiguredHostRoot(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "etc/hostname", "host-node-1\n")
	writeFixture(t, root, "etc/os-release", `
NAME="Example Linux"
VERSION_ID="42"
PRETTY_NAME="Example Linux 42"
IGNORED="value"
`)
	writeFixture(
		t,
		root,
		"etc/machine-id",
		"0123456789abcdef0123456789abcdef\n",
	)
	base := model.Labels{
		{Name: "service.name", Value: "wisp"},
		{Name: "host.name", Value: "container-name"},
	}
	detected, errs := DetectResource(
		base,
		Paths{RootFS: root},
		map[string]string{"service.name": "wisp"},
		true,
	)
	if len(errs) != 0 {
		t.Fatalf("detection errors: %v", errs)
	}
	for name, want := range map[string]string{
		"host.name":      "host-node-1",
		"host.id":        "0123456789abcdef0123456789abcdef",
		"os.type":        "linux",
		"os.name":        "Example Linux",
		"os.version":     "42",
		"os.description": "Example Linux 42",
	} {
		if got, _ := detected.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if arch, ok := detected.Get("host.arch"); !ok || arch == "" {
		t.Error("host.arch was not detected")
	}
	names := make([]string, 0, len(detected))
	for _, label := range detected {
		names = append(names, label.Name)
	}
	if !slices.IsSorted(names) {
		t.Errorf("resource labels are not sorted: %v", names)
	}
}

func TestDetectResourcePreservesExplicitAttributes(t *testing.T) {
	explicit := map[string]string{
		"service.name":   "wisp",
		"host.name":      "configured-host",
		"host.id":        "configured-id",
		"host.arch":      "configured-arch",
		"os.type":        "configured-os",
		"os.name":        "configured-name",
		"os.version":     "configured-version",
		"os.description": "configured-description",
	}
	base := make(model.Labels, 0, len(explicit))
	for name, value := range explicit {
		base = append(base, model.Label{Name: name, Value: value})
	}
	detected, errs := DetectResource(
		base,
		Paths{RootFS: t.TempDir()},
		explicit,
		true,
	)
	if len(errs) != 0 {
		t.Fatalf("explicit resource should need no filesystem detection: %v", errs)
	}
	for name, want := range explicit {
		if got, _ := detected.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestDetectResourceHostIDIsOptInAndFailuresAreFailOpen(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "etc/hostname", "invalid hostname\n")
	writeFixture(t, root, "etc/os-release", `PRETTY_NAME="unterminated`)
	writeFixture(t, root, "etc/machine-id", "uninitialized\n")
	base := model.Labels{
		{Name: "service.name", Value: "wisp"},
		{Name: "host.name", Value: "fallback"},
	}
	detected, errs := DetectResource(
		base,
		Paths{RootFS: root},
		map[string]string{"service.name": "wisp"},
		false,
	)
	if len(errs) < 2 {
		t.Fatalf("detection errors = %v, want hostname and os-release", errs)
	}
	if got, _ := detected.Get("host.name"); got != "fallback" {
		t.Errorf("fail-open host.name = %q, want fallback", got)
	}
	if _, exists := detected.Get("host.id"); exists {
		t.Fatal("host.id should not be detected without opt-in")
	}

	_, errs = DetectResource(
		base,
		Paths{RootFS: root},
		map[string]string{"service.name": "wisp"},
		true,
	)
	if len(errs) < 3 {
		t.Fatalf("host.id opt-in errors = %v", errs)
	}
}

func TestParseOSReleaseValue(t *testing.T) {
	for raw, want := range map[string]string{
		`plain`:             "plain",
		`'single quoted'`:   "single quoted",
		`"double quoted"`:   "double quoted",
		`"dollar\$quote\""`: `dollar$quote"`,
	} {
		got, err := parseOSReleaseValue(raw)
		if err != nil || got != want {
			t.Errorf(
				"parseOSReleaseValue(%q) = %q, %v; want %q",
				raw,
				got,
				err,
				want,
			)
		}
	}
	for _, raw := range []string{
		"has space",
		`"unterminated`,
		`"bad\qescape"`,
		"'unterminated",
	} {
		if _, err := parseOSReleaseValue(raw); err == nil {
			t.Errorf("parseOSReleaseValue(%q) should fail", raw)
		}
	}
}
