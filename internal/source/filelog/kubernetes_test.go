package filelog

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestParseKubernetesPodLogPath(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "host", "var", "log", "pods")
	tests := []struct {
		name string
		path string
		want kubernetesPathMetadata
		ok   bool
	}{
		{
			name: "current log",
			path: filepath.Join(
				root,
				"payments_checkout-7c8d9_275ecb36-5aa8-4c2a-9c47-d8bb681b9aff",
				"api",
				"3.log",
			),
			want: kubernetesPathMetadata{
				namespace:    "payments",
				podName:      "checkout-7c8d9",
				podUID:       "275ecb36-5aa8-4c2a-9c47-d8bb681b9aff",
				container:    "api",
				restartCount: 3,
			},
			ok: true,
		},
		{
			name: "rotated log",
			path: filepath.Join(
				root,
				"default_api-0_ABC-123",
				"worker",
				"0.log.20260718-101112",
			),
			want: kubernetesPathMetadata{
				namespace: "default", podName: "api-0", podUID: "ABC-123",
				container: "worker",
			},
			ok: true,
		},
		{
			name: "outside root",
			path: filepath.Join(
				filepath.Dir(root),
				"other",
				"default_api_uid",
				"api",
				"0.log",
			),
		},
		{
			name: "extra depth",
			path: filepath.Join(root, "extra", "default_api_uid", "api", "0.log"),
		},
		{
			name: "invalid pod directory",
			path: filepath.Join(root, "default_api_name_uid", "api", "0.log"),
		},
		{
			name: "invalid namespace",
			path: filepath.Join(root, "Default_api_uid", "api", "0.log"),
		},
		{
			name: "invalid container",
			path: filepath.Join(root, "default_api_uid", "API", "0.log"),
		},
		{
			name: "invalid restart count",
			path: filepath.Join(root, "default_api_uid", "api", "-1.log"),
		},
		{
			name: "unrecognized filename",
			path: filepath.Join(root, "default_api_uid", "api", "current.txt"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := parseKubernetesPodLogPath(root, test.path)
			if ok != test.ok || got != test.want {
				t.Fatalf("metadata=%+v ok=%v, want %+v ok=%v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestKubernetesEnrichmentConfigDefaultsAndValidation(t *testing.T) {
	base := Config{
		Include:        []string{filepath.Join(t.TempDir(), "*.log")},
		CheckpointFile: filepath.Join(t.TempDir(), "checkpoint.json"),
		Format:         "cri",
		Kubernetes:     &KubernetesConfig{},
	}
	source, err := New(
		base,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := source.cfg.Kubernetes.PodLogsRoot; got != "/var/log/pods" {
		t.Fatalf("default pod logs root=%q", got)
	}

	relative := base
	relative.Kubernetes = &KubernetesConfig{PodLogsRoot: "var/log/pods"}
	if _, err := New(relative, nil); err == nil {
		t.Fatal("relative pod logs root accepted")
	}
	text := base
	text.Format = "text"
	if _, err := New(text, nil); err == nil {
		t.Fatal("Kubernetes enrichment accepted with text framing")
	}
}
