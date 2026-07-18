package filelog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeKubernetesMetadataClient struct {
	mu         sync.Mutex
	pod        apiPod
	podErr     error
	owner      apiOwner
	ownerErr   error
	podCalls   int
	ownerCalls int
}

func (c *fakeKubernetesMetadataClient) Pod(
	context.Context,
	string,
	string,
) (apiPod, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.podCalls++
	return c.pod, c.podErr
}

func (c *fakeKubernetesMetadataClient) Owner(
	context.Context,
	string,
	ownerReference,
) (apiOwner, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ownerCalls++
	return c.owner, c.ownerErr
}

func boolPointer(value bool) *bool { return &value }

func TestKubernetesAPIResolverEnrichesWithoutBlockingInitialLookup(
	t *testing.T,
) {
	client := &fakeKubernetesMetadataClient{}
	client.pod.Metadata.UID = "pod-uid"
	client.pod.Metadata.Labels = map[string]string{
		"app.kubernetes.io/name": "checkout",
		"ignored":                "secret",
	}
	client.pod.Metadata.OwnerReferences = []ownerReference{{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       "checkout-7b9f",
		UID:        "replicaset-uid",
		Controller: boolPointer(true),
	}}
	client.pod.Spec.NodeName = "node-a"
	client.pod.Spec.Containers = append(
		client.pod.Spec.Containers,
		apiContainer{Name: "api", Image: "registry.example/checkout:v2"},
	)
	client.pod.Status.ContainerStatuses = append(
		client.pod.Status.ContainerStatuses,
		apiContainerStatus{
			Name:        "api",
			ImageID:     "registry.example/checkout@sha256:abc123",
			ContainerID: "containerd://container-id",
		},
	)
	client.owner.Metadata.UID = "replicaset-uid"
	client.owner.Metadata.OwnerReferences = []ownerReference{{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "checkout",
		UID:        "deployment-uid",
		Controller: boolPointer(true),
	}}
	resolver, err := newKubernetesAPIResolver(&KubernetesAPIConfig{
		Timeout:      time.Second,
		CacheTTL:     time.Minute,
		StaleAfter:   time.Hour,
		FailureRetry: time.Second,
		MaxPods:      10,
		Workers:      1,
		Labels:       []string{"app.kubernetes.io/name"},
		client:       client,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolver.start(ctx)
	pathMetadata := kubernetesPathMetadata{
		namespace: "prod",
		podName:   "checkout-7b9f-x",
		podUID:    "pod-uid",
		container: "api",
	}
	if got := resolver.lookup(pathMetadata); got != nil {
		t.Fatalf("initial asynchronous lookup=%v", got)
	}
	var got map[string]string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got = resolver.lookup(pathMetadata)
		if len(got) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got["k8s.node.name"] != "node-a" ||
		got["k8s.deployment.name"] != "checkout" ||
		got["k8s.replicaset.name"] != "checkout-7b9f" ||
		got["k8s.pod.label.app.kubernetes.io/name"] != "checkout" ||
		got["container.image.name"] != "registry.example/checkout" ||
		got["container.id"] != "container-id" ||
		got["oci.manifest.digest"] != "sha256:abc123" {
		t.Fatalf("attributes=%v", got)
	}
	if _, exists := got["k8s.pod.label.ignored"]; exists {
		t.Fatal("non-allowlisted label was copied")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.podCalls != 1 || client.ownerCalls != 1 {
		t.Fatalf(
			"pod calls=%d owner calls=%d",
			client.podCalls,
			client.ownerCalls,
		)
	}
}

func TestKubernetesAPIResolverFailsOpenAndNegativeCaches(t *testing.T) {
	client := &fakeKubernetesMetadataClient{
		podErr: errors.New("api unavailable"),
	}
	resolver, err := newKubernetesAPIResolver(&KubernetesAPIConfig{
		Timeout:      time.Second,
		CacheTTL:     time.Minute,
		StaleAfter:   time.Hour,
		FailureRetry: time.Hour,
		MaxPods:      10,
		Workers:      1,
		client:       client,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolver.start(ctx)
	metadata := kubernetesPathMetadata{
		namespace: "prod", podName: "api", podUID: "uid", container: "api",
	}
	if got := resolver.lookup(metadata); got != nil {
		t.Fatalf("failure lookup=%v", got)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		calls := client.podCalls
		client.mu.Unlock()
		if calls == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for range 10 {
		if got := resolver.lookup(metadata); got != nil {
			t.Fatalf("negative cache lookup=%v", got)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.podCalls != 1 {
		t.Fatalf("negative cache pod calls=%d", client.podCalls)
	}
}

func TestKubernetesAPIResolverRejectsReusedPodName(t *testing.T) {
	client := &fakeKubernetesMetadataClient{}
	client.pod.Metadata.UID = "new-pod-uid"
	resolver, err := newKubernetesAPIResolver(&KubernetesAPIConfig{
		Timeout:      time.Second,
		CacheTTL:     time.Minute,
		StaleAfter:   time.Hour,
		FailureRetry: time.Minute,
		MaxPods:      10,
		Workers:      1,
		client:       client,
	})
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := resolver.fetch(
		context.Background(),
		kubernetesPathMetadata{
			namespace: "prod",
			podName:   "checkout",
			podUID:    "old-pod-uid",
			container: "api",
		},
	)
	if err == nil || attributes != nil {
		t.Fatalf("attributes=%v error=%v", attributes, err)
	}
}

func TestKubernetesAPIResolverMarksBoundedStaleMetadata(t *testing.T) {
	resolver, err := newKubernetesAPIResolver(&KubernetesAPIConfig{
		Timeout:      time.Second,
		CacheTTL:     time.Minute,
		StaleAfter:   time.Hour,
		FailureRetry: time.Minute,
		MaxPods:      10,
		Workers:      1,
		client:       &fakeKubernetesMetadataClient{},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	resolver.now = func() time.Time { return now }
	resolver.cache["pod-uid"] = kubernetesCacheEntry{
		attributes: map[string]string{"k8s.node.name": "node-a"},
		refreshAt:  now.Add(-time.Second),
		staleAt:    now.Add(time.Minute),
		lastUsed:   now.Add(-time.Minute),
	}
	got := resolver.lookup(kubernetesPathMetadata{
		namespace: "prod", podName: "api", podUID: "pod-uid",
	})
	if got["k8s.node.name"] != "node-a" ||
		got["wisp.kubernetes.api.stale"] != "true" {
		t.Fatalf("stale attributes=%v", got)
	}
	if len(resolver.queue) != 1 {
		t.Fatalf("scheduled refreshes=%d", len(resolver.queue))
	}
}

func TestKubernetesAPIRequiresExplicitInClusterIdentity(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	_, err := newKubernetesAPIResolver(&KubernetesAPIConfig{})
	if err == nil {
		t.Fatal("missing in-cluster identity accepted")
	}
}

func TestKubernetesAPIResolverRejectsInvalidLabelAllowlist(t *testing.T) {
	client := &fakeKubernetesMetadataClient{}
	for _, labels := range [][]string{
		{"not valid"},
		{"app.kubernetes.io/name", "app.kubernetes.io/name"},
	} {
		if _, err := newKubernetesAPIResolver(&KubernetesAPIConfig{
			Labels: labels,
			client: client,
		}); err == nil {
			t.Fatalf("accepted labels=%v", labels)
		}
	}
}

func TestKubernetesAPIResolverSourceConstruction(t *testing.T) {
	client := &fakeKubernetesMetadataClient{}
	_, err := New(Config{
		Include:        []string{"/tmp/*.log"},
		CheckpointFile: t.TempDir() + "/checkpoint.json",
		Format:         "cri",
		Kubernetes: &KubernetesConfig{
			PodLogsRoot: "/var/log/pods",
			API: &KubernetesAPIConfig{
				MaxPods: 10,
				Workers: 1,
				client:  client,
			},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
}

func TestKubernetesAPICacheAugmentsPathResource(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pods")
	source, err := New(Config{
		Include:        []string{filepath.Join(root, "*", "*", "*.log")},
		CheckpointFile: filepath.Join(t.TempDir(), "checkpoint.json"),
		Format:         "cri",
		Kubernetes: &KubernetesConfig{
			PodLogsRoot: root,
			API: &KubernetesAPIConfig{
				MaxPods: 10,
				Workers: 1,
				client:  &fakeKubernetesMetadataClient{},
			},
		},
		Resource: map[string]string{
			"service.name":  "wisp",
			"k8s.node.name": "global-node",
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	source.kubernetesAPI.cache["pod-uid"] = kubernetesCacheEntry{
		attributes: map[string]string{
			"k8s.node.name":       "pod-node",
			"k8s.deployment.name": "checkout",
		},
		refreshAt: time.Now().Add(time.Hour),
		staleAt:   time.Now().Add(time.Hour),
		lastUsed:  time.Now(),
	}
	logPath := filepath.Join(
		root,
		"prod_checkout-abc_pod-uid",
		"api",
		"2.log",
	)
	resource, identity, pathEnriched, apiEnriched := source.resourceForPath(
		logPath,
	)
	if !pathEnriched || !apiEnriched {
		t.Fatalf(
			"path enriched=%v API enriched=%v",
			pathEnriched,
			apiEnriched,
		)
	}
	if got := resourceAttributeString(
		resource,
		"k8s.node.name",
	); got != "pod-node" {
		t.Fatalf("node=%q", got)
	}
	if identity["k8s.pod.uid"] != "pod-uid" ||
		identity["k8s.deployment.name"] != "checkout" {
		t.Fatalf("identity=%v", identity)
	}
}

func TestInClusterMetadataClientReloadsTokenAndBoundsResponse(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("token-one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var authorizations []string
	var requestPaths []string
	server := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			authorizations = append(
				authorizations,
				request.Header.Get("Authorization"),
			)
			requestPaths = append(requestPaths, request.URL.EscapedPath())
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(
				`{"metadata":{"uid":"pod-uid"}}`,
			))
		},
	))
	defer server.Close()
	client := &inClusterMetadataClient{
		baseURL: server.URL, tokenFile: tokenFile, http: server.Client(),
	}
	if _, err := client.Pod(context.Background(), "prod", "api"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("token-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Pod(context.Background(), "prod", "api"); err != nil {
		t.Fatal(err)
	}
	if len(authorizations) != 2 ||
		authorizations[0] != "Bearer token-one" ||
		authorizations[1] != "Bearer token-two" {
		t.Fatalf("authorization headers=%v", authorizations)
	}
	if len(requestPaths) != 2 ||
		requestPaths[0] != "/api/v1/namespaces/prod/pods/api" ||
		requestPaths[1] != "/api/v1/namespaces/prod/pods/api" {
		t.Fatalf("request paths=%v", requestPaths)
	}

	oversized := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write(bytes.Repeat(
				[]byte("x"),
				maxKubernetesAPIResponseBytes+1,
			))
		},
	))
	defer oversized.Close()
	client.baseURL = oversized.URL
	client.http = oversized.Client()
	if _, err := client.Pod(
		context.Background(),
		"prod",
		"api",
	); err == nil {
		t.Fatal("oversized Kubernetes API response accepted")
	}
}
