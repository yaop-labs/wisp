package filelog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yaop-labs/reef/tlsconf"

	"github.com/yaop-labs/wisp/internal/httpx"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

const (
	defaultKubernetesAPITimeout   = 2 * time.Second
	defaultKubernetesCacheTTL     = 5 * time.Minute
	defaultKubernetesStaleAfter   = time.Hour
	defaultKubernetesFailureRetry = 30 * time.Second
	defaultKubernetesMaxPods      = 10_000
	defaultKubernetesWorkers      = 2
	maxKubernetesAPIResponseBytes = 1 << 20
	maxServiceAccountTokenBytes   = 16 << 10
	serviceAccountTokenFile       = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: well-known projected service-account token path
	serviceAccountCAFile          = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type KubernetesAPIConfig struct {
	Timeout      time.Duration
	CacheTTL     time.Duration
	StaleAfter   time.Duration
	FailureRetry time.Duration
	MaxPods      int
	Workers      int
	Labels       []string

	client kubernetesMetadataClient
}

type kubernetesMetadataClient interface {
	Pod(context.Context, string, string) (apiPod, error)
	Owner(context.Context, string, ownerReference) (apiOwner, error)
}

type kubernetesAPIResolver struct {
	cfg    KubernetesAPIConfig
	client kubernetesMetadataClient
	queue  chan kubernetesPathMetadata
	now    func() time.Time

	mu        sync.Mutex
	cache     map[string]kubernetesCacheEntry
	pending   map[string]struct{}
	startOnce sync.Once
}

type kubernetesCacheEntry struct {
	attributes map[string]string
	refreshAt  time.Time
	staleAt    time.Time
	lastUsed   time.Time
}

func newKubernetesAPIResolver(
	cfg *KubernetesAPIConfig,
) (*kubernetesAPIResolver, error) {
	if cfg == nil {
		return nil, nil
	}
	value := *cfg
	value.Labels = append([]string(nil), cfg.Labels...)
	if value.Timeout <= 0 {
		value.Timeout = defaultKubernetesAPITimeout
	}
	if value.CacheTTL <= 0 {
		value.CacheTTL = defaultKubernetesCacheTTL
	}
	if value.StaleAfter <= 0 {
		value.StaleAfter = defaultKubernetesStaleAfter
	}
	if value.FailureRetry <= 0 {
		value.FailureRetry = defaultKubernetesFailureRetry
	}
	if value.MaxPods <= 0 {
		value.MaxPods = defaultKubernetesMaxPods
	}
	if value.Workers <= 0 {
		value.Workers = defaultKubernetesWorkers
	}
	if value.Timeout < 100*time.Millisecond ||
		value.Timeout > 30*time.Second ||
		value.CacheTTL < time.Second ||
		value.CacheTTL > 24*time.Hour ||
		value.StaleAfter < value.CacheTTL ||
		value.StaleAfter > 7*24*time.Hour ||
		value.FailureRetry < time.Second ||
		value.FailureRetry > time.Hour ||
		value.MaxPods < 1 || value.MaxPods > 100_000 ||
		value.Workers < 1 || value.Workers > 16 ||
		len(value.Labels) > 32 {
		return nil, fmt.Errorf("filelog: invalid Kubernetes API bounds")
	}
	seenLabels := make(map[string]struct{}, len(value.Labels))
	for _, label := range value.Labels {
		if !validKubernetesMetadataLabelKey(label) {
			return nil, fmt.Errorf("filelog: invalid Kubernetes label key")
		}
		if _, exists := seenLabels[label]; exists {
			return nil, fmt.Errorf("filelog: duplicate Kubernetes label key")
		}
		seenLabels[label] = struct{}{}
	}
	client := value.client
	if client == nil {
		var err error
		client, err = newInClusterMetadataClient()
		if err != nil {
			return nil, err
		}
	}
	return &kubernetesAPIResolver{
		cfg: value, client: client,
		queue:   make(chan kubernetesPathMetadata, value.Workers*64),
		now:     time.Now,
		cache:   make(map[string]kubernetesCacheEntry),
		pending: make(map[string]struct{}),
	}, nil
}

func validKubernetesMetadataLabelKey(value string) bool {
	if strings.Count(value, "/") > 1 {
		return false
	}
	prefix, name, qualified := strings.Cut(value, "/")
	if !qualified {
		name = prefix
		prefix = ""
	}
	if name == "" || len(name) > 63 ||
		!kubernetesLabelNameEdge(name[0]) ||
		!kubernetesLabelNameEdge(name[len(name)-1]) {
		return false
	}
	for index := 1; index < len(name)-1; index++ {
		value := name[index]
		if !kubernetesLabelNameEdge(value) &&
			value != '-' && value != '_' && value != '.' {
			return false
		}
	}
	if prefix == "" {
		return true
	}
	return validDNSSubdomain(prefix)
}

func kubernetesLabelNameEdge(value byte) bool {
	return asciiLowercaseAlphanumeric(value) ||
		value >= 'A' && value <= 'Z'
}

func (r *kubernetesAPIResolver) start(ctx context.Context) {
	if r == nil {
		return
	}
	r.startOnce.Do(func() {
		for range r.cfg.Workers {
			go r.worker(ctx)
		}
	})
}

func (r *kubernetesAPIResolver) close() {
	if r == nil {
		return
	}
	if closer, ok := r.client.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (r *kubernetesAPIResolver) size() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

func (r *kubernetesAPIResolver) lookup(
	metadata kubernetesPathMetadata,
) map[string]string {
	if r == nil {
		return nil
	}
	now := r.now()
	key := metadata.podUID
	r.mu.Lock()
	entry, exists := r.cache[key]
	if exists {
		entry.lastUsed = now
		r.cache[key] = entry
	}
	needsRefresh := !exists || !now.Before(entry.refreshAt)
	if needsRefresh {
		r.scheduleLocked(metadata)
	}
	var attributes map[string]string
	if exists && len(entry.attributes) > 0 && now.Before(entry.staleAt) {
		attributes = cloneStrings(entry.attributes)
		if !now.Before(entry.refreshAt) {
			attributes["wisp.kubernetes.api.stale"] = "true"
			selfobs.FileLogKubernetesAPIStaleHits.Inc()
		} else {
			selfobs.FileLogKubernetesAPICacheHits.Inc()
		}
	} else {
		selfobs.FileLogKubernetesAPICacheMisses.Inc()
	}
	r.mu.Unlock()
	return attributes
}

func (r *kubernetesAPIResolver) scheduleLocked(
	metadata kubernetesPathMetadata,
) {
	if _, exists := r.pending[metadata.podUID]; exists {
		return
	}
	select {
	case r.queue <- metadata:
		r.pending[metadata.podUID] = struct{}{}
	default:
		selfobs.FileLogKubernetesAPIQueueDrops.Inc()
	}
}

func (r *kubernetesAPIResolver) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case metadata := <-r.queue:
			r.refresh(ctx, metadata)
		}
	}
}

func (r *kubernetesAPIResolver) refresh(
	parent context.Context,
	metadata kubernetesPathMetadata,
) {
	ctx, cancel := context.WithTimeout(parent, r.cfg.Timeout)
	defer cancel()
	attributes, err := r.fetch(ctx, metadata)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, metadata.podUID)
	if err != nil {
		selfobs.FileLogKubernetesAPIErrors.Inc()
		entry := r.cache[metadata.podUID]
		entry.refreshAt = now.Add(r.cfg.FailureRetry)
		entry.lastUsed = now
		if entry.staleAt.IsZero() {
			entry.staleAt = now
		}
		r.insertLocked(metadata.podUID, entry)
		return
	}
	r.insertLocked(metadata.podUID, kubernetesCacheEntry{
		attributes: attributes,
		refreshAt:  now.Add(r.cfg.CacheTTL),
		staleAt:    now.Add(r.cfg.StaleAfter),
		lastUsed:   now,
	})
	selfobs.FileLogKubernetesAPIRefreshes.Inc()
}

func (r *kubernetesAPIResolver) insertLocked(
	key string,
	entry kubernetesCacheEntry,
) {
	if _, exists := r.cache[key]; !exists && len(r.cache) >= r.cfg.MaxPods {
		var (
			oldestKey  string
			oldestTime time.Time
		)
		for candidate, value := range r.cache {
			if oldestKey == "" || value.lastUsed.Before(oldestTime) {
				oldestKey, oldestTime = candidate, value.lastUsed
			}
		}
		delete(r.cache, oldestKey)
		selfobs.FileLogKubernetesAPIEvictions.Inc()
	}
	r.cache[key] = entry
}

func (r *kubernetesAPIResolver) fetch(
	ctx context.Context,
	metadata kubernetesPathMetadata,
) (map[string]string, error) {
	pod, err := r.client.Pod(ctx, metadata.namespace, metadata.podName)
	if err != nil {
		return nil, err
	}
	if pod.Metadata.UID != metadata.podUID {
		selfobs.FileLogKubernetesAPIUIDMismatches.Inc()
		return nil, fmt.Errorf("kubernetes API pod UID does not match log path")
	}
	attributes := map[string]string{}
	if pod.Spec.NodeName != "" {
		attributes["k8s.node.name"] = boundedMetadata(pod.Spec.NodeName)
	}
	for _, label := range r.cfg.Labels {
		if value, exists := pod.Metadata.Labels[label]; exists {
			attributes["k8s.pod.label."+label] = boundedMetadata(value)
		}
	}
	enrichContainer(attributes, pod, metadata.container)
	owner, ok := controllingOwner(pod.Metadata.OwnerReferences)
	if ok {
		enrichOwner(attributes, owner)
		switch owner.Kind {
		case "ReplicaSet", "Job":
			parent, parentErr := r.client.Owner(
				ctx,
				metadata.namespace,
				owner,
			)
			if parentErr == nil {
				if parentOwner, found := controllingOwner(
					parent.Metadata.OwnerReferences,
				); found {
					enrichOwner(attributes, parentOwner)
				}
			} else {
				selfobs.FileLogKubernetesAPIOwnerErrors.Inc()
			}
		}
	}
	return attributes, nil
}

func cloneStrings(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func boundedMetadata(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return '\uFFFD'
		}
		return character
	}, value)
	if len(value) > 4096 {
		value = value[:4096]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

type objectMetadata struct {
	UID             string            `json:"uid"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []ownerReference  `json:"ownerReferences"`
}

type ownerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller"`
}

type apiPod struct {
	Metadata objectMetadata `json:"metadata"`
	Spec     struct {
		NodeName            string         `json:"nodeName"`
		Containers          []apiContainer `json:"containers"`
		InitContainers      []apiContainer `json:"initContainers"`
		EphemeralContainers []apiContainer `json:"ephemeralContainers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses          []apiContainerStatus `json:"containerStatuses"`
		InitContainerStatuses      []apiContainerStatus `json:"initContainerStatuses"`
		EphemeralContainerStatuses []apiContainerStatus `json:"ephemeralContainerStatuses"`
	} `json:"status"`
}

type apiContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type apiContainerStatus struct {
	Name        string `json:"name"`
	Image       string `json:"image"`
	ImageID     string `json:"imageID"`
	ContainerID string `json:"containerID"`
}

type apiOwner struct {
	Metadata objectMetadata `json:"metadata"`
}

func controllingOwner(values []ownerReference) (ownerReference, bool) {
	for _, value := range values {
		if value.Controller != nil && *value.Controller {
			return value, true
		}
	}
	return ownerReference{}, false
}

func enrichOwner(attributes map[string]string, owner ownerReference) {
	keys := map[string]string{
		"Deployment":  "k8s.deployment.name",
		"ReplicaSet":  "k8s.replicaset.name",
		"StatefulSet": "k8s.statefulset.name",
		"DaemonSet":   "k8s.daemonset.name",
		"Job":         "k8s.job.name",
		"CronJob":     "k8s.cronjob.name",
	}
	if key := keys[owner.Kind]; key != "" && owner.Name != "" {
		attributes[key] = boundedMetadata(owner.Name)
	}
}

func enrichContainer(
	attributes map[string]string,
	pod apiPod,
	containerName string,
) {
	containers := append(
		append(
			append([]apiContainer(nil), pod.Spec.Containers...),
			pod.Spec.InitContainers...,
		),
		pod.Spec.EphemeralContainers...,
	)
	for _, container := range containers {
		if container.Name == containerName {
			name := imageName(container.Image)
			if name != "" {
				attributes["container.image.name"] = boundedMetadata(name)
			}
			break
		}
	}
	statuses := append(
		append(
			append(
				[]apiContainerStatus(nil),
				pod.Status.ContainerStatuses...,
			),
			pod.Status.InitContainerStatuses...,
		),
		pod.Status.EphemeralContainerStatuses...,
	)
	for _, status := range statuses {
		if status.Name != containerName {
			continue
		}
		if status.ContainerID != "" {
			_, id, _ := strings.Cut(status.ContainerID, "://")
			if id == "" {
				id = status.ContainerID
			}
			attributes["container.id"] = boundedMetadata(id)
		}
		if status.ImageID != "" {
			attributes["container.image.id"] = boundedMetadata(status.ImageID)
			if digest := imageDigest(status.ImageID); digest != "" {
				attributes["oci.manifest.digest"] = digest
			}
		}
		if _, exists := attributes["container.image.name"]; !exists {
			name := imageName(status.Image)
			if name != "" {
				attributes["container.image.name"] = boundedMetadata(name)
			}
		}
		break
	}
}

func imageName(value string) string {
	if index := strings.IndexByte(value, '@'); index >= 0 {
		return value[:index]
	}
	slash := strings.LastIndexByte(value, '/')
	colon := strings.LastIndexByte(value, ':')
	if colon > slash {
		return value[:colon]
	}
	return value
}

func imageDigest(value string) string {
	if index := strings.LastIndexByte(value, '@'); index >= 0 {
		return boundedMetadata(value[index+1:])
	}
	return ""
}

type inClusterMetadataClient struct {
	baseURL   string
	tokenFile string
	http      *http.Client
}

func newInClusterMetadataClient() (*inClusterMetadataClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf(
			"filelog: Kubernetes API enrichment requires in-cluster service environment",
		)
	}
	token, err := readBoundedFile(
		serviceAccountTokenFile,
		maxServiceAccountTokenBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("filelog: Kubernetes service token: %w", err)
	}
	if strings.TrimSpace(string(token)) == "" {
		return nil, fmt.Errorf("filelog: Kubernetes service token is empty")
	}
	tlsConfig, err := tlsconf.Client(&tlsconf.ClientConfig{
		Enabled: true,
		CAFile:  serviceAccountCAFile,
	})
	if err != nil {
		return nil, fmt.Errorf("filelog: Kubernetes service CA: %w", err)
	}
	return &inClusterMetadataClient{
		baseURL:   "https://" + net.JoinHostPort(host, port),
		tokenFile: serviceAccountTokenFile,
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			CheckRedirect: func(
				_ *http.Request,
				_ []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *inClusterMetadataClient) Pod(
	ctx context.Context,
	namespace string,
	name string,
) (apiPod, error) {
	var pod apiPod
	err := c.get(
		ctx,
		path.Join("/api/v1/namespaces", namespace, "pods", name),
		&pod,
	)
	return pod, err
}

func (c *inClusterMetadataClient) Owner(
	ctx context.Context,
	namespace string,
	owner ownerReference,
) (apiOwner, error) {
	var value apiOwner
	var resourcePath string
	switch owner.Kind {
	case "ReplicaSet":
		if !validDNSSubdomain(owner.Name) ||
			!validKubernetesUID(owner.UID) {
			return value, fmt.Errorf("invalid Kubernetes ReplicaSet owner")
		}
		resourcePath = path.Join(
			"/apis/apps/v1/namespaces",
			namespace,
			"replicasets",
			owner.Name,
		)
	case "Job":
		if !validDNSSubdomain(owner.Name) ||
			!validKubernetesUID(owner.UID) {
			return value, fmt.Errorf("invalid Kubernetes Job owner")
		}
		resourcePath = path.Join(
			"/apis/batch/v1/namespaces",
			namespace,
			"jobs",
			owner.Name,
		)
	default:
		return value, fmt.Errorf("unsupported Kubernetes owner kind")
	}
	err := c.get(ctx, resourcePath, &value)
	if err == nil && owner.UID != "" && value.Metadata.UID != owner.UID {
		return apiOwner{}, fmt.Errorf("kubernetes owner UID mismatch")
	}
	return value, err
}

func (c *inClusterMetadataClient) get(
	ctx context.Context,
	requestPath string,
	output any,
) error {
	token, err := readBoundedFile(c.tokenFile, maxServiceAccountTokenBytes)
	if err != nil {
		return fmt.Errorf("read Kubernetes service account token: %w", err)
	}
	if len(token) == 0 {
		return fmt.Errorf("kubernetes service account token has invalid size")
	}
	requestURL, err := url.JoinPath(c.baseURL, requestPath)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		requestURL,
		nil,
	)
	if err != nil {
		return err
	}
	tokenValue := strings.TrimSpace(string(token))
	if tokenValue == "" {
		return fmt.Errorf("kubernetes service account token is empty")
	}
	request.Header.Set("Authorization", "Bearer "+tokenValue)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"kubernetes API: %w",
			httpx.ErrorFromResponse(response),
		)
	}
	data, err := io.ReadAll(
		io.LimitReader(response.Body, maxKubernetesAPIResponseBytes+1),
	)
	if err != nil {
		return fmt.Errorf("read Kubernetes API response: %w", err)
	}
	if len(data) > maxKubernetesAPIResponseBytes {
		return fmt.Errorf("kubernetes API response exceeds bounds")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode Kubernetes API response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("kubernetes API response exceeds bounds or has trailing JSON")
	}
	return nil
}

func (c *inClusterMetadataClient) CloseIdleConnections() {
	c.http.CloseIdleConnections()
}

func readBoundedFile(filePath string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return value, nil
}
