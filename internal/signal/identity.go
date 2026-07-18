package signal

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

var identityKeys = map[string]struct{}{
	"service.name": {}, "service.namespace": {}, "service.instance.id": {},
	"service.version": {}, "deployment.environment.name": {},
	"host.id": {}, "host.name": {}, "process.pid": {},
	"process.executable.name": {}, "process.executable.path": {},
	"process.executable.build_id.gnu": {}, "process.executable.build_id.go": {},
	"process.runtime.name": {}, "process.runtime.version": {},
	"container.id": {}, "container.name": {}, "k8s.cluster.name": {},
	"k8s.namespace.name": {}, "k8s.node.name": {}, "k8s.pod.name": {},
	"k8s.pod.uid": {}, "k8s.container.name": {}, "k8s.deployment.name": {},
	"k8s.replicaset.name": {}, "k8s.statefulset.name": {},
	"k8s.daemonset.name": {}, "k8s.job.name": {}, "k8s.cronjob.name": {},
	"wisp.profile.executable.build_id": {}, "wisp.profile.executable.debug_name": {},
}

// ResourceIdentity filters an OTLP-style attribute map down to bounded
// correlation and symbolization identity. False means an allowlisted value was
// unsafe to duplicate into envelope metadata; callers should omit identity but
// keep the telemetry payload.
func ResourceIdentity(attributes map[string]string) (map[string]string, bool) {
	out := make(map[string]string)
	for key, value := range attributes {
		if _, keep := identityKeys[key]; !keep {
			continue
		}
		if len(value) > maxResourceValueBytes || !utf8.ValidString(value) ||
			strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, false
		}
		out[key] = value
	}
	return out, true
}

func IsIdentityKey(key string) bool {
	_, ok := identityKeys[key]
	return ok
}
