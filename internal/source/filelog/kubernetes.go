package filelog

import (
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxKubernetesNamespaceBytes = 63
	maxKubernetesNameBytes      = 253
	maxKubernetesUIDBytes       = 128
)

type kubernetesPathMetadata struct {
	namespace    string
	podName      string
	podUID       string
	container    string
	restartCount int64
}

func parseKubernetesPodLogPath(root, path string) (kubernetesPathMetadata, bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || filepath.IsAbs(relative) {
		return kubernetesPathMetadata{}, false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) != 3 || parts[0] == ".." || parts[1] == ".." ||
		parts[2] == ".." {
		return kubernetesPathMetadata{}, false
	}
	podParts := strings.Split(parts[0], "_")
	if len(podParts) != 3 ||
		!validDNSLabel(podParts[0]) ||
		!validDNSSubdomain(podParts[1]) ||
		!validKubernetesUID(podParts[2]) ||
		!validDNSLabel(parts[1]) {
		return kubernetesPathMetadata{}, false
	}
	restartText, _, found := strings.Cut(parts[2], ".log")
	if !found || restartText == "" {
		return kubernetesPathMetadata{}, false
	}
	restart, err := strconv.ParseUint(restartText, 10, 63)
	if err != nil {
		return kubernetesPathMetadata{}, false
	}
	suffix := strings.TrimPrefix(parts[2], restartText+".log")
	if suffix != "" && (!strings.HasPrefix(suffix, ".") ||
		!safeKubernetesPathValue(suffix, maxKubernetesUIDBytes)) {
		return kubernetesPathMetadata{}, false
	}
	return kubernetesPathMetadata{
		namespace:    podParts[0],
		podName:      podParts[1],
		podUID:       podParts[2],
		container:    parts[1],
		restartCount: int64(restart),
	}, true
}

func validDNSSubdomain(value string) bool {
	if value == "" || len(value) > maxKubernetesNameBytes {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func validDNSLabel(value string) bool {
	if value == "" || len(value) > maxKubernetesNamespaceBytes ||
		!asciiLowercaseAlphanumeric(value[0]) ||
		!asciiLowercaseAlphanumeric(value[len(value)-1]) {
		return false
	}
	for i := 1; i < len(value)-1; i++ {
		if !asciiLowercaseAlphanumeric(value[i]) && value[i] != '-' {
			return false
		}
	}
	return true
}

func asciiLowercaseAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validKubernetesUID(value string) bool {
	if !safeKubernetesPathValue(value, maxKubernetesUIDBytes) {
		return false
	}
	for i := range len(value) {
		char := value[i]
		if !asciiAlphanumeric(char) && char != '-' {
			return false
		}
	}
	return true
}

func asciiAlphanumeric(value byte) bool {
	return asciiLowercaseAlphanumeric(value) ||
		value >= 'A' && value <= 'Z'
}

func safeKubernetesPathValue(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && utf8.ValidString(value) &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}
