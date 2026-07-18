package host

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/yaop-labs/wisp/internal/model"
)

const (
	maxHostnameBytes  = 253
	maxOSReleaseBytes = 64 << 10
	maxMachineIDBytes = 256
)

// DetectResource fills missing host and OS semantic attributes. Explicit
// resource attributes always win. Detection errors are fail-open and contain
// no detected values, so callers can log them without leaking machine IDs.
func DetectResource(
	base model.Labels,
	paths Paths,
	explicit map[string]string,
	includeHostID bool,
) (model.Labels, []error) {
	paths = normalizedPaths(paths)
	attributes := make(map[string]string, len(base)+6)
	for _, label := range base {
		attributes[label.Name] = label.Value
	}
	var detectionErrors []error

	if _, configured := explicit["host.name"]; !configured {
		hostname, err := detectHostname(paths.RootFS)
		if err != nil {
			detectionErrors = append(
				detectionErrors,
				fmt.Errorf("host.name: %w", err),
			)
		} else {
			attributes["host.name"] = hostname
		}
	}
	if _, configured := explicit["host.arch"]; !configured {
		arch, err := detectHostArch()
		if err != nil {
			detectionErrors = append(
				detectionErrors,
				fmt.Errorf("host.arch: %w", err),
			)
		} else {
			attributes["host.arch"] = arch
		}
	}
	if _, configured := explicit["os.type"]; !configured {
		attributes["os.type"] = "linux"
	}
	needOSRelease := false
	for _, key := range []string{
		"os.name",
		"os.version",
		"os.description",
	} {
		if _, configured := explicit[key]; !configured {
			needOSRelease = true
			break
		}
	}
	if needOSRelease {
		osRelease, err := detectOSRelease(paths.RootFS)
		if err != nil {
			detectionErrors = append(
				detectionErrors,
				fmt.Errorf("os release: %w", err),
			)
		} else {
			for key, value := range map[string]string{
				"os.name":        osRelease["NAME"],
				"os.version":     osRelease["VERSION_ID"],
				"os.description": osRelease["PRETTY_NAME"],
			} {
				if _, configured := explicit[key]; !configured &&
					value != "" {
					attributes[key] = value
				}
			}
		}
	}
	if includeHostID {
		if _, configured := explicit["host.id"]; !configured {
			hostID, err := detectMachineID(paths.RootFS)
			if err != nil {
				detectionErrors = append(
					detectionErrors,
					fmt.Errorf("host.id: %w", err),
				)
			} else {
				attributes["host.id"] = hostID
			}
		}
	}

	labels := make(model.Labels, 0, len(attributes))
	for _, name := range slices.Sorted(maps.Keys(attributes)) {
		labels = append(labels, model.Label{
			Name:  name,
			Value: attributes[name],
		})
	}
	return labels, detectionErrors
}

func detectHostname(root string) (string, error) {
	data, err := readBoundedFile(
		filepath.Join(root, "etc", "hostname"),
		maxHostnameBytes+2,
	)
	if err != nil {
		return "", err
	}
	hostname := strings.TrimSpace(string(data))
	if hostname == "" || len(hostname) > maxHostnameBytes ||
		strings.IndexFunc(hostname, unicode.IsSpace) >= 0 ||
		strings.IndexByte(hostname, 0) >= 0 {
		return "", errors.New("invalid hostname file")
	}
	return hostname, nil
}

func detectHostArch() (string, error) {
	var value unix.Utsname
	if err := unix.Uname(&value); err != nil {
		return "", err
	}
	machine := strings.ToLower(utsString(value.Machine))
	architectures := map[string]string{
		"x86_64":  "amd64",
		"amd64":   "amd64",
		"aarch64": "arm64",
		"arm64":   "arm64",
		"armv6l":  "arm32",
		"armv7l":  "arm32",
		"i386":    "x86",
		"i486":    "x86",
		"i586":    "x86",
		"i686":    "x86",
		"ia64":    "ia64",
		"ppc":     "ppc32",
		"ppc64":   "ppc64",
		"ppc64le": "ppc64",
		"s390x":   "s390x",
	}
	arch, exists := architectures[machine]
	if !exists {
		return "", fmt.Errorf("unsupported uname machine")
	}
	return arch, nil
}

func detectOSRelease(root string) (map[string]string, error) {
	var data []byte
	var err error
	for _, name := range []string{
		filepath.Join(root, "etc", "os-release"),
		filepath.Join(root, "usr", "lib", "os-release"),
	} {
		data, err = readBoundedFile(name, maxOSReleaseBytes)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || !validOSReleaseKey(key) {
			return nil, fmt.Errorf(
				"line %d is malformed",
				lineNumber+1,
			)
		}
		if key != "NAME" && key != "VERSION_ID" &&
			key != "PRETTY_NAME" {
			continue
		}
		value, err := parseOSReleaseValue(raw)
		if err != nil {
			return nil, fmt.Errorf(
				"line %d: %w",
				lineNumber+1,
				err,
			)
		}
		values[key] = value
	}
	if len(values) == 0 {
		return nil, errors.New("no supported os-release fields")
	}
	return values, nil
}

func validOSReleaseKey(key string) bool {
	if key == "" {
		return false
	}
	for _, value := range key {
		if (value < 'A' || value > 'Z') &&
			(value < '0' || value > '9') &&
			value != '_' {
			return false
		}
	}
	return true
}

func parseOSReleaseValue(raw string) (string, error) {
	if len(raw) > 4096 || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("os-release value exceeds bounds")
	}
	if strings.HasPrefix(raw, `"`) {
		if len(raw) < 2 || !strings.HasSuffix(raw, `"`) {
			return "", errors.New("invalid double-quoted value")
		}
		var value strings.Builder
		for index := 1; index < len(raw)-1; index++ {
			if raw[index] != '\\' {
				value.WriteByte(raw[index])
				continue
			}
			index++
			if index >= len(raw)-1 {
				return "", errors.New(
					"invalid double-quoted escape",
				)
			}
			switch raw[index] {
			case '"', '$', '\'', '\\', '`':
			default:
				return "", errors.New(
					"invalid double-quoted escape",
				)
			}
			value.WriteByte(raw[index])
		}
		return value.String(), nil
	}
	if strings.HasPrefix(raw, "'") {
		if len(raw) < 2 || !strings.HasSuffix(raw, "'") {
			return "", errors.New("invalid single-quoted value")
		}
		return raw[1 : len(raw)-1], nil
	}
	if strings.ContainsAny(raw, " \t\"'\\") {
		return "", errors.New("invalid unquoted value")
	}
	return raw, nil
}

func detectMachineID(root string) (string, error) {
	var lastErr error
	for _, name := range []string{
		filepath.Join(root, "etc", "machine-id"),
		filepath.Join(root, "var", "lib", "dbus", "machine-id"),
	} {
		data, err := readBoundedFile(name, maxMachineIDBytes)
		if err != nil {
			lastErr = err
			continue
		}
		value := strings.TrimSpace(string(data))
		if len(value) != 32 {
			lastErr = errors.New("machine-id has invalid length")
			continue
		}
		valid := true
		for _, character := range value {
			isDigit := character >= '0' && character <= '9'
			isLowerHex := character >= 'a' && character <= 'f'
			if !isDigit && !isLowerHex {
				valid = false
				break
			}
		}
		if !valid {
			lastErr = errors.New("machine-id has invalid format")
			continue
		}
		return value, nil
	}
	return "", lastErr
}
