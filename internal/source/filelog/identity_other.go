//go:build !linux

package filelog

import (
	"fmt"
	"os"
)

func fileIdentity(os.FileInfo) (string, error) {
	return "", fmt.Errorf("filelog: durable file identity requires Linux")
}
