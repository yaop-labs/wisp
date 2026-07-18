//go:build linux

package filelog

import (
	"fmt"
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("filelog: unsupported Linux stat payload %T", info.Sys())
	}
	return fmt.Sprintf("%x:%x", stat.Dev, stat.Ino), nil
}
