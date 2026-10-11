//go:build !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd

package ca

import (
	"fmt"
	"runtime"
)

func acquireFileLock(_ string) (func(), error) {
	return nil, fmt.Errorf("ca: persistent CA locking is unsupported on %s", runtime.GOOS)
}
