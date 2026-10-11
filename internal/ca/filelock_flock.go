//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package ca

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// acquireFileLock takes an exclusive kernel lock on a permanent file. Keeping
// the file avoids inode-replacement races; closing the descriptor releases the
// lock automatically, including when the process exits unexpectedly.
func acquireFileLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ca: open lock %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("ca: secure lock %s: %w", path, err)
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("ca: lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
