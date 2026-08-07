//go:build !windows

package statelock

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openOwnerMetadataForWrite(path string) (*os.File, error) {
	return openOwnerMetadataFile(path, unix.O_WRONLY|unix.O_CREAT, true)
}

func openOwnerMetadataForRead(path string) (*os.File, error) {
	return openOwnerMetadataFile(path, unix.O_RDONLY, false)
}

func openOwnerMetadataFile(path string, flags int, truncate bool) (*os.File, error) {
	// #nosec G304 -- metadata path is derived from the caller-selected managed state directory.
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open owner metadata without following links: %w", err)
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("stat owner metadata: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("owner metadata must be a single-link regular file: %s", path)
	}
	file, err := ownerMetadataFileFromDescriptor(fd, path)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open owner metadata file: %s", path)
	}
	if truncate {
		if err := file.Truncate(0); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("truncate owner metadata: %w", err)
		}
	}
	return file, nil
}

func ownerMetadataFileFromDescriptor(fd int, path string) (*os.File, error) {
	if fd < 0 {
		return nil, fmt.Errorf("open owner metadata file: invalid descriptor")
	}
	return os.NewFile(uintptr(fd), path), nil
}
