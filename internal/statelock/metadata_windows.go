//go:build windows

package statelock

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func openOwnerMetadataForWrite(path string) (*os.File, error) {
	return openOwnerMetadataFile(path, windows.GENERIC_WRITE, windows.OPEN_ALWAYS, true)
}

func openOwnerMetadataForRead(path string) (*os.File, error) {
	return openOwnerMetadataFile(path, windows.GENERIC_READ, windows.OPEN_EXISTING, false)
}

func openOwnerMetadataFile(path string, access uint32, createMode uint32, truncate bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode owner metadata path: %w", err)
	}
	handle, err := windows.CreateFile(
		name,
		access,
		0,
		nil,
		createMode,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open owner metadata without following links: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("stat owner metadata: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("owner metadata must be a single-link regular file: %s", path)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
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
