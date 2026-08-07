//go:build !windows

package statelock

import (
	"strings"
	"testing"
)

func TestOwnerMetadataFileRejectsNegativeDescriptor(t *testing.T) {
	file, err := ownerMetadataFileFromDescriptor(-1, "owner.json")
	if err == nil {
		if file != nil {
			_ = file.Close()
		}
		t.Fatal("ownerMetadataFileFromDescriptor() error = nil, want invalid descriptor rejection")
	}
	if file != nil {
		t.Fatalf("ownerMetadataFileFromDescriptor() file = %v, want nil", file)
	}
	if !strings.Contains(err.Error(), "invalid descriptor") {
		t.Fatalf("ownerMetadataFileFromDescriptor() error = %v, want invalid descriptor", err)
	}
}
