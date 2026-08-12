package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunShapeReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shape.json")
	if err := os.WriteFile(path, []byte(`{"repositories":96,"jenkins_files":60}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--input", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"repositories"`) {
		t.Fatalf("unexpected receipt: %s", stdout.String())
	}
}

func TestRunShapeReceiptFailures(t *testing.T) {
	var output bytes.Buffer
	if code := run(nil, &output, &output); code != 2 {
		t.Fatalf("missing input code=%d", code)
	}
	if code := run([]string{"--unknown"}, &output, &output); code != 2 {
		t.Fatalf("parse failure code=%d", code)
	}
	if code := run([]string{"--input", filepath.Join(t.TempDir(), "missing")}, &output, &output); code != 1 {
		t.Fatalf("read failure code=%d", code)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--input", path}, &output, &output); code != 1 {
		t.Fatalf("decode failure code=%d", code)
	}
	if err := os.WriteFile(path, []byte(`{"repositories":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--input", path}, failingWriter{}, &output); code != 1 {
		t.Fatalf("encode failure code=%d", code)
	}
}
