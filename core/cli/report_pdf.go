package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func writeReportPDF(path string, lines []string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o750); err != nil {
		return fmt.Errorf("mkdir report pdf dir: %w", err)
	}
	payload := renderSimplePDF(lines)
	if err := os.WriteFile(cleanPath, payload, 0o600); err != nil {
		return fmt.Errorf("write report pdf: %w", err)
	}
	return nil
}

func renderSimplePDF(lines []string) []byte {
	content := bytes.Buffer{}
	content.WriteString("BT\n/F1 12 Tf\n50 770 Td\n")
	for i, line := range lines {
		if i > 0 {
			content.WriteString("0 -16 Td\n")
		}
		content.WriteString("(")
		content.WriteString(escapePDFLine(line))
		content.WriteString(") Tj\n")
	}
	content.WriteString("ET\n")

	stream := content.String()
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
	}

	out := bytes.Buffer{}
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		_, _ = fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}

	xrefOffset := out.Len()
	_, _ = fmt.Fprintf(&out, "xref\n0 %d\n", len(objects)+1)
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		_, _ = fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	_, _ = fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefOffset)
	return out.Bytes()
}

func escapePDFLine(in string) string {
	normalized := strings.ReplaceAll(in, "\n", " ")
	normalized = strings.TrimSpace(normalized)
	if len(normalized) > 110 {
		normalized = normalized[:110]
	}
	normalized = strings.ReplaceAll(normalized, "\\", "\\\\")
	normalized = strings.ReplaceAll(normalized, "(", "\\(")
	normalized = strings.ReplaceAll(normalized, ")", "\\)")
	return normalized
}
