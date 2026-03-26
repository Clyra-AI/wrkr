package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pdfLineWidthChars = 88
	pdfLinesPerPage   = 44
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
	wrapped := wrapPDFLines(lines, pdfLineWidthChars)
	pages := paginatePDFLines(wrapped, pdfLinesPerPage)
	if len(pages) == 0 {
		pages = [][]string{{}}
	}

	pageObjectNums := make([]int, 0, len(pages))
	contentObjectNums := make([]int, 0, len(pages))
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
	}
	pageCount := len(pages)
	for idx := 0; idx < pageCount; idx++ {
		pageObjectNums = append(pageObjectNums, 4+(idx*2))
		contentObjectNums = append(contentObjectNums, 5+(idx*2))
	}

	kids := make([]string, 0, len(pageObjectNums))
	for _, num := range pageObjectNums {
		kids = append(kids, fmt.Sprintf("%d 0 R", num))
	}
	objects = append(objects, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pageCount))
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	for idx, page := range pages {
		stream := renderPDFPage(page)
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", contentObjectNums[idx]))
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream))
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

func renderPDFPage(lines []string) string {
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
	return content.String()
}

func wrapPDFLines(lines []string, maxChars int) []string {
	if maxChars <= 0 {
		maxChars = pdfLineWidthChars
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, wrapPDFLine(line, maxChars)...)
	}
	return out
}

func wrapPDFLine(in string, maxChars int) []string {
	normalized := normalizePDFLine(in)
	if normalized == "" {
		return nil
	}
	words := strings.Fields(normalized)
	if len(words) == 0 {
		return nil
	}

	out := make([]string, 0, 4)
	current := ""
	flush := func() {
		if strings.TrimSpace(current) != "" {
			out = append(out, strings.TrimSpace(current))
		}
		current = ""
	}

	for _, word := range words {
		if len(word) > maxChars {
			flush()
			out = append(out, splitLongWord(word, maxChars)...)
			continue
		}
		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if len(candidate) > maxChars {
			flush()
			current = word
			continue
		}
		current = candidate
	}
	flush()
	return out
}

func splitLongWord(word string, maxChars int) []string {
	if maxChars <= 0 || len(word) <= maxChars {
		return []string{word}
	}
	out := make([]string, 0, (len(word)/maxChars)+1)
	for start := 0; start < len(word); start += maxChars {
		end := start + maxChars
		if end > len(word) {
			end = len(word)
		}
		out = append(out, word[start:end])
	}
	return out
}

func paginatePDFLines(lines []string, linesPerPage int) [][]string {
	if linesPerPage <= 0 {
		linesPerPage = pdfLinesPerPage
	}
	if len(lines) == 0 {
		return nil
	}
	pages := make([][]string, 0, (len(lines)/linesPerPage)+1)
	for start := 0; start < len(lines); start += linesPerPage {
		end := start + linesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, append([]string(nil), lines[start:end]...))
	}
	return pages
}

func normalizePDFLine(in string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(in), "\n", " ")), " ")
}

func escapePDFLine(in string) string {
	normalized := normalizePDFLine(in)
	normalized = strings.ReplaceAll(normalized, "\\", "\\\\")
	normalized = strings.ReplaceAll(normalized, "(", "\\(")
	normalized = strings.ReplaceAll(normalized, ")", "\\)")
	return normalized
}
