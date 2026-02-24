package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultAdvisoryEndpoint = "https://api.osv.dev/v1/query"
	defaultRegistryBase     = "https://registry.modelcontextprotocol.io"
	maxLookupAttempts       = 2
	legacyRegistrySchema    = "registry/http-status.v0"
)

func NewDefault() Service {
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	advisoryEndpoint := strings.TrimSpace(os.Getenv("WRKR_MCP_ENRICH_ADVISORY_ENDPOINT"))
	if advisoryEndpoint == "" {
		advisoryEndpoint = defaultAdvisoryEndpoint
	}
	registryBase := strings.TrimSpace(os.Getenv("WRKR_MCP_ENRICH_REGISTRY_BASE"))
	if registryBase == "" {
		registryBase = defaultRegistryBase
	}
	return Service{
		Advisories: OSVAdvisoryClient{
			HTTPClient: client,
			Endpoint:   advisoryEndpoint,
		},
		Registry: MCPRegistryClient{
			HTTPClient: client,
			BaseURL:    registryBase,
		},
	}
}

type OSVAdvisoryClient struct {
	HTTPClient *http.Client
	Endpoint   string
}

func (c OSVAdvisoryClient) Lookup(ctx context.Context, pkg string, version string) (AdvisoryResult, error) {
	endpoint := strings.TrimSpace(c.Endpoint)
	if endpoint == "" {
		return AdvisoryResult{Count: 0, Source: "disabled", Schema: "none", Fresh: false}, fmt.Errorf("advisory endpoint is empty")
	}
	body := map[string]any{
		"package": map[string]any{
			"name":      strings.TrimSpace(pkg),
			"ecosystem": inferEcosystem(pkg),
		},
	}
	if strings.TrimSpace(version) != "" {
		body["version"] = strings.TrimSpace(version)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return AdvisoryResult{Count: 0, Source: endpoint, Schema: "none", Fresh: false}, err
	}

	var lastErr error
	for attempt := 1; attempt <= maxLookupAttempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, doErr := c.httpClient().Do(req) // #nosec G107,G704 -- endpoint is explicit operator-configured advisory source for deterministic enrich mode.
		if doErr != nil {
			lastErr = doErr
			continue
		}
		responsePayload, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("advisory lookup status=%d", resp.StatusCode)
			continue
		}
		decoded, decodeErr := decodeOSVResponse(responsePayload)
		if decodeErr != nil {
			lastErr = decodeErr
			continue
		}
		return AdvisoryResult{
			Count:  decoded.Count,
			Source: endpoint,
			Schema: decoded.Schema,
			Fresh:  decoded.Fresh,
		}, nil
	}
	return AdvisoryResult{Count: 0, Source: endpoint, Schema: "none", Fresh: false}, lastErr
}

type decodedAdvisory struct {
	Count  int
	Schema string
	Fresh  bool
}

func decodeOSVResponse(payload []byte) (decodedAdvisory, error) {
	v1 := struct {
		Vulns []json.RawMessage `json:"vulns"`
	}{}
	if err := json.Unmarshal(payload, &v1); err == nil && v1.Vulns != nil {
		return decodedAdvisory{
			Count:  len(v1.Vulns),
			Schema: "osv/v1",
			Fresh:  true,
		}, nil
	}
	v2Compat := struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}{}
	if err := json.Unmarshal(payload, &v2Compat); err == nil && v2Compat.Vulnerabilities != nil {
		return decodedAdvisory{
			Count:  len(v2Compat.Vulnerabilities),
			Schema: "osv/v2_compat",
			Fresh:  false,
		}, nil
	}
	return decodedAdvisory{}, fmt.Errorf("advisory schema mismatch")
}

type MCPRegistryClient struct {
	HTTPClient *http.Client
	BaseURL    string
}

func (c MCPRegistryClient) Lookup(ctx context.Context, pkg string) (RegistryResult, error) {
	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		return RegistryResult{Status: "unknown", Source: "disabled", Schema: "none", Fresh: false}, fmt.Errorf("registry base url is empty")
	}
	trimmedPackage := strings.TrimSpace(pkg)
	if trimmedPackage == "" {
		return RegistryResult{Status: "unknown", Source: base, Schema: "none", Fresh: false}, nil
	}

	endpoint := strings.TrimRight(base, "/") + "/v0/servers/" + url.PathEscape(trimmedPackage)
	var lastErr error
	for attempt := 1; attempt <= maxLookupAttempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		resp, doErr := c.httpClient().Do(req) // #nosec G107,G704 -- endpoint is explicit operator-configured registry source for deterministic enrich mode.
		if doErr != nil {
			lastErr = doErr
			continue
		}
		responsePayload, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			schema, fresh, decodeErr := decodeRegistryResponse(responsePayload)
			if decodeErr != nil {
				lastErr = decodeErr
				continue
			}
			return RegistryResult{Status: "listed", Source: endpoint, Schema: schema, Fresh: fresh}, nil
		case http.StatusNotFound:
			// Treat 404 as authoritative unlisted even when body schema is unknown/plain-text.
			schema, fresh, decodeErr := decodeRegistryResponse(responsePayload)
			if decodeErr != nil {
				return RegistryResult{Status: "unlisted", Source: endpoint, Schema: legacyRegistrySchema, Fresh: false}, nil
			}
			return RegistryResult{Status: "unlisted", Source: endpoint, Schema: schema, Fresh: fresh}, nil
		default:
			lastErr = fmt.Errorf("registry lookup status=%d", resp.StatusCode)
		}
	}
	return RegistryResult{Status: "unknown", Source: endpoint, Schema: "none", Fresh: false}, lastErr
}

type registryEnvelope struct {
	SchemaVersion string `json:"schema_version"`
}

func decodeRegistryResponse(payload []byte) (string, bool, error) {
	if len(strings.TrimSpace(string(payload))) == 0 {
		return legacyRegistrySchema, false, nil
	}
	envelope := registryEnvelope{}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", false, fmt.Errorf("registry schema mismatch")
	}
	switch strings.ToLower(strings.TrimSpace(envelope.SchemaVersion)) {
	case "":
		return legacyRegistrySchema, false, nil
	case "v1":
		return "registry/v1", true, nil
	case "v0":
		return "registry/v0", false, nil
	default:
		return "", false, fmt.Errorf("unsupported registry schema_version=%s", envelope.SchemaVersion)
	}
}

func inferEcosystem(pkg string) string {
	trimmed := strings.TrimSpace(pkg)
	if strings.HasPrefix(trimmed, "github.com/") {
		return "Go"
	}
	if strings.Contains(trimmed, "pypi") {
		return "PyPI"
	}
	return "npm"
}

func (c OSVAdvisoryClient) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return &http.Client{Timeout: 2 * time.Second}
	}
	return c.HTTPClient
}

func (c MCPRegistryClient) httpClient() *http.Client {
	if c.HTTPClient == nil {
		return &http.Client{Timeout: 2 * time.Second}
	}
	return c.HTTPClient
}
