# Custom Detector Extensions

Wrkr supports deterministic file-based detector extensions via repository-local descriptor files.

## Descriptor path

- `.wrkr/detectors/extensions.json`

## Schema contract

- Schema: `schemas/v1/findings/extension-detectors.schema.json`
- Version field is required and currently `v1`.

## Example

```json
{
  "version": "v1",
  "detectors": [
    {
      "id": "custom_mcp_review",
      "finding_type": "custom_mcp_review_required",
      "tool_type": "custom_detector",
      "location": ".mcp.json",
      "severity": "medium",
      "remediation": "Review custom MCP trust posture before approval.",
      "permissions": ["mcp.access"],
      "evidence": [
        {"key": "owner", "value": "security-team"}
      ]
    }
  ]
}
```

## Determinism and failure behavior

- Descriptors are loaded and validated with strict typed parsing.
- Descriptor IDs are deterministically ordered before emission.
- Invalid descriptors fail closed as detector errors with stable code/class (`invalid_extension_descriptor`, `extension`).
- Extension findings are additive and do not bypass built-in detector/risk/proof boundaries.
