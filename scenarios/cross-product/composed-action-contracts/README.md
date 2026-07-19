# Legacy Composed Action Contract Fixture Pointer

The former hand-authored Gait validation and Axym correlation projections have
been removed. They were illustrative shapes, not exact production Wrkr output,
and are no longer an authoritative interoperability contract.

Use `scenarios/cross-product/action-contract-interop/` instead. Its artifacts
and packet views are produced by a real Wrkr scan/state/export pipeline,
validated by schema and digest, regenerated into temporary storage for exact
byte comparison, and passed unchanged to external Gait/Axym consumers.
