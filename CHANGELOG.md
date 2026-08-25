# Changelog

## 1.0.0 (2026-08-19)

First stable release. Full compliance with `draft-drake-email-hardware-attestation-03`.

### Breaking changes

- **Authentication-Results output (Mode 2)**: property `header.trust_tier` renamed to
  `header.tier` per IANA registration in Section 8. New properties `header.mode`
  (`identified`/`hidden`) and `header.aid` (when disclosed) are now emitted.
- **SD-JWT `typ` header validation**: verifier now rejects SD-JWTs without
  `typ: airs-email+sd-jwt` (was previously unchecked).
- **`trust_tier` claim extraction**: verifier now extracts trust tier from nested
  `aid: {trust_tier: ...}` structure (was previously flat `trust_tier` claim).

### New features

- `is_identified_mode` flag on `Mode2VerificationResult` distinguishes identified
  vs hidden mode based on presence of `sub` claim.
- `rdap_issuer_verified` flag: when `sub` is present, verifier resolves the identity
  via AIRS RDAP and confirms `iss` matches the registry's `currentIssuer`.
- EdDSA (Ed25519) support added to Mode 1 CMS signature verification.

### Previous versions

- 0.5.0: Added RDAP resolution, `is_identified_mode`, nested `aid` claim parsing.
- 0.4.0: Added EdDSA CMS support.
- 0.3.0: Initial Mode 1 + Mode 2 verification with DNS key discovery.
