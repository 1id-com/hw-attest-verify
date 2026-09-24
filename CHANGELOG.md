# Changelog

## 2.0.1 (2026-09-24)

Implements the draft's trust paths and result names, so the appendix command
`python3 -m hw_attest_verify --auth-results --no-time-check --hostname mailpal.com < example.eml`
verifies the real examples with no trust store.

### Mode 1

- **Registrar-bound path needs no trust store (AUD-F20)**: a message with
  `aid` and `bind` passes on a verified Registrar binding; its chain only
  carries the proof key. Without `aid`/`bind` the manufacturer-rooted path
  (`trusted_root_certificates`) is still required. `registrar_binding_verified`
  and `manufacturer_rooted_path_verified` record which path(s) succeeded, and
  `trust_tier` / `agent_identity_urn` are reported only after a verified binding.
- **Binding authority from the Registry (AUD-F04)**: the `aid` is resolved at
  the AIRS Registry, `iss` must equal its `currentIssuer`, and the key comes only
  from that issuer's RFC 8414 metadata `jwks_uri` (new
  `current_issuer_resolver` argument; default AIRS RDAP).
- **Binding algorithms (AUD-F50)**: ES256, RS256 and PS256 (salt 32).
- **Malformed `cnf.jwk` fails (AUD-F77)** instead of skipping the signer-key check.
- **Freshness is policy (AUD-F49)**: a `ts` outside the window yields `policy`,
  not `fail`.

### Mode 2

- **Identified mode (AUD-F03)**: a disclosed `sub` is resolved before key
  discovery; no current issuer = `fail`, an unreachable Registry = `temperror`
  (was a silent pass).
- **Hidden mode (AUD-F16)**: only issuers in `trusted_hidden_mode_issuers`
  (CLI `--trust-hidden-issuer`) are used; others yield `policy`.
- **RFC 9901 disclosure processing (AUD-F52)**: nested `_sd` and array-element
  digests, duplicate digests, unreferenced disclosures, collisions, and
  selectively disclosed `iss`/`iat`/`exp`/`nonce`/`cnf` are handled.
  `process_sd_jwt_disclosures_per_rfc9901` replaces `_verify_and_extract_disclosures`.
- **`aid.trust_tier` must be disclosed (AUD-F17)**; **`kid` is required
  (AUD-F51)**; **ES256, RS256 and PS256** issuer signatures (AUD-F18).
- **Time rules (AUD-F49)**: a materially future `iat` and an expired `exp` fail;
  age and token lifetime limits yield `policy` (`max_proof_age_seconds`).
- **`cnf`**: recorded as `cnf_jwk_thumbprint`; a `cnf`-bearing presentation
  in a message without `Hardware-Attestation` fails.

### Combined mode (AUD-F19)

- New `apply_combined_mode_requirements_to_mode2_result(mode1, mode2)`: Mode 2
  passes only if Mode 1 passed, Mode 1 `h=` covers `Hardware-Trust-Proof`,
  `cnf.jwk` is the CMS signer key, a Mode 1 `aid` equals the disclosed `sub`,
  and the tiers agree. The CLI applies it; the MailPal milter does too.

### Results and discovery

- Both result classes carry `authentication_results_result`: `pass`, `fail`,
  `policy`, `temperror` or `permerror` (duplicates, malformed or unsupported
  input). The CLI prints it in the A-R lines.
- `TransientExternalLookupFailure` marks lookups that could not complete.
  Verification no longer uses the `_hwattest` DNS / `{domain}` JWKS discovery.
- `__version__` now matches the package version.

### Tests

- 223 tests (was 147), including the four real appendix emails verified
  offline with the Registry and issuer answers recorded on 2026-09-24.

## 2.0.0 (2026-09-24)

Wire change: both modes always cover nine header fields.

### Breaking changes

- **Always-covered fields**: Mode 1 `h=` MUST name, and Mode 2 always hashes,
  From, To, Subject, Date, Message-ID, Reply-To, MIME-Version, Content-Type and
  Content-Transfer-Encoding (was the first five). A listed field that is absent
  from the message contributes nothing (DKIM rule), so adding it later breaks
  verification.
- **Duplicates**: a message carrying any of the nine fields more than once fails
  both modes when the caller passes `ordered_header_pairs`, as the CLI and the
  MailPal milter do (`find_duplicate_singleton_header_field_names` in `parse.py`).
- **Mode 1 fallback without ordered header pairs** now selects exactly the
  fields named in `h=` (AUD-F44).
- **Mode 1 tag grammar follows the draft ABNF**: an unrecognized tag makes the
  field malformed (was ignored; AUD-F25); tags must appear in the order
  v, typ, alg, h, bh, ts, chain, [aid, bind] (AUD-F74); WSP/FWS inside the
  h, bh, ts, aid values is now removed before validation like chain and bind
  (was rejected; AUD-F26). v, typ and alg still allow whitespace only around
  the value.
- **Mode 1 CMS is decoded strictly (AUD-F78)**: `chain` must be one
  ContentInfo(SignedData) with detached id-data content, exactly one
  SignerInfo, no signedAttrs, SHA-256 in both digest locations, and a
  SignerInfo signatureAlgorithm plus parameters that match `alg` and the
  signer key: RS256 = sha256WithRSAEncryption or rsaEncryption (OWN-021),
  NULL or absent parameters; ES256 = ecdsa-with-SHA256 with parameters absent
  (NULL, as older Python SDKs emitted, now fails); PS256 = id-RSASSA-PSS with
  SHA-256, MGF1-SHA-256, salt 32, trailerField absent or 1. BER lengths are
  accepted as RFC 5652 permits, including the indefinite lengths BouncyCastle
  emits by default (OWN-024); every certificate must parse; any error fails (the old byte search
  passed on unparseable input). New module `cms_signed_data_profile.py`.
- **The signer is the certificate SignerInfo.sid names** (issuerAndSerialNumber
  or subjectKeyIdentifier, RFC 5652), not whichever bundled certificate's key
  happens to verify.
- **PS256 salt must be 32 octets (AUD-F79)**; any recoverable salt length was
  accepted before.
- **The certificate path is built from the signer (AUD-F80)** by issuer name
  and signature; the order of the CMS certificates SET no longer matters.
  OpenSSL writes that SET in DER-sorted order, so OpenSSL-made CMS always
  failed before whenever trusted roots were given. New module
  `signer_certificate_path_building_and_validation.py`.
- **RFC 5280 CA rules (AUD-F82)**: every intermediate needs basicConstraints
  cA TRUE, keyCertSign when KeyUsage is present, and pathLenConstraint is
  honoured (self-issued certificates not counted); an unrecognised critical
  extension fails; every certificate's validity is checked at
  `reference_time_unix` (default: now) rather than the wall clock. Trusted
  roots are still matched by public key, and the trust store's copy of a root
  (with its constraints) is what counts, not a copy bundled in the message.
- **Requires cryptography >= 42** (the code already used
  `not_valid_before_utc`, which 41 lacks).
- Removed private helpers `_validate_cms_digest_algorithm_is_sha256`,
  `_extract_certificates_from_cms_signed_data`,
  `_extract_signature_from_cms_signed_data` and `_validate_certificate_chain`
  (`_asn1_read_tag_length` stays: the oneid-sdk tests use it).

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
