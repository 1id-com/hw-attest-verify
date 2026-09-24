# Changelog

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
