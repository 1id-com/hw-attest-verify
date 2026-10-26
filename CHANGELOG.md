# Changelog

## Unreleased

Tests and documentation only; the published 3.0.0 package is unchanged.

- The five real appendix captures were regenerated through the live system under
  revision -03 on 2026-10-27 (published `oneid` 4.0.0 and `oneid-enroll` 3.0.0,
  verified by this package 3.0.0 in the MailPal milter) and are recorded under
  `tests/fixtures/real_examples_2026_10_27` together with the live RFC 8414 and
  JWK Set answers. All five pass offline in both modes (sovereign, portable,
  enclave, virtual, declared); the strict expected failures are gone.
- The revision -02 captures of 2026-09-24 moved to
  `tests/fixtures/revision_02_captures_2026_09_24`, where they only prove that a
  revision -03 verifier rejects them (`make pypi-check-published-verify` runs the
  published verifier over `tests/fixtures/real_examples_*` only).
- `test_real_example_is_expired_when_checked_as_current` sets the clock instead of
  depending on the capture being more than one hour old (during that first hour the
  proof is `policy` for a different reason: the local age policy).

## 3.0.0 (2026-10-26)

Implements revision -03 of `draft-drake-email-hardware-attestation` (amendments
EML-01 to EML-13). **Breaking**: a -03 verifier does not accept -02 proofs (the
signed input and the covered fields changed) and the meaning of `pass` is
stricter. This is the "initial development" stage: there is no compatibility
mode, and the real appendix captures of revision -02 are recorded as expected
failures until they are replaced by captures made through the live system.

### Mode 1: the signed input and the covered fields

- **92-octet attestation-input with a purpose label (EML-12)**:
  `"AIRS-Email-Mode1-v1" || 0x00 || h-hash || bh-raw || ts` (was 72 octets with
  no label). The detached CMS signature is over exactly those 92 octets.
  `MODE1_ATTESTATION_INPUT_PURPOSE_LABEL_INCLUDING_THE_TERMINATING_ZERO_OCTET`
  in `parse.py`; the helper `_compute_attestation_input` returns the 92 octets.
- **Thirteen always-covered fields (EML-11)**: `h=` must list From, To, Cc,
  Subject, Date, Message-ID, Sender, Reply-To, In-Reply-To, References,
  MIME-Version, Content-Type and Content-Transfer-Encoding (was nine), whether or
  not each is present; Mode 2's message-binding nonce covers the same thirteen
  (`ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER`). Duplicates of the four added
  fields are rejected like the original singletons.
- **Hardware-Trust-Proof canonicalization (EML-10)**: when `h=` names
  `Hardware-Trust-Proof` its value is canonicalized with every whitespace
  character deleted, so a legal refolding of the SD-JWT in transit does not break
  the Mode 1 signature.
- **`ts` grammar (EML-03)**: `0` or a decimal without leading zeroes, at most
  18446744073709551615; anything else is `permerror`. `v` must be exactly `1`
  without leading zeroes.
- **Header size limit**: a field over `maximum_header_field_value_octets`
  (default 65536) is `permerror` before any decoding.

### Results

- **`pass` needs a trust path (EML-01)**: `pass` only if at least one trust path
  succeeded and every path evaluated succeeded. A valid CMS signature with no
  verified Registrar binding is `policy` (reason in `failure_reasons`). New result
  fields: `trust_path_that_succeeded` (`"registrar"` or `""`),
  `cms_signature_and_message_binding_verified`.
- **The manufacturer-rooted path is reserved (EML-07)**: no evidence profile is
  named, so none is reported (`manufacturer_rooted_path_verified` stays `None`).
  `trusted_root_certificates` / `--trust-store` still validate the signer's
  certificate path to the supplied roots, but only as information
  (`signer_certificate_path_to_supplied_roots_is_valid` and `..._failure`).
- **Expiry is `policy` (EML-02)**: an expired Registrar binding assertion
  (`registrar_assertion_has_expired`) or an expired SD-JWT (`token_has_expired`)
  is `policy` with the cause in the reason; a forged expired assertion is still
  `fail`. A non-numeric or non-finite `iat` / `exp` fails closed.
- **The Registry test namespace is `policy` (EML-13)**: a `urn:aid:test:` identity
  is reported as `policy`, with no tier and no `aid` property
  (`aid_is_in_the_registry_test_namespace`,
  `disclosed_sub_is_in_the_registry_test_namespace`); its binding or SD-JWT is
  fully verified first, so forgery is still a failure.
- **The binding's `aid` object is required (EML-05)**: a Registrar binding
  without the `aid` claim object, or whose `trust_tier` does not correspond to
  `typ`, fails.
- **Authentication-Results**: `header.path=registrar` is written when a trust
  path succeeded; `header.tier` and `header.aid` only with a verified binding.

### Added

- `max_timestamp_age_seconds` (parameter of `verify_hardware_attestation`): the local freshness policy for how OLD
  `ts` may be, separate from `max_timestamp_skew_seconds` (the clock-skew allowance for a `ts` or binding `iat` in the
  future). The default is the skew value, so the strict policy of an MSA, and every existing call, is unchanged. A
  receiver that verifies after queueing and greylisting sets it to the lifetime of the Registrar's mail assertions
  without also accepting a `ts` from the future. A stale `ts` is `policy`, as before; the reason now says "old" or
  "in the future" (it said "from the reference time").

### Removed

- `allow_self_signed` (parameter of `verify_hardware_attestation` and
  `verify_email_from_raw`) and the CLI option `--allow-self-signed`: a
  self-signed signer certificate has no trust path of its own. The CLI option now
  prints an explanation and exits with status 2.

### Tests

- `tests/test_revision_03_combined_mode_end_to_end.py`: complete Combined-mode
  messages built from the draft's text alone (an independent producer), covering
  all thirteen fields, the two Hardware-* fields folded and refolded, expiry,
  the test namespace, and a known-answer vector for the 92-octet input computed
  with coreutils only (`tests/fixtures/known_answer_mode1_attestation_input`).
- The revision -02 appendix captures in
  `tests/fixtures/real_examples_2026_09_24` are rejected (a test says so, naming
  the missing fields) and the tests that need a passing capture are strict
  expected failures until live captures replace them.
- `tests/fixtures/mode1_real_cms_producer_vectors.json` was regenerated for -03
  (22 vectors: the Python and Node SDK builders, OpenSSL with three signer
  identifier and certificate-order variants, BouncyCastle in BER and DER). Each
  asserts that the CMS signature, the body hash and the structure verify and
  that the result is `policy` (a producer vector has no Registrar binding, so
  nothing established a trust path, EML-01); the one negative vector (a PSS
  signature with a 20-octet salt) is `permerror`. The path to the supplied root
  is checked as a diagnostic for every positive vector.

## 2.0.2 (2026-09-25)

Fixes from the external pre-submission review (rfc/072).

- **AIRS resolution is validated (review #2)**: the RDAP answer must be an
  `aid_agentIdentity` whose `handle` and `aid_data.canonical` equal the
  requested aid, with `lifecycleState` `operational`. A decommissioned
  identity, an answer for another identity, or an unknown lifecycle state now
  fails both modes with that reason (`AirsIdentityResolutionRejected`) instead
  of passing. A missing `currentIssuer` still means "no current issuer".
- **Authentication-Results values are RFC 8601 values (review #10)**: a value
  that is not an RFC 2045 token -- the `aid` URN and the `issuer` URL -- is
  written as a quoted-string, e.g. `header.aid="urn:aid:global:..."`, as in the
  draft's own examples.
- CLI Authentication-Results: `header.tier` and `header.issuer` are omitted
  when there is no value (a hidden-mode `policy` result printed
  `header.tier=unknown`, which is no tier value; OWN-033).
- References to the email draft no longer pin a revision.

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
