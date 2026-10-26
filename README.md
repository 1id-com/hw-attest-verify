# hw-attest-verify

Verification library for RFC `Hardware-Attestation` and `Hardware-Trust-Proof` email headers.

Receiving mail servers use this library to verify that an email was sent from a hardware-attested identity, as defined in [draft-drake-email-hardware-attestation](https://1id.com/rfc/).

## Installation

```bash
pip install hw-attest-verify
```

## Usage

The simplest correct use is the CLI or `verify_email_from_raw`, which pass
every header instance in order (duplicates and DKIM `h=` selection) and apply
the Combined-mode rules when a message carries both fields:

```python
from hw_attest_verify.__main__ import verify_email_from_raw

results = verify_email_from_raw(raw_email_text)
mode1 = results.get("_mode1_result_object")   # VerificationResult or None
mode2 = results.get("_mode2_result_object")   # Mode2VerificationResult or None
```

Every result carries `authentication_results_result`, the draft's result name:
`pass`, `fail`, `policy` (cryptographically valid, declined by local policy,
e.g. too old or an untrusted hidden-mode issuer), `temperror` (the AIRS
Registry or the issuer could not be reached) or `permerror` (malformed,
unsupported, duplicated fields). `is_valid` is true only for `pass`.

### Mode 1: Hardware-Attestation (Direct Hardware Attestation)

```python
from hw_attest_verify import verify_hardware_attestation

result = verify_hardware_attestation(
    header_value=hardware_attestation_value,
    email_headers=lowercased_header_dict,
    body=raw_body_bytes,
    ordered_header_pairs=every_header_in_order,      # [(name, unfolded value), ...]
)
print(result.authentication_results_result, result.trust_path_that_succeeded,
      result.cms_signature_and_message_binding_verified, result.trust_tier, result.agent_identity_urn)
```

The signed input is the 92-octet `attestation-input` of revision -03:
`"AIRS-Email-Mode1-v1" || 0x00 || h-hash || bh-raw || ts` (the 20-octet purpose
label, the header hash, the body hash and the 8-octet timestamp). The `h=` tag
must list the thirteen always-covered fields (From, To, Cc, Subject, Date,
Message-ID, Sender, Reply-To, In-Reply-To, References, MIME-Version,
Content-Type, Content-Transfer-Encoding), whether or not each is present.

**What `pass` means.** A valid CMS signature over the message is not by itself
a pass. `pass` requires at least one trust path that succeeded, and every path
the verifier evaluated must have succeeded. The one path the draft defines
today is **Registrar-bound**: a message with `aid` and `bind` whose binding JWS
is verified against the AIRS Registry's `currentIssuer` for that `aid` and that
issuer's RFC 8414 JWK Set, with its `cnf.jwk` equal to the CMS signer key. The
result then has `trust_path_that_succeeded == "registrar"`, and `trust_tier`
and `agent_identity_urn` are reported (and only then). A message whose CMS
signature verifies but which has no verified Registrar binding is `policy`, with
the reason in `failure_reasons`; `cms_signature_and_message_binding_verified`
tells such a message apart from a forged one.

The manufacturer-rooted path of earlier revisions is reserved: revision -03 names
no evidence profile for it, so this library never reports one
(`manufacturer_rooted_path_verified` stays `None`). `trusted_root_certificates`
and the CLI's `--trust-store` still make the library validate the signer's
certificate path to those roots, but the outcome is only informational
(`signer_certificate_path_to_supplied_roots_is_valid`), never a trust path.

Other results the draft assigns to `policy` rather than `fail`:

- the Registrar binding assertion has expired (`registrar_assertion_has_expired`):
  the CMS signature was good, the assertion was just no longer current;
- the identity is in the `urn:aid:test:` namespace
  (`aid_is_in_the_registry_test_namespace`): no tier and no `aid` are reported;
- `ts` outside the freshness window. The window has two separate bounds: `max_timestamp_skew_seconds` (default
  300) is the clock-skew allowance for a `ts` in the future, and `max_timestamp_age_seconds` (default: the same
  value) is how OLD a `ts` may be. A receiver that verifies after queueing and greylisting (the first trusted MTA)
  raises only the age to the lifetime of the Registrar's mail assertions (the MailPal hook uses one hour);
  an MSA keeps the strict default (draft -03, "Freshness at Submission").

A forged or malformed message is still `fail` or `permerror`, including a
non-numeric or non-finite `iat` / `exp`, a missing `aid` object in the binding
and a header field over `maximum_header_field_value_octets` (65536).

### Mode 2: Hardware-Trust-Proof (SD-JWT Trust Proof)

```python
from hw_attest_verify import verify_hardware_trust_proof

result = verify_hardware_trust_proof(
    header_value=hardware_trust_proof_value,
    email_headers=lowercased_header_dict,
    body=raw_body_bytes,
    ordered_header_pairs=every_header_in_order,
    trusted_hidden_mode_issuers=["https://1id.com/realms/agents"],  # local policy
)
print(result.authentication_results_result, result.is_identified_mode,
      result.trust_tier, result.agent_identity_urn, result.issuer)
```

A presentation that discloses `sub` is **identified**: the `sub` is resolved
at the AIRS Registry and `iss` must equal its `currentIssuer`. Without `sub` it
is **hidden**, and only issuers in `trusted_hidden_mode_issuers` are used
(otherwise the result is `policy`). Disclosures are processed per RFC 9901
(nested and array digests); `aid.trust_tier` must be disclosed. ES256, RS256
and PS256 issuer signatures are accepted; `kid` is required.

### Combined mode

```python
from hw_attest_verify import apply_combined_mode_requirements_to_mode2_result

apply_combined_mode_requirements_to_mode2_result(mode1_result, mode2_result)
```

When both fields are present, Mode 2 passes only if Mode 1 passed, Mode 1
`h=` covers `Hardware-Trust-Proof`, the SD-JWT `cnf.jwk` is the CMS signer key,
a Mode 1 `aid` equals the disclosed `sub`, and the two proofs state the same
trust tier. A `cnf`-bearing presentation in a message without
`Hardware-Attestation` fails. The `Hardware-Trust-Proof` field named in `h=` is
canonicalized by deleting every whitespace character from its value, so a legal
refolding of the long SD-JWT in transit does not break the Mode 1 signature.

### Parsing without verification

```python
from hw_attest_verify import parse_hardware_attestation_header

parsed = parse_hardware_attestation_header(header_value)
print(f"typ={parsed.typ}, alg={parsed.alg}, trust_tier={parsed.trust_tier}")
print(f"Signed headers: {parsed.signed_header_names}")
print(f"Timestamp: {parsed.ts}")
```

### CLI: Verify a raw email

```bash
# Authentication-Results lines, as in the draft's appendix
python -m hw_attest_verify --auth-results --no-time-check --hostname mailpal.com < email.eml

# JSON (default output)
hw-attest-verify email.eml
```

Options: `--auth-results`, `--hostname NAME`, `--no-time-check` (archived
mail: skip ts/iat/exp and age checks), `--trust-store PATH` (PEM roots; the
signer certificate path to them is validated for information only, it is never a
trust path), `--trust-hidden-issuer URI` (repeatable; local policy for
hidden-mode Mode 2), `--allow-eddsa` (testing only). The exit status is 0 when
any method passed. `--allow-self-signed` was removed in 3.0.0: a self-signed
signer certificate has no trust path of its own, so there is nothing for it to
allow; the option now prints an explanation and exits with status 2.

## Authoritative Registrar Key Discovery

Registrar keys come only from the issuer the AIRS Registry names:

1. Resolve the `aid` / `sub` via AIRS RDAP (`https://airs.1id.biz`) and read
   `aid_data.currentIssuer`; no current issuer = fail, unreachable = temperror.
2. Fetch RFC 8414 metadata for exactly that issuer (for
   `https://1id.com/realms/agents`:
   `https://1id.com/.well-known/oauth-authorization-server/realms/agents`);
   its `issuer` must equal `currentIssuer` and it must publish `jwks_uri`.
3. Take the key named by the JWS `kid` from that JWK Set.

A token, certificate or JWS never supplies its own issuer key. Responses are
cached for 300 seconds. (The older `_hwattest` DNS / `{domain}/.well-known/jwks.json`
helper `discover_issuer_public_key` remains importable but no verification path
uses it; the `[dns]` extra is no longer needed.)

## Trust Tiers

| typ | Trust Tier | Hardware |
|-----|-----------|----------|
| TPM | sovereign | TPM 2.0, discrete or firmware (Windows, Linux) |
| PIV | portable  | YubiKey / PIV smartcard |
| ENC | enclave   | Apple Secure Enclave |
| VRT | virtual   | Hypervisor virtual TPM (vTPM) |
| SFT | declared  | Software key |

## RFC Reference

[draft-drake-email-hardware-attestation](https://datatracker.ietf.org/doc/draft-drake-email-hardware-attestation/) -- Hardware Attestation for Email Sender Verification

## License

MIT


## Spec -> code traceability (G6.3)

This is C3, the offline verifier for
`draft-drake-email-hardware-attestation`. Paths relative to this
package.

| Draft section | Implementing file(s) |
|---|---|
| 5 Mode 1 Direct Hardware Attestation (verify) | `hw_attest_verify/mode1.py` (verification flow, digest reconstruction, signature check with the SignerInfo-named certificate; PS256 salt 32), `hw_attest_verify/cms_signed_data_profile.py` (strict CMS SignedData profile + CMS Algorithm Mapping), `hw_attest_verify/signer_certificate_path_building_and_validation.py` (path built from the signer to a trusted root, RFC 5280 CA rules) |
| 5.2 attestation-input (92 octets: label, h-hash, bh-raw, ts) + DKIM canon | `hw_attest_verify/mode1.py` `_compute_attestation_input`, `_canonicalise_headers_for_direct_attestation`, `_canonicalise_selected_header_field_using_dkim2_header_hash_rules` (the Hardware-Trust-Proof exception, EML-10), `_select_headers_bottom_up_per_dkim`; the label is `MODE1_ATTESTATION_INPUT_PURPOSE_LABEL_INCLUDING_THE_TERMINATING_ZERO_OCTET` in `parse.py` |
| 5 header grammar (v=/typ=/alg=/h=/bh=/ts=/chain=/aid=) | `hw_attest_verify/parse.py` |
| Mode 1 Registrar Binding JWS (currentIssuer, RFC 8414 key, cnf.jwk = signer key; ES256/RS256/PS256) | `hw_attest_verify/mode1.py` `_verify_registrar_binding_jws`, `hw_attest_verify/issuer_key_discovery.py` |
| 6 Mode 2 SD-JWT Trust Proof (verify) | `hw_attest_verify/mode2.py` `verify_hardware_trust_proof` (identified/hidden issuer rules, RFC 9901 `process_sd_jwt_disclosures_per_rfc9901`, ES256/RS256/PS256) |
| Combined Mode | `hw_attest_verify/combined.py` `apply_combined_mode_requirements_to_mode2_result` |
| 6.3 Message-binding nonce (fixed thirteen-field set) | `hw_attest_verify/mode2.py` `_compute_message_binding_nonce` (From,To,Cc,Subject,Date,Message-ID,Sender,Reply-To,In-Reply-To,References,MIME-Version,Content-Type,Content-Transfer-Encoding, in order, then `hardware-trust-proof:`; absent fields contribute nothing; no oversigning; a duplicated field fails); the list is `ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER` in `parse.py` |
| 7 Acceptable algorithms | `cms_signed_data_profile.py` + `mode1.py` (ES256/RS256/PS256), `issuer_key_discovery.py` `verify_compact_jws_signature` (JWS: ES256/RS256/PS256) |
| Authoritative Registrar Key Discovery (RDAP currentIssuer, RFC 8414, jwks_uri) | `hw_attest_verify/mode2.py` `_resolve_issuer_via_rdap`, `hw_attest_verify/issuer_key_discovery.py` `discover_registrar_signing_key` |
| 8 IANA A-R: `hw-attest` (header.typ/alg/tier/aid), `hw-trust` (header.mode/tier/issuer/aid); results pass/fail/policy/temperror/permerror | `authentication_results_result` on both result classes; `hw_attest_verify/__main__.py` `_format_mode1/2_auth_results_line` |
| CLI (`--auth-results --no-time-check --hostname`) | `hw_attest_verify/__main__.py` `verify_email_from_raw` |

Verified end-to-end by gates G4.2 (tamper suite), G4.3 (live 5-tier
round trips), and G4.6 (the draft's own appendix examples re-verify
through this CLI; `tests/test_combined_mode_and_real_example_emails.py`
re-verifies the real appendix emails offline; the revision -02 captures there
are recorded as expected failures until they are replaced by captures made
through the live system under revision -03). The manufacturer-rooted path is
reserved by the draft (EML-07): no evidence profile ties a hardware key to its
manufacturer, so none is invented here and none is ever reported (AUD-F21).
`tests/test_revision_03_combined_mode_end_to_end.py` builds complete
Combined-mode messages from the draft's text alone and carries a known-answer
vector for the 92-octet input that was computed with coreutils only.
