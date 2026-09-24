# hw-attest-verify

Verification library for RFC `Hardware-Attestation` and `Hardware-Trust-Proof` email headers.

Receiving mail servers use this library to verify that an email was sent from a hardware-attested identity, as defined in [draft-drake-email-hardware-attestation-03](https://1id.com/rfc/).

## Installation

```bash
pip install hw-attest-verify

# With DNS key discovery support (recommended):
pip install hw-attest-verify[dns]
```

## Usage

### Mode 1: Hardware-Attestation (Direct Hardware Attestation)

```python
from hw_attest_verify import verify_hardware_attestation

result = verify_hardware_attestation(
    header_value=msg["Hardware-Attestation"],
    email_headers={
        "from": msg["From"],
        "to": msg["To"],
        "subject": msg["Subject"],
        "date": msg["Date"],
        "message-id": msg["Message-ID"],
    },
    body=msg.get_payload(decode=True),
    allow_self_signed=True,  # or provide trusted_root_certificates
)

if result.is_valid:
    print(f"Verified: trust_tier={result.trust_tier}, alg={result.alg}")
    print(f"Certificate: {result.leaf_certificate_subject}")
else:
    print(f"Verification failed: {result.failure_reason}")
```

### Mode 2: Hardware-Trust-Proof (SD-JWT Trust Proof)

```python
from hw_attest_verify import verify_hardware_trust_proof

result = verify_hardware_trust_proof(
    header_value=msg["Hardware-Trust-Proof"],
    email_headers={
        "from": msg["From"],
        "to": msg["To"],
        "subject": msg["Subject"],
        "date": msg["Date"],
        "message-id": msg["Message-ID"],
    },
    body=msg.get_payload(decode=True),
)

if result.is_valid:
    print(f"Verified: trust_tier={result.trust_tier}")
    print(f"Issuer: {result.issuer}")
    print(f"Disclosed claims: {result.disclosed_claims}")
else:
    print(f"Verification failed: {result.failure_reason}")
```

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
# From stdin
python -m hw_attest_verify < email.eml

# From file
hw-attest-verify email.eml
```

Output is JSON with `is_valid`, `trust_tier`, `failure_reasons`, etc.

## Issuer Key Discovery (Mode 2)

The library discovers the issuer's public key using two mechanisms:

1. **DNS TXT record** (preferred): `_hwattest.{domain}` with format
   `v=hwattest1; alg=ES256; p=<base64 SPKI DER>`
2. **HTTPS JWKS fallback**: `https://{issuer}/.well-known/jwks.json`

Install `dnspython` for DNS discovery: `pip install hw-attest-verify[dns]`

## Trust Tiers

| typ | Trust Tier | Hardware |
|-----|-----------|----------|
| TPM | sovereign | Discrete TPM 2.0 (Windows, Linux) |
| PIV | portable  | YubiKey / PIV smartcard |
| ENC | enclave   | Apple Secure Enclave |
| VRT | virtual   | Firmware TPM (fTPM) |
| SFT | declared  | Software key (fallback) |

## RFC Reference

[draft-drake-email-hardware-attestation-03](https://1id.com/rfc/draft-drake-email-hardware-attestation-03.html) -- Hardware Attestation for Email Sender Verification

## License

MIT


## Spec -> code traceability (G6.3)

This is C3, the offline verifier for
`draft-drake-email-hardware-attestation-03`. Paths relative to this
package.

| Draft section | Implementing file(s) |
|---|---|
| 5 Mode 1 Direct Hardware Attestation (verify) | `hw_attest_verify/mode1.py` (verification flow, digest reconstruction, signature check with the SignerInfo-named certificate; PS256 salt 32), `hw_attest_verify/cms_signed_data_profile.py` (strict CMS SignedData profile + CMS Algorithm Mapping), `hw_attest_verify/signer_certificate_path_building_and_validation.py` (path built from the signer to a trusted root, RFC 5280 CA rules) |
| 5.2 Attestation digest / h-hash + DKIM canon | `hw_attest_verify/mode1.py` `_compute_attestation_digest`, `_canonicalise_headers_for_direct_attestation`, `_select_headers_bottom_up_per_dkim` |
| 5 header grammar (v=/typ=/alg=/h=/bh=/ts=/chain=/aid=) | `hw_attest_verify/parse.py` |
| 6 Mode 2 SD-JWT Trust Proof (verify) | `hw_attest_verify/mode2.py` (SD-JWT parse, disclosure hashes, ES256 sig) |
| 6.3 Message-binding nonce (fixed nine-field set) | `hw_attest_verify/mode2.py` `_compute_message_binding_nonce` (From,To,Subject,Date,Message-ID,Reply-To,MIME-Version,Content-Type,Content-Transfer-Encoding, in order; absent fields contribute nothing; no oversigning; a duplicated field fails) |
| 7 Acceptable algorithms | `cms_signed_data_profile.py` + `mode1.py` (ES256/RS256/PS256), `mode2.py` (ES256 only); source of truth published at C6 |
| 8 Issuer key discovery (`_hwattest` TXT, SPKI `p=`, JWKS fallback) | `hw_attest_verify/issuer_key_discovery.py` |
| 8 IANA A-R: `hw-attest` (header.typ/alg/tier/aid), `hw-trust` (header.mode/tier/issuer/aid) | `hw_attest_verify/__main__.py` `_format_mode1/2_auth_results_line` |
| CLI (`--auth-results --no-time-check --hostname`) | `hw_attest_verify/__main__.py` `verify_email_from_raw` |

Verified end-to-end by gates G4.2 (tamper suite), G4.3 (live 5-tier
round trips), and G4.6 (the draft's own appendix examples re-verify
through this CLI). Not implemented: manufacturer-root-only chains
(Profile M) -- the Issuer-certified chain format is what ships.
