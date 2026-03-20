# hw-attest-verify

Verification library for RFC `Hardware-Attestation` and `Hardware-Trust-Proof` email headers.

Receiving mail servers use this library to verify that an email was sent from hardware-attested identity, as defined in [draft-drake-email-hardware-attestation-00](https://1id.com/rfc/).

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

[draft-drake-email-hardware-attestation-00](https://1id.com/rfc/draft-drake-email-hardware-attestation-00.html) -- Hardware Attestation for Email Sender Verification

## License

MIT

