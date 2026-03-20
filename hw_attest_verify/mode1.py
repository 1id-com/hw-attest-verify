"""
Mode 1 verification: Hardware-Attestation header (CMS SignedData).

RFC: draft-drake-email-hardware-attestation-00, Section 5

Verification steps:
  1. Parse the header parameters (v, typ, alg, h, bh, ts, chain)
  2. Decode the CMS SignedData from the chain parameter
  3. Recompute the attestation-digest using h-hash || bh-raw || ts-bytes
  4. Verify the CMS signature using the leaf certificate's public key
  5. Validate the certificate chain
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils

from .parse import ParsedHardwareAttestationHeader, parse_hardware_attestation_header


_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = [
  "from", "to", "subject", "date", "message-id",
]

_DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS = 300


@dataclass
class VerificationResult:
  """Result of verifying a Hardware-Attestation header."""
  is_valid: bool = False
  trust_tier: str = ""
  typ: str = ""
  alg: str = ""
  timestamp_unix: int = 0
  agent_identity_urn: Optional[str] = None
  leaf_certificate_subject: str = ""
  certificate_chain_length: int = 0
  failure_reason: str = ""
  failure_reasons: List[str] = field(default_factory=list)


def verify_hardware_attestation(
  header_value: str,
  email_headers: Dict[str, str],
  body: bytes,
  max_timestamp_skew_seconds: int = _DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS,
  trusted_root_certificates: Optional[List[x509.Certificate]] = None,
  allow_self_signed: bool = False,
  reference_time_unix: Optional[int] = None,
) -> VerificationResult:
  """Verify a Mode 1 Hardware-Attestation header.

  Args:
    header_value: The raw Hardware-Attestation header value string.
    email_headers: Dict of email header name -> value (must include required headers).
    body: Raw email body bytes.
    max_timestamp_skew_seconds: Maximum allowed time drift (default 300s / 5 minutes).
    trusted_root_certificates: Optional list of trusted root CA certs for chain validation.
    allow_self_signed: If True, accept self-signed leaf certificates (testing only).
    reference_time_unix: Unix timestamp to use for time checks (default: now).

  Returns:
    VerificationResult with is_valid=True if all checks pass.
  """
  result = VerificationResult()
  failure_reasons: List[str] = []

  parsed = parse_hardware_attestation_header(header_value)
  result.typ = parsed.typ
  result.trust_tier = parsed.trust_tier
  result.alg = parsed.alg
  result.timestamp_unix = parsed.ts
  result.agent_identity_urn = parsed.aid

  if parsed.version != 1:
    failure_reasons.append(f"Unsupported version: v={parsed.version} (expected v=1)")

  if not parsed.typ:
    failure_reasons.append("Missing typ parameter")

  if not parsed.alg:
    failure_reasons.append("Missing alg parameter")

  if not parsed.chain_base64:
    failure_reasons.append("Missing or empty chain parameter")

  if not parsed.bh:
    failure_reasons.append("Missing bh parameter")

  if parsed.ts == 0:
    failure_reasons.append("Missing or invalid ts parameter")

  if failure_reasons:
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  if reference_time_unix is None:
    reference_time_unix = int(time.time())

  timestamp_age_seconds = abs(reference_time_unix - parsed.ts)
  if timestamp_age_seconds > max_timestamp_skew_seconds:
    failure_reasons.append(
      f"Timestamp too far from current time: {timestamp_age_seconds}s drift "
      f"(max allowed: {max_timestamp_skew_seconds}s)"
    )

  try:
    chain_der_bytes = base64.b64decode(parsed.chain_base64)
  except Exception as decode_error:
    failure_reasons.append(f"Could not base64-decode chain parameter: {decode_error}")
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  extracted_certificates = _extract_certificates_from_cms_signed_data(chain_der_bytes)
  if not extracted_certificates:
    failure_reasons.append("No certificates found in CMS SignedData")
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  result.certificate_chain_length = len(extracted_certificates)
  leaf_certificate = extracted_certificates[0]

  try:
    subject_common_names = leaf_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if subject_common_names:
      result.leaf_certificate_subject = subject_common_names[0].value
    else:
      result.leaf_certificate_subject = str(leaf_certificate.subject)
  except Exception:
    result.leaf_certificate_subject = "(could not extract subject)"

  extracted_signature_bytes = _extract_signature_from_cms_signed_data(chain_der_bytes)
  if extracted_signature_bytes is None:
    failure_reasons.append("Could not extract signature from CMS SignedData")
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  header_value_without_chain_for_self_reference = _reconstruct_header_template_without_chain(parsed)

  attestation_digest = _compute_attestation_digest(
    email_headers=email_headers,
    body_bytes=body,
    attestation_timestamp_unix=parsed.ts,
    header_value_without_chain=header_value_without_chain_for_self_reference,
  )

  signature_verification_error = _verify_signature_against_certificate(
    leaf_certificate=leaf_certificate,
    signature_bytes=extracted_signature_bytes,
    signed_data=attestation_digest,
    algorithm_name=parsed.alg,
  )
  if signature_verification_error:
    failure_reasons.append(f"Signature verification failed: {signature_verification_error}")

  received_bh_bytes = _base64url_decode(parsed.bh)
  canonicalised_body = _canonicalise_body_using_dkim_simple(body)
  recomputed_bh = hashlib.sha256(canonicalised_body).digest()
  if received_bh_bytes != recomputed_bh:
    failure_reasons.append("Body hash (bh) does not match recomputed hash")

  if trusted_root_certificates:
    chain_validation_error = _validate_certificate_chain(
      extracted_certificates, trusted_root_certificates,
    )
    if chain_validation_error:
      failure_reasons.append(f"Certificate chain validation failed: {chain_validation_error}")
  elif not allow_self_signed:
    failure_reasons.append(
      "No trusted root certificates provided and allow_self_signed is False. "
      "Provide trusted_root_certificates or set allow_self_signed=True for testing."
    )

  if failure_reasons:
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  result.is_valid = True
  return result


def _reconstruct_header_template_without_chain(parsed: ParsedHardwareAttestationHeader) -> str:
  """Reconstruct the header value with chain= empty for self-referencing digest."""
  signed_header_names_str = ":".join(parsed.signed_header_names)
  template = (
    f"v={parsed.version}; typ={parsed.typ}; alg={parsed.alg}; "
    f"h={signed_header_names_str}; bh={parsed.bh}; ts={parsed.ts}; "
    f"chain="
  )
  if parsed.aid:
    template += f"; aid={parsed.aid}"
  return template


def _compute_attestation_digest(
  email_headers: Dict[str, str],
  body_bytes: bytes,
  attestation_timestamp_unix: int,
  header_value_without_chain: str,
) -> bytes:
  """Compute the attestation-digest for Mode 1 (RFC Section 5.2).

  attestation-input = h-hash || bh-raw || ts-bytes   (72 bytes)
  attestation-digest = SHA-256(attestation-input)     (32 bytes)
  """
  canonicalised_header_bytes = _canonicalise_headers_for_direct_attestation(
    email_headers, header_value_without_chain,
  )
  h_hash = hashlib.sha256(canonicalised_header_bytes).digest()

  canonicalised_body = _canonicalise_body_using_dkim_simple(body_bytes)
  bh_raw = hashlib.sha256(canonicalised_body).digest()

  ts_bytes = struct.pack(">Q", attestation_timestamp_unix)

  attestation_input = h_hash + bh_raw + ts_bytes
  return hashlib.sha256(attestation_input).digest()


def _canonicalise_headers_for_direct_attestation(
  email_headers: Dict[str, str],
  header_value_without_chain: str,
) -> bytes:
  """Canonicalise headers for Mode 1 attestation digest, per RFC Section 5.2."""
  lowered = {k.strip().lower(): v for k, v in email_headers.items()}

  lines: List[str] = []
  for required_name in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING:
    if required_name not in lowered:
      continue
    canon_name = required_name.strip().lower()
    canon_value = _dkim_relaxed_header_value(lowered[required_name])
    lines.append(f"{canon_name}:{canon_value}\r\n")

  for extra_name in sorted(lowered.keys()):
    if extra_name in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING:
      continue
    if extra_name in ("hardware-attestation", "hardware-trust-proof"):
      continue
    canon_name = extra_name.strip().lower()
    canon_value = _dkim_relaxed_header_value(lowered[extra_name])
    lines.append(f"{canon_name}:{canon_value}\r\n")

  lines.append(f"hardware-attestation:{header_value_without_chain}")
  return "".join(lines).encode("utf-8")


def _dkim_relaxed_header_value(raw_value: str) -> str:
  """RFC 6376 Section 3.4.2 relaxed header canonicalization (value part)."""
  unfolded = raw_value.replace("\r\n ", " ").replace("\r\n\t", " ")
  unfolded = unfolded.replace("\n ", " ").replace("\n\t", " ")
  compressed = re.sub(r"[ \t]+", " ", unfolded)
  return compressed.strip()


def _canonicalise_body_using_dkim_simple(body_bytes: bytes) -> bytes:
  """RFC 6376 Section 3.4.3 simple body canonicalization."""
  if not body_bytes:
    return b"\r\n"
  while body_bytes.endswith(b"\r\n\r\n"):
    body_bytes = body_bytes[:-2]
  if not body_bytes.endswith(b"\r\n"):
    body_bytes = body_bytes + b"\r\n"
  return body_bytes


def _base64url_decode(encoded_string: str) -> bytes:
  """Decode base64url (no padding) to bytes."""
  padded = encoded_string + "=" * (4 - len(encoded_string) % 4)
  return base64.urlsafe_b64decode(padded)


def _extract_certificates_from_cms_signed_data(cms_der_bytes: bytes) -> List[x509.Certificate]:
  """Extract certificates from a CMS SignedData DER structure.

  Walks the ASN.1 structure to find the [0] IMPLICIT SET OF Certificate
  within the SignedData SEQUENCE.
  """
  certificates: List[x509.Certificate] = []
  try:
    offset = 0
    tag, length, value_offset = _asn1_read_tag_length(cms_der_bytes, offset)
    content_info_bytes = cms_der_bytes[value_offset:value_offset + length]

    inner_offset = 0
    oid_tag, oid_len, oid_val_offset = _asn1_read_tag_length(content_info_bytes, inner_offset)
    inner_offset = oid_val_offset + oid_len

    if inner_offset >= len(content_info_bytes):
      return certificates

    explicit_tag, explicit_len, explicit_val_offset = _asn1_read_tag_length(content_info_bytes, inner_offset)
    signed_data_bytes = content_info_bytes[explicit_val_offset:explicit_val_offset + explicit_len]

    sd_offset = 0
    sd_tag, sd_len, sd_val_offset = _asn1_read_tag_length(signed_data_bytes, sd_offset)
    sd_content = signed_data_bytes[sd_val_offset:sd_val_offset + sd_len]

    pos = 0
    while pos < len(sd_content):
      elem_tag, elem_len, elem_val_offset = _asn1_read_tag_length(sd_content, pos)
      elem_end = elem_val_offset + elem_len

      if elem_tag == 0xA0:
        certs_content = sd_content[elem_val_offset:elem_end]
        cert_pos = 0
        while cert_pos < len(certs_content):
          cert_tag, cert_len, cert_val_offset = _asn1_read_tag_length(certs_content, cert_pos)
          cert_der = certs_content[cert_pos:cert_val_offset + cert_len]
          try:
            cert = x509.load_der_x509_certificate(cert_der)
            certificates.append(cert)
          except Exception:
            pass
          cert_pos = cert_val_offset + cert_len
        break

      pos = elem_end

  except Exception:
    pass

  return certificates


def _extract_signature_from_cms_signed_data(cms_der_bytes: bytes) -> Optional[bytes]:
  """Extract the signature bytes from the SignerInfo in a CMS SignedData."""
  try:
    offset = 0
    tag, length, value_offset = _asn1_read_tag_length(cms_der_bytes, offset)
    content_info_bytes = cms_der_bytes[value_offset:value_offset + length]

    inner_offset = 0
    oid_tag, oid_len, oid_val_offset = _asn1_read_tag_length(content_info_bytes, inner_offset)
    inner_offset = oid_val_offset + oid_len

    explicit_tag, explicit_len, explicit_val_offset = _asn1_read_tag_length(content_info_bytes, inner_offset)
    signed_data_bytes = content_info_bytes[explicit_val_offset:explicit_val_offset + explicit_len]

    sd_tag, sd_len, sd_val_offset = _asn1_read_tag_length(signed_data_bytes, 0)
    sd_content = signed_data_bytes[sd_val_offset:sd_val_offset + sd_len]

    last_set_content = None
    pos = 0
    while pos < len(sd_content):
      elem_tag, elem_len, elem_val_offset = _asn1_read_tag_length(sd_content, pos)
      elem_end = elem_val_offset + elem_len
      if elem_tag == 0x31:
        last_set_content = sd_content[elem_val_offset:elem_end]
      pos = elem_end

    if last_set_content is None:
      return None

    signer_info_tag, si_len, si_val_offset = _asn1_read_tag_length(last_set_content, 0)
    signer_info_content = last_set_content[si_val_offset:si_val_offset + si_len]

    last_octet_string_value = None
    si_pos = 0
    while si_pos < len(signer_info_content):
      si_tag, si_elem_len, si_elem_val_offset = _asn1_read_tag_length(signer_info_content, si_pos)
      si_elem_end = si_elem_val_offset + si_elem_len
      if si_tag == 0x04:
        last_octet_string_value = signer_info_content[si_elem_val_offset:si_elem_end]
      si_pos = si_elem_end

    return last_octet_string_value

  except Exception:
    return None


def _asn1_read_tag_length(data: bytes, offset: int) -> tuple:
  """Read an ASN.1 tag and length at the given offset.

  Returns (tag, length, value_offset).
  """
  if offset >= len(data):
    raise ValueError(f"ASN.1 read past end of data at offset {offset}")

  tag = data[offset]
  offset += 1

  if offset >= len(data):
    raise ValueError("ASN.1 truncated after tag")

  first_length_byte = data[offset]
  offset += 1

  if first_length_byte < 0x80:
    return (tag, first_length_byte, offset)

  num_length_bytes = first_length_byte & 0x7F
  if num_length_bytes == 0:
    raise ValueError("ASN.1 indefinite length not supported")

  length_value = 0
  for _ in range(num_length_bytes):
    if offset >= len(data):
      raise ValueError("ASN.1 truncated in length")
    length_value = (length_value << 8) | data[offset]
    offset += 1

  return (tag, length_value, offset)


def _validate_certificate_chain(
  chain: List[x509.Certificate],
  trusted_roots: List[x509.Certificate],
) -> Optional[str]:
  """Validate that each cert in the chain is signed by the next, ending at a trusted root.

  Returns None on success, or an error string on failure.
  """
  if not chain:
    return "Certificate chain is empty"

  trusted_root_fingerprints = set()
  for root in trusted_roots:
    try:
      pub_der = root.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
      )
      trusted_root_fingerprints.add(pub_der)
    except Exception:
      pass

  for i in range(len(chain) - 1):
    child = chain[i]
    parent = chain[i + 1]
    parent_key = parent.public_key()

    try:
      if isinstance(parent_key, rsa.RSAPublicKey):
        parent_key.verify(
          child.signature, child.tbs_certificate_bytes,
          padding.PKCS1v15(), child.signature_hash_algorithm,
        )
      elif isinstance(parent_key, ec.EllipticCurvePublicKey):
        parent_key.verify(
          child.signature, child.tbs_certificate_bytes,
          ec.ECDSA(child.signature_hash_algorithm),
        )
      else:
        return f"Unsupported key type at position {i+1}: {type(parent_key).__name__}"
    except InvalidSignature:
      return f"Certificate at position {i} is not signed by certificate at position {i+1}"
    except Exception as chain_error:
      return f"Error verifying cert at position {i}: {chain_error}"

  root_cert = chain[-1]
  root_pub_der = root_cert.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
  )
  if root_pub_der not in trusted_root_fingerprints:
    return f"Chain root '{root_cert.subject}' is not in the set of trusted roots"

  return None


def _verify_signature_against_certificate(
  leaf_certificate: x509.Certificate,
  signature_bytes: bytes,
  signed_data: bytes,
  algorithm_name: str,
) -> Optional[str]:
  """Verify a signature using the leaf certificate's public key.

  Returns None on success, or an error message string on failure.
  """
  public_key = leaf_certificate.public_key()

  try:
    if algorithm_name == "ES256":
      if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"Certificate has {type(public_key).__name__}, expected EC for ES256"
      public_key.verify(signature_bytes, signed_data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    elif algorithm_name == "RS256":
      if not isinstance(public_key, rsa.RSAPublicKey):
        return f"Certificate has {type(public_key).__name__}, expected RSA for RS256"
      public_key.verify(
        signature_bytes, signed_data,
        padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()),
      )
    elif algorithm_name == "PS256":
      if not isinstance(public_key, rsa.RSAPublicKey):
        return f"Certificate has {type(public_key).__name__}, expected RSA for PS256"
      public_key.verify(
        signature_bytes, signed_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        utils.Prehashed(hashes.SHA256()),
      )
    else:
      return f"Unsupported algorithm: {algorithm_name}"
  except InvalidSignature:
    return "Cryptographic signature does not match"
  except Exception as unexpected_error:
    return f"Unexpected error during signature verification: {unexpected_error}"

  return None

