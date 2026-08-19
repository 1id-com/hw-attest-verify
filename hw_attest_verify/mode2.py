"""
Mode 2 verification: Hardware-Trust-Proof header (SD-JWT with selective disclosure).

RFC: draft-drake-email-hardware-attestation-00, Section 6

Verification steps (RFC Section 6.5):
  1. Parse the SD-JWT presentation (header.payload.signature~disclosure1~...)
  2. Extract the issuer (iss) claim
  3. Obtain the Issuer's public key (DNS _hwattest.{domain} then JWKS fallback)
  4. Verify the ES256 signature
  5. Verify exp / iat timing
  6. Verify each disclosure hash matches an _sd entry
  7. Verify the message-binding nonce
  8. Extract disclosed claims
"""

from __future__ import annotations

import base64
import email.header
import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from .issuer_key_discovery import discover_issuer_public_key


_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = [
  "from", "to", "subject", "date", "message-id",
]


def _unfold_mime_header_value(raw_value: str) -> str:
  """Remove RFC 5322 header folding from a structured header value.

  Handles three scenarios:
    1. Raw wire-format: CRLF + WSP (RFC 5322 folding)
    2. Partially unfolded by email libraries: LF + WSP
    3. Fully unfolded by email libraries: only the leading WSP remains
       (e.g. Python email.policy.default converts "\\n\\t" to "\\t")

  For SD-JWT and structured parameters, the folding whitespace is never
  part of the value content, so we collapse all runs of SP/HTAB that
  appear after unfolding into nothing.
  """
  import re
  unfolded = raw_value.replace("\r\n\t", "").replace("\r\n ", "")
  unfolded = unfolded.replace("\n\t", "").replace("\n ", "")
  unfolded = re.sub(r"[ \t]{2,}", "", unfolded)
  unfolded = unfolded.replace("\t", "")
  return unfolded

_DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 3600
_DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS = 300


@dataclass
class Mode2VerificationResult:
  """Result of verifying a Hardware-Trust-Proof header."""
  is_valid: bool = False
  trust_tier: str = ""
  agent_identity_urn: str = ""
  issuer: str = ""
  issued_at_unix: int = 0
  expires_at_unix: int = 0
  disclosed_claims: Dict[str, object] = field(default_factory=dict)
  failure_reason: str = ""
  failure_reasons: List[str] = field(default_factory=list)
  is_identified_mode: bool = False
  rdap_issuer_verified: bool = False


def verify_hardware_trust_proof(
  header_value: str,
  email_headers: Dict[str, str],
  body: bytes,
  ordered_header_pairs: Optional[List[tuple]] = None,
  max_timestamp_skew_seconds: int = _DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS,
  max_token_lifetime_seconds: int = _DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
  reference_time_unix: Optional[int] = None,
  issuer_public_key_override: Optional[ec.EllipticCurvePublicKey] = None,
) -> Mode2VerificationResult:
  """Verify a Mode 2 Hardware-Trust-Proof header.

  Implements the full RFC Section 6.5 verification algorithm:
    1. Parse SD-JWT presentation
    2. Extract issuer, discover public key (DNS then JWKS)
    3. Verify ES256 signature
    4. Verify timing (exp, iat)
    5. Verify disclosure hashes
    6. Verify message-binding nonce
    7. Extract disclosed claims

  Args:
    header_value: The raw Hardware-Trust-Proof header value string.
    email_headers: Dict of email header name -> value.
    body: Raw email body bytes.
    max_timestamp_skew_seconds: Maximum iat drift from reference time.
    max_token_lifetime_seconds: Maximum allowed exp - iat span.
    reference_time_unix: Unix timestamp for time checks (default: now).
    issuer_public_key_override: If provided, skip key discovery and use this key.

  Returns:
    Mode2VerificationResult with is_valid=True if all checks pass.
  """
  result = Mode2VerificationResult()
  failure_reasons: List[str] = []

  if reference_time_unix is None:
    reference_time_unix = int(time.time())

  header_value = _unfold_mime_header_value(header_value)

  sd_jwt_parts = _parse_sd_jwt_presentation(header_value.strip())
  if sd_jwt_parts is None:
    result.failure_reason = "Could not parse SD-JWT presentation"
    result.failure_reasons = [result.failure_reason]
    return result

  jwt_header_json, jwt_payload_json, jwt_signature_bytes, disclosure_strings = sd_jwt_parts

  try:
    jwt_header = json.loads(jwt_header_json)
  except json.JSONDecodeError as parse_error:
    result.failure_reason = f"JWT header is not valid JSON: {parse_error}"
    result.failure_reasons = [result.failure_reason]
    return result

  try:
    jwt_payload = json.loads(jwt_payload_json)
  except json.JSONDecodeError as parse_error:
    result.failure_reason = f"JWT payload is not valid JSON: {parse_error}"
    result.failure_reasons = [result.failure_reason]
    return result

  issuer = jwt_payload.get("iss", "")
  if not issuer:
    failure_reasons.append("Missing iss (issuer) claim in SD-JWT payload")

  result.issuer = issuer

  jwt_typ = jwt_header.get("typ", "")
  if jwt_typ and jwt_typ != "airs-email+sd-jwt":
    failure_reasons.append(f"Unexpected typ header: {jwt_typ!r} (expected 'airs-email+sd-jwt')")

  algorithm = jwt_header.get("alg", "")
  if algorithm != "ES256":
    failure_reasons.append(f"Unsupported algorithm: {algorithm} (expected ES256)")

  iat = jwt_payload.get("iat")
  exp = jwt_payload.get("exp")

  if iat is not None:
    result.issued_at_unix = int(iat)
    iat_drift = abs(reference_time_unix - int(iat))
    if iat_drift > max_timestamp_skew_seconds:
      failure_reasons.append(
        f"iat is {iat_drift}s from reference time (max: {max_timestamp_skew_seconds}s)"
      )

  if exp is not None:
    result.expires_at_unix = int(exp)
    if max_timestamp_skew_seconds < 999_999_000 and int(exp) < reference_time_unix:
      failure_reasons.append(f"Token has expired (exp={exp}, now={reference_time_unix})")

  if iat is not None and exp is not None:
    token_lifetime = int(exp) - int(iat)
    if max_timestamp_skew_seconds < 999_999_000 and token_lifetime > max_token_lifetime_seconds:
      failure_reasons.append(
        f"Token lifetime {token_lifetime}s exceeds maximum {max_token_lifetime_seconds}s"
      )

  if failure_reasons:
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  header_b64 = header_value.strip().split("~")[0].rsplit(".", 1)[0].rsplit(".", 1)[0]
  jwt_compact = header_value.strip().split("~")[0]
  jwt_parts = jwt_compact.split(".")
  if len(jwt_parts) != 3:
    result.failure_reason = "SD-JWT does not have 3 dot-separated parts"
    result.failure_reasons = [result.failure_reason]
    return result

  signing_input = f"{jwt_parts[0]}.{jwt_parts[1]}".encode("ascii")

  public_key = issuer_public_key_override
  if public_key is None:
    issuer_domain = _extract_domain_from_issuer(issuer)
    if not issuer_domain:
      result.failure_reason = f"Cannot extract domain from issuer: {issuer}"
      result.failure_reasons = [result.failure_reason]
      return result

    kid = jwt_header.get("kid")
    public_key = discover_issuer_public_key(issuer_domain, kid=kid)
    if public_key is None:
      result.failure_reason = f"Could not discover issuer public key for {issuer_domain}"
      result.failure_reasons = [result.failure_reason]
      return result

  signature_error = _verify_es256_signature(public_key, signing_input, jwt_signature_bytes)
  if signature_error:
    failure_reasons.append(f"Signature verification failed: {signature_error}")
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  sd_array = jwt_payload.get("_sd", [])
  disclosed_claims, disclosure_errors = _verify_and_extract_disclosures(
    disclosure_strings, sd_array,
  )
  for disclosure_error_message in disclosure_errors:
    failure_reasons.append(disclosure_error_message)

  nonce = jwt_payload.get("nonce")
  if nonce is None:
    failure_reasons.append("Missing nonce claim (required for message binding)")
  elif iat is not None:
    expected_nonce = _compute_message_binding_nonce(
      email_headers, body, int(iat),
      ordered_header_pairs=ordered_header_pairs,
    )
    if nonce != expected_nonce:
      failure_reasons.append(
        f"Message-binding nonce mismatch: got {nonce!r}, expected {expected_nonce!r}"
      )

  result.disclosed_claims = disclosed_claims

  aid_claim = disclosed_claims.get("aid")
  if isinstance(aid_claim, dict):
    result.trust_tier = str(aid_claim.get("trust_tier", ""))
  else:
    result.trust_tier = str(disclosed_claims.get("trust_tier", jwt_payload.get("trust_tier", "")))

  result.agent_identity_urn = str(jwt_payload.get("sub", ""))
  result.is_identified_mode = bool(result.agent_identity_urn)

  if result.is_identified_mode and not failure_reasons:
    rdap_issuer = _resolve_issuer_via_rdap(result.agent_identity_urn)
    if rdap_issuer is not None:
      if rdap_issuer == issuer:
        result.rdap_issuer_verified = True
      else:
        failure_reasons.append(
          f"RDAP currentIssuer {rdap_issuer!r} does not match JWT iss {issuer!r}"
        )
    else:
      pass

  if failure_reasons:
    result.failure_reasons = failure_reasons
    result.failure_reason = failure_reasons[0]
    return result

  result.is_valid = True
  return result


def _parse_sd_jwt_presentation(
  presentation: str,
) -> Optional[tuple]:
  """Parse an SD-JWT presentation into its components.

  Format: base64url(header).base64url(payload).base64url(signature)~disclosure1~disclosure2~...~

  Returns (header_json, payload_json, signature_bytes, [disclosure_strings])
  or None if parsing fails.
  """
  tilde_parts = presentation.split("~")
  jwt_compact = tilde_parts[0]
  disclosure_strings = [d for d in tilde_parts[1:] if d]

  dot_parts = jwt_compact.split(".")
  if len(dot_parts) != 3:
    return None

  try:
    header_json = _base64url_decode_to_string(dot_parts[0])
    payload_json = _base64url_decode_to_string(dot_parts[1])
    signature_bytes = _base64url_decode_to_bytes(dot_parts[2])
  except Exception:
    return None

  return (header_json, payload_json, signature_bytes, disclosure_strings)


def _base64url_decode_to_bytes(encoded: str) -> bytes:
  padded = encoded + "=" * (4 - len(encoded) % 4)
  return base64.urlsafe_b64decode(padded)


def _base64url_decode_to_string(encoded: str) -> str:
  return _base64url_decode_to_bytes(encoded).decode("utf-8")


def _base64url_encode_no_padding(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _extract_domain_from_issuer(issuer: str) -> Optional[str]:
  """Extract the domain name from an issuer URL or identifier."""
  if issuer.startswith("https://") or issuer.startswith("http://"):
    parsed = urlparse(issuer)
    return parsed.hostname
  if "." in issuer and "/" not in issuer:
    return issuer
  return None


def _verify_es256_signature(
  public_key: ec.EllipticCurvePublicKey,
  signing_input: bytes,
  signature_bytes: bytes,
) -> Optional[str]:
  """Verify an ES256 (ECDSA P-256 + SHA-256) JWS signature.

  JWS signatures use raw R||S format (64 bytes for P-256),
  not DER-encoded. Convert to DER before calling cryptography.

  Returns None on success, or an error string on failure.
  """
  from cryptography.exceptions import InvalidSignature

  try:
    if len(signature_bytes) == 64:
      der_signature = _raw_rs_to_der(signature_bytes)
    else:
      der_signature = signature_bytes

    public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    return None
  except InvalidSignature:
    return "ES256 signature does not match"
  except Exception as unexpected_error:
    return f"Unexpected error: {unexpected_error}"


def _raw_rs_to_der(raw_rs: bytes) -> bytes:
  """Convert a raw R||S ECDSA signature (JWS format) to DER format."""
  r_bytes = raw_rs[:32]
  s_bytes = raw_rs[32:]

  def _encode_der_integer(value_bytes: bytes) -> bytes:
    stripped = value_bytes.lstrip(b"\x00") or b"\x00"
    if stripped[0] & 0x80:
      stripped = b"\x00" + stripped
    return b"\x02" + bytes([len(stripped)]) + stripped

  r_der = _encode_der_integer(r_bytes)
  s_der = _encode_der_integer(s_bytes)
  sequence_content = r_der + s_der
  return b"\x30" + bytes([len(sequence_content)]) + sequence_content


def _verify_and_extract_disclosures(
  disclosure_strings: List[str],
  sd_array: List[str],
) -> tuple:
  """Verify disclosure hashes against the _sd array and extract claims.

  Each disclosure is base64url-encoded JSON: [salt, claim_name, claim_value].
  Its hash is base64url(SHA-256(disclosure_string)).

  Returns (disclosed_claims_dict, [error_messages]).
  """
  disclosed_claims: Dict[str, object] = {}
  error_messages: List[str] = []

  for disclosure_b64 in disclosure_strings:
    disclosure_hash = _base64url_encode_no_padding(
      hashlib.sha256(disclosure_b64.encode("ascii")).digest()
    )
    if disclosure_hash not in sd_array:
      error_messages.append(
        f"Disclosure hash {disclosure_hash} not found in _sd array"
      )
      continue

    try:
      disclosure_json = _base64url_decode_to_string(disclosure_b64)
      disclosure_array = json.loads(disclosure_json)
      if isinstance(disclosure_array, list) and len(disclosure_array) >= 3:
        claim_name = str(disclosure_array[1])
        claim_value = disclosure_array[2]
        disclosed_claims[claim_name] = claim_value
    except Exception as decode_error:
      error_messages.append(f"Could not decode disclosure: {decode_error}")

  return disclosed_claims, error_messages


def _decode_rfc2047_encoded_words_to_unicode(raw_header_value: str) -> str:
  """Decode RFC 2047 encoded-words to plain Unicode before canonicalization.

  MTAs may re-encode RFC 2047 differently (splitting across fold points,
  or consolidating multiple encoded-words). Decoding before canonicalization
  ensures the attestation hash is independent of encoding representation.
  """
  try:
    decoded_parts = email.header.decode_header(raw_header_value)
    return str(email.header.make_header(decoded_parts))
  except Exception:
    return raw_header_value


def _dkim_relaxed_header_value(raw_value: str) -> str:
  """RFC 6376 Section 3.4.2 relaxed header canonicalization (value part).

  Pre-step: Decode RFC 2047 encoded-words to Unicode, then normalize.
  """
  import re
  decoded = _decode_rfc2047_encoded_words_to_unicode(raw_value)
  normalized = decoded.replace("\r\n", "\n").replace("\n", "\r\n")
  unfolded = re.sub(r"\r\n[ \t]", " ", normalized)
  compressed = re.sub(r"[ \t]+", " ", unfolded)
  return compressed.strip()


def _canonicalise_body_using_dkim_simple(body_bytes: bytes) -> bytes:
  """RFC 6376 Section 3.4.3 simple body canonicalization.

  Normalizes bare LF to CRLF first (emails stored on disk often lose CR).
  """
  if not body_bytes:
    return b"\r\n"
  body_bytes = body_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
  while body_bytes.endswith(b"\r\n\r\n"):
    body_bytes = body_bytes[:-2]
  if not body_bytes.endswith(b"\r\n"):
    body_bytes = body_bytes + b"\r\n"
  return body_bytes


def _select_headers_bottom_up_per_dkim(
  header_names_from_h_tag: List[str],
  message_headers: List[tuple],
) -> List[Optional[tuple]]:
  """Select header instances per DKIM RFC 6376 Section 3.7 bottom-up rule."""
  consumed_indices: set = set()
  selected: List[Optional[tuple]] = []
  for requested_name in header_names_from_h_tag:
    target = requested_name.strip().lower()
    found_index = -1
    for i in range(len(message_headers) - 1, -1, -1):
      if i in consumed_indices:
        continue
      if message_headers[i][0].strip().lower() == target:
        found_index = i
        break
    if found_index >= 0:
      consumed_indices.add(found_index)
      selected.append(message_headers[found_index])
    else:
      selected.append(None)
  return selected


def _compute_message_binding_nonce(
  email_headers: Dict[str, str],
  body_bytes: bytes,
  iat_unix_timestamp: int,
  ordered_header_pairs: Optional[List[tuple]] = None,
) -> str:
  """Compute the RFC Section 6.3 message-binding nonce.

  message-binding = h-hash || bh-raw || ts-bytes   (72 bytes)
  nonce = base64url(SHA-256(message-binding))

  Uses the SD-JWT's iat for ts-bytes, per the RFC verification algorithm.

  email-03 Mode 2 covers a FIXED set: exactly From, To, Subject, Date,
  Message-ID, in THAT order, each once -- no oversigning and no bottom-up
  selection (that is a Mode 1 behavior; Mode 1 carries an explicit h=
  list, Mode 2 does not, so its covered set must be fixed and known to
  both sides). ordered_header_pairs is accepted for signature
  compatibility but ignored here: the fixed set is taken from
  email_headers in canonical order.
  """
  lowered = {k.strip().lower(): v for k, v in email_headers.items()}
  lines: List[str] = []
  for required_name in _MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING:
    if required_name in lowered:
      canon_value = _dkim_relaxed_header_value(lowered[required_name])
      lines.append(f"{required_name}:{canon_value}\r\n")

  lines.append("hardware-trust-proof:")

  canonicalised_header_bytes = "".join(lines).encode("utf-8")
  h_hash = hashlib.sha256(canonicalised_header_bytes).digest()

  canonicalised_body = _canonicalise_body_using_dkim_simple(body_bytes)
  bh_raw = hashlib.sha256(canonicalised_body).digest()

  ts_bytes = struct.pack(">Q", iat_unix_timestamp)

  message_binding = h_hash + bh_raw + ts_bytes
  nonce_raw = hashlib.sha256(message_binding).digest()

  return _base64url_encode_no_padding(nonce_raw)


_RDAP_TIMEOUT_SECONDS = 5.0
_AIRS_RDAP_BASE_URL = "https://airs.1id.biz"


def _resolve_issuer_via_rdap(agent_identity_urn: str) -> Optional[str]:
  """Resolve an agent identity URN via AIRS RDAP and return currentIssuer.

  Per draft-drake-agent-identity-resolution-00 Section 4, the verifier
  resolves the sub claim to confirm the issuer matches the RDAP-advertised
  currentIssuer for that identity.

  Returns the currentIssuer string, or None if RDAP lookup fails or the
  identity is not found (non-fatal -- allows offline/degraded verification).
  """
  import urllib.request
  import urllib.error

  urn_path = agent_identity_urn
  if urn_path.startswith("urn:aid:"):
    urn_path = urn_path[len("urn:aid:"):]

  rdap_url = f"{_AIRS_RDAP_BASE_URL}/rdap/aid_identity/{urn_path}"

  try:
    request = urllib.request.Request(rdap_url, headers={"Accept": "application/rdap+json"})
    with urllib.request.urlopen(request, timeout=_RDAP_TIMEOUT_SECONDS) as response:
      data = json.loads(response.read().decode("utf-8"))
      aid_data = data.get("aid_data", {})
      return aid_data.get("currentIssuer")
  except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
    return None

