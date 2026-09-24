"""
Mode 2 verification: Hardware-Trust-Proof header (SD-JWT with selective disclosure).

RFC: draft-drake-email-hardware-attestation-03, Section 6

Verification follows the draft's "Verification Algorithm" for Mode 2:
  1. Reject duplicate singleton fields; parse the SD-JWT (all input untrusted).
  2. Disclosed canonical sub -> resolve it at the AIRS Registry and require
     iss == currentIssuer (identified); no sub -> receiver-local policy must
     trust iss (hidden) before any discovery.
  3. RFC 8414 key discovery for that issuer; verify the JWS (ES256, RS256,
     PS256) and the disclosures per RFC 9901; require aid.trust_tier; reject
     a cnf-bearing presentation without a Hardware-Attestation field.
  4. Require iat and nonce; reject a materially future iat; enforce exp.
  5. Recompute the message-binding nonce and require equality.
  6. Receiver-local age policy on iat (a policy result, not a failure).
  7. Report identified (with the verified sub) or hidden.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from .issuer_key_discovery import (
  TransientExternalLookupFailure,
  discover_registrar_signing_key,
  verify_compact_jws_signature,
)


from .parse import ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER, find_duplicate_singleton_header_field_names

_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = list(ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER)


def _unfold_mime_header_value(raw_value: str) -> str:
  """Remove RFC 5322 header folding from an SD-JWT compact header value.

  SD-JWT compact serialization (header.payload.sig~disc1~...) never
  contains whitespace, so after RFC 5322 unfolding we strip ALL WSP.
  """
  import re
  unfolded = re.sub(r"\r\n([ \t]+)", r"\1", raw_value)
  unfolded = re.sub(r"\n([ \t]+)", r"\1", unfolded)
  unfolded = re.sub(r"[ \t]+", "", unfolded)
  return unfolded.strip()

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
  # Email draft IANA result name: pass / fail / policy / temperror / permerror.
  authentication_results_result: str = "fail"
  # Combined mode: the Issuer-signed payload carries cnf, and the RFC 7638
  # thumbprint of its jwk ("" when absent or malformed).
  carries_cnf_claim: bool = False
  cnf_jwk_thumbprint: str = ""


_ACCEPTED_ISSUER_JWS_ALGORITHMS = ("ES256", "RS256", "PS256")

# Claims the verifier needs before or during verification: they MUST NOT be
# selectively disclosable (draft "Header Field and Claims"; cnf in Combined mode).
_CLAIMS_THAT_MUST_BE_IN_THE_ISSUER_SIGNED_PAYLOAD = ("iss", "iat", "exp", "nonce", "cnf")


def verify_hardware_trust_proof(
  header_value: str,
  email_headers: Dict[str, str],
  body: bytes,
  ordered_header_pairs: Optional[List[tuple]] = None,
  max_timestamp_skew_seconds: int = _DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS,
  max_token_lifetime_seconds: int = _DEFAULT_MAX_TOKEN_LIFETIME_SECONDS,
  reference_time_unix: Optional[int] = None,
  issuer_public_key_override=None,
  skip_time_checks: bool = False,
  current_issuer_resolver: Optional[Callable[[str], Optional[str]]] = None,
  trusted_hidden_mode_issuers: Optional[Iterable[str]] = None,
  max_proof_age_seconds: Optional[int] = None,
) -> Mode2VerificationResult:
  """Verify a Mode 2 Hardware-Trust-Proof header (see the module docstring).

  Args:
    header_value: The raw Hardware-Trust-Proof header value string.
    email_headers: Dict of lowercased email header name -> value.
    body: Raw email body bytes.
    ordered_header_pairs: Every header instance in order (duplicates, DKIM h= selection).
    max_timestamp_skew_seconds: How far iat may be in the future before it fails.
    max_token_lifetime_seconds: Local policy on exp - iat.
    reference_time_unix: Unix time for the time checks (default: now).
    issuer_public_key_override: Use this issuer key instead of RFC 8414 discovery
      (tests / offline); the identified and hidden-mode issuer checks still apply.
    skip_time_checks: Skip iat/exp/age checks (archived mail).
    current_issuer_resolver: aid -> currentIssuer (None = no current issuer; raise
      TransientExternalLookupFailure when it cannot complete). Default: AIRS RDAP.
    trusted_hidden_mode_issuers: Issuers local policy trusts for hidden-identity
      presentations (no sub). Empty: hidden mode yields policy.
    max_proof_age_seconds: Local age policy on iat (default: max_timestamp_skew_seconds).

  Returns:
    Mode2VerificationResult; is_valid is True only for authentication_results_result "pass".
  """
  result = Mode2VerificationResult()

  if reference_time_unix is None:
    reference_time_unix = int(time.time())
  if max_proof_age_seconds is None:
    max_proof_age_seconds = max_timestamp_skew_seconds
  if current_issuer_resolver is None:
    current_issuer_resolver = _resolve_issuer_via_rdap

  duplicate_singleton_names = find_duplicate_singleton_header_field_names(ordered_header_pairs)
  if duplicate_singleton_names:
    return _finish_mode2_result(result, "permerror", [
      f"Duplicate singleton headers (permerror): {', '.join(duplicate_singleton_names)}"
    ])

  header_value = _unfold_mime_header_value(header_value)
  sd_jwt_parts = _parse_sd_jwt_presentation(header_value.strip())
  if sd_jwt_parts is None:
    return _finish_mode2_result(result, "permerror", ["Could not parse SD-JWT presentation"])
  jwt_header_json, jwt_payload_json, jwt_signature_bytes, disclosure_strings = sd_jwt_parts

  try:
    jwt_header = json.loads(jwt_header_json)
    jwt_payload = json.loads(jwt_payload_json)
  except json.JSONDecodeError as parse_error:
    return _finish_mode2_result(result, "permerror", [f"JWT header or payload is not valid JSON: {parse_error}"])
  if not isinstance(jwt_header, dict) or not isinstance(jwt_payload, dict):
    return _finish_mode2_result(result, "permerror", ["JWT header and payload must be JSON objects"])

  malformed_reasons: List[str] = []
  jwt_typ = jwt_header.get("typ", "")
  if jwt_typ != "airs-email+sd-jwt":
    malformed_reasons.append(f"typ header must be 'airs-email+sd-jwt' (got {jwt_typ!r})")
  algorithm = jwt_header.get("alg", "")
  if algorithm not in _ACCEPTED_ISSUER_JWS_ALGORITHMS:
    # AUD-F18: asymmetric algorithms only (RFC 8725); none / HS* never.
    malformed_reasons.append(
      f"Unsupported algorithm: {algorithm!r} (accepted: {', '.join(_ACCEPTED_ISSUER_JWS_ALGORITHMS)})"
    )
  kid = jwt_header.get("kid")
  if not isinstance(kid, str) or not kid:
    malformed_reasons.append("Missing kid header (required)")  # AUD-F51
  issuer = jwt_payload.get("iss")
  if not isinstance(issuer, str) or not issuer:
    malformed_reasons.append("Missing iss (issuer) claim in the Issuer-signed payload")
  sd_alg = jwt_payload.get("_sd_alg", "sha-256")
  if sd_alg != "sha-256":
    malformed_reasons.append(f"Unsupported _sd_alg: {sd_alg!r} (expected 'sha-256')")
  iat = jwt_payload.get("iat")
  if not isinstance(iat, int) or isinstance(iat, bool):
    malformed_reasons.append("Missing or non-integer iat claim (required)")
  exp = jwt_payload.get("exp")
  if exp is not None and (not isinstance(exp, int) or isinstance(exp, bool)):
    malformed_reasons.append("exp claim is not an integer")
  nonce = jwt_payload.get("nonce")
  if not isinstance(nonce, str) or not nonce:
    malformed_reasons.append("Missing nonce claim (required for message binding)")
  if malformed_reasons:
    result.issuer = issuer if isinstance(issuer, str) else ""
    return _finish_mode2_result(result, "permerror", malformed_reasons)

  result.issuer = issuer
  result.issued_at_unix = iat
  result.expires_at_unix = exp or 0

  # RFC 9901 disclosure processing needs only the digests, so the candidate
  # sub is known before discovery; it stays untrusted until the signature and
  # the digests have both verified (AUD-F52).
  processed_payload, disclosure_errors = process_sd_jwt_disclosures_per_rfc9901(jwt_payload, disclosure_strings)
  if disclosure_errors:
    return _finish_mode2_result(result, "fail", disclosure_errors)
  candidate_sub = processed_payload.get("sub")
  if candidate_sub is not None and (not isinstance(candidate_sub, str) or not candidate_sub):
    return _finish_mode2_result(result, "fail", ["sub is not a canonical AIRS identifier string"])

  # Step 2 (AUD-F03 / AUD-F16).
  if candidate_sub:
    try:
      current_issuer = current_issuer_resolver(candidate_sub)
    except TransientExternalLookupFailure as transient_lookup_failure:
      return _finish_mode2_result(result, "temperror", [
        f"AIRS resolution of {candidate_sub!r} could not complete: {transient_lookup_failure}"
      ])
    if not current_issuer:
      return _finish_mode2_result(result, "fail", [
        f"AIRS identity {candidate_sub!r} has no current issuer (identified verification fails)"
      ])
    if current_issuer != issuer:
      return _finish_mode2_result(result, "fail", [
        f"RDAP currentIssuer {current_issuer!r} does not match JWT iss {issuer!r}"
      ])
    result.rdap_issuer_verified = True
  elif issuer not in set(trusted_hidden_mode_issuers or ()):
    return _finish_mode2_result(result, "policy", [
      f"Hidden-identity presentation from issuer {issuer!r}, which local policy does not trust"
    ])

  # Step 3: authoritative key discovery and signature.
  public_key = issuer_public_key_override
  if public_key is None:
    try:
      public_key, discovery_failure = discover_registrar_signing_key(issuer, kid)
    except TransientExternalLookupFailure as transient_lookup_failure:
      return _finish_mode2_result(result, "temperror", [
        f"Issuer key discovery could not complete: {transient_lookup_failure}"
      ])
    if public_key is None:
      return _finish_mode2_result(result, "fail", [f"Issuer key discovery failed: {discovery_failure}"])
  jwt_compact_parts = header_value.strip().split("~")[0].split(".")
  signing_input = f"{jwt_compact_parts[0]}.{jwt_compact_parts[1]}".encode("ascii")
  signature_failure = verify_compact_jws_signature(public_key, algorithm, signing_input, jwt_signature_bytes)
  if signature_failure:
    return _finish_mode2_result(result, "fail", [f"Signature verification failed: {signature_failure}"])

  failure_reasons: List[str] = []
  policy_reasons: List[str] = []

  aid_claim = processed_payload.get("aid")
  disclosed_trust_tier = aid_claim.get("trust_tier") if isinstance(aid_claim, dict) else None
  if isinstance(disclosed_trust_tier, str) and disclosed_trust_tier:
    result.trust_tier = disclosed_trust_tier
  else:
    failure_reasons.append("aid.trust_tier is not disclosed (every presentation MUST disclose it)")  # AUD-F17

  if "cnf" in jwt_payload:
    result.carries_cnf_claim = True
    cnf_claim = jwt_payload.get("cnf")
    cnf_jwk = cnf_claim.get("jwk") if isinstance(cnf_claim, dict) else None
    from .mode1 import _compute_jwk_thumbprint_from_jwk_dict
    result.cnf_jwk_thumbprint = (
      _compute_jwk_thumbprint_from_jwk_dict(cnf_jwk) if isinstance(cnf_jwk, dict) else None
    ) or ""
    if not result.cnf_jwk_thumbprint:
      failure_reasons.append("cnf claim has no usable jwk")
    if not _message_has_hardware_attestation_field(email_headers, ordered_header_pairs):
      failure_reasons.append(
        "SD-JWT carries cnf (Combined mode) but the message has no Hardware-Attestation field"
      )

  if not skip_time_checks:
    if iat > reference_time_unix + max_timestamp_skew_seconds:
      failure_reasons.append(f"iat {iat} is materially in the future (reference time {reference_time_unix})")
    if exp is not None and exp < reference_time_unix:
      failure_reasons.append(f"Token has expired (exp={exp}, now={reference_time_unix})")
    # AUD-F49: age and lifetime limits are receiver policy, not forgery.
    if reference_time_unix - iat > max_proof_age_seconds:
      policy_reasons.append(
        f"iat is {reference_time_unix - iat}s old (local age policy allows {max_proof_age_seconds}s)"
      )
    if exp is not None and exp - iat > max_token_lifetime_seconds:
      policy_reasons.append(
        f"Token lifetime {exp - iat}s exceeds the local maximum {max_token_lifetime_seconds}s"
      )

  expected_nonce = _compute_message_binding_nonce(
    email_headers, body, iat, ordered_header_pairs=ordered_header_pairs,
  )
  if nonce != expected_nonce:
    failure_reasons.append(f"Message-binding nonce mismatch: got {nonce!r}, expected {expected_nonce!r}")

  result.disclosed_claims = {
    claim_name: claim_value for claim_name, claim_value in processed_payload.items()
    if claim_name not in _CLAIMS_THAT_MUST_BE_IN_THE_ISSUER_SIGNED_PAYLOAD
  }
  result.agent_identity_urn = candidate_sub or ""
  result.is_identified_mode = bool(candidate_sub)

  if failure_reasons:
    return _finish_mode2_result(result, "fail", failure_reasons)
  if policy_reasons:
    return _finish_mode2_result(result, "policy", policy_reasons)
  return _finish_mode2_result(result, "pass", [])


def _finish_mode2_result(
  result: Mode2VerificationResult,
  authentication_results_result: str,
  reasons: List[str],
) -> Mode2VerificationResult:
  result.authentication_results_result = authentication_results_result
  result.is_valid = authentication_results_result == "pass"
  result.failure_reasons = list(reasons)
  result.failure_reason = reasons[0] if reasons else ""
  return result


def _message_has_hardware_attestation_field(
  email_headers: Dict[str, str],
  ordered_header_pairs: Optional[List[tuple]],
) -> bool:
  if ordered_header_pairs:
    return any(str(name).strip().lower() == "hardware-attestation" for name, _value in ordered_header_pairs)
  return any(str(name).strip().lower() == "hardware-attestation" for name in email_headers)


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
  padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
  return base64.urlsafe_b64decode(padded)


def _base64url_decode_to_string(encoded: str) -> str:
  return _base64url_decode_to_bytes(encoded).decode("utf-8")


def _base64url_encode_no_padding(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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


def process_sd_jwt_disclosures_per_rfc9901(
  issuer_signed_payload: dict,
  disclosure_strings: List[str],
) -> tuple:
  """RFC 9901 Section 7.1 step 3: replace the digests embedded in the payload
  (object _sd arrays and {"...": digest} array elements, recursively, including
  inside disclosed values) with the disclosed claims.

  Rejects: undecodable or malformed disclosures, a digest that appears more
  than once, a disclosure of the wrong kind for its position, a disclosed claim
  name that is _sd / ... or already present, a top-level disclosure of a claim
  that must be in the Issuer-signed payload, and a disclosure not referenced
  by any digest. Digests with no disclosure (decoys, withheld claims) are dropped.

  Returns (processed_payload, []) or (None, [error]).
  """
  disclosures_by_digest: Dict[str, list] = {}
  for disclosure_b64 in disclosure_strings:
    digest = _base64url_encode_no_padding(hashlib.sha256(disclosure_b64.encode("ascii")).digest())
    try:
      decoded_disclosure = json.loads(_base64url_decode_to_string(disclosure_b64))
    except Exception as decode_error:
      return None, [f"Could not decode disclosure: {decode_error}"]
    if (
      not isinstance(decoded_disclosure, list)
      or len(decoded_disclosure) not in (2, 3)
      or not isinstance(decoded_disclosure[0], str)
      or (len(decoded_disclosure) == 3 and not isinstance(decoded_disclosure[1], str))
    ):
      return None, ["Disclosure is not [salt, claim_name, value] or [salt, value]"]
    if digest in disclosures_by_digest:
      return None, ["The same disclosure is presented more than once"]
    disclosures_by_digest[digest] = decoded_disclosure

  referenced_digests: set = set()
  embedded_digests_seen: set = set()

  def claim_digest_once(digest) -> Optional[list]:
    if not isinstance(digest, str):
      raise ValueError("an embedded digest is not a string")
    if digest in embedded_digests_seen:
      raise ValueError(f"digest {digest} appears more than once")
    embedded_digests_seen.add(digest)
    disclosure = disclosures_by_digest.get(digest)
    if disclosure is not None:
      referenced_digests.add(digest)
    return disclosure

  def process(value, is_top_level_object: bool = False):
    if isinstance(value, dict):
      processed_object = {
        claim_name: process(claim_value)
        for claim_name, claim_value in value.items() if claim_name != "_sd"
      }
      embedded_object_digests = value.get("_sd", [])
      if not isinstance(embedded_object_digests, list):
        raise ValueError("_sd is not an array")
      for digest in embedded_object_digests:
        disclosure = claim_digest_once(digest)
        if disclosure is None:
          continue
        if len(disclosure) != 3:
          raise ValueError("an _sd digest refers to an array-element disclosure")
        _salt, claim_name, claim_value = disclosure
        if claim_name in ("_sd", "..."):
          raise ValueError(f"disclosed claim name {claim_name!r} is not allowed")
        if claim_name in processed_object:
          raise ValueError(f"disclosed claim {claim_name!r} is already present")
        if is_top_level_object and claim_name in _CLAIMS_THAT_MUST_BE_IN_THE_ISSUER_SIGNED_PAYLOAD:
          raise ValueError(f"{claim_name!r} MUST NOT be selectively disclosable")
        processed_object[claim_name] = process(claim_value)
      return processed_object
    if isinstance(value, list):
      processed_array = []
      for element in value:
        if isinstance(element, dict) and list(element.keys()) == ["..."]:
          disclosure = claim_digest_once(element["..."])
          if disclosure is None:
            continue
          if len(disclosure) != 2:
            raise ValueError("an array-element digest refers to an object-property disclosure")
          processed_array.append(process(disclosure[1]))
        else:
          processed_array.append(process(element))
      return processed_array
    return value

  try:
    processed_payload = process(issuer_signed_payload, is_top_level_object=True)
  except (ValueError, RecursionError) as processing_error:
    return None, [f"SD-JWT disclosure processing failed: {processing_error}"]
  unreferenced_digests = set(disclosures_by_digest) - referenced_digests
  if unreferenced_digests:
    return None, [f"{len(unreferenced_digests)} disclosure(s) are not referenced by any digest"]
  processed_payload.pop("_sd_alg", None)
  return processed_payload, []


def _canonicalise_header_value_using_dkim2_header_hash_rules(raw_value: str) -> str:
  """Apply DKIM2 -06 Section 6.2 to a selected Mode-2 header value."""
  import re
  # Encoded words remain in their transmitted form because DKIM2 hashes the
  # header field octets after only its specified case and WSP operations.
  unfolded = re.sub(r"\r?\n(?=[ \t])", "", raw_value)
  compressed = re.sub(r"[ \t]+", " ", unfolded)
  return compressed.strip(" \t")


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

  email-03 Mode 2 covers a FIXED set: the nine always-covered fields
  (ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER), in THAT order, each once -- no oversigning and no bottom-up
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
      canon_value = _canonicalise_header_value_using_dkim2_header_hash_rules(
        lowered[required_name]
      )
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
  """Resolve a canonical aid at the AIRS Registry (RDAP) and return its
  currentIssuer (draft-drake-agent-identity-resolution).

  Returns None when the identity is unknown (HTTP 404) or has no current
  issuer: Registrar-backed verification then fails. Raises
  TransientExternalLookupFailure when the lookup cannot complete (network,
  timeout, HTTP 429/5xx): the result is temperror, never a silent pass (AUD-F03).
  """
  import urllib.request
  import urllib.error

  from urllib.parse import quote as url_quote

  urn_path = url_quote(agent_identity_urn, safe="")
  rdap_url = f"{_AIRS_RDAP_BASE_URL}/rdap/aid_identity/{urn_path}"

  try:
    request = urllib.request.Request(rdap_url, headers={"Accept": "application/rdap+json"})
    with urllib.request.urlopen(request, timeout=_RDAP_TIMEOUT_SECONDS) as response:
      data = json.loads(response.read().decode("utf-8"))
  except urllib.error.HTTPError as http_error:
    if http_error.code == 404:
      return None
    if http_error.code == 429 or http_error.code >= 500:
      raise TransientExternalLookupFailure(f"RDAP {rdap_url}: HTTP {http_error.code}") from http_error
    return None
  except (urllib.error.URLError, TimeoutError, OSError) as network_error:
    raise TransientExternalLookupFailure(f"RDAP {rdap_url}: {network_error}") from network_error
  except json.JSONDecodeError:
    return None
  aid_data = data.get("aid_data") if isinstance(data, dict) else None
  current_issuer = aid_data.get("currentIssuer") if isinstance(aid_data, dict) else None
  return current_issuer if isinstance(current_issuer, str) and current_issuer else None
