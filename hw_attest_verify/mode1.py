"""
Mode 1 verification: Hardware-Attestation header (CMS SignedData).

RFC: draft-drake-email-hardware-attestation-03, Section "Mode 1: Direct Hardware Attestation"

Verification steps:
  1. Parse the header parameters (v, typ, alg, h, bh, ts, chain, aid, bind)
  2. Decode the CMS SignedData strictly against the Version 1 profile and
     check its algorithm identifiers against alg (cms_signed_data_profile.py)
  3. Recompute the 92-byte attestation-input
     (label || h-hash || bh-raw || ts-bytes; the label is the 20 octets
     "AIRS-Email-Mode1-v1" and a zero octet, EML-12)
  4. Verify the CMS signature with the certificate SignerInfo.sid names
  5. Verify the Registrar binding JWS (aid + bind): the one trust path this
     version of the draft defines. The manufacturer-rooted path is RESERVED
     (EML-07): the draft names no evidence profile for it, so it is never
     evaluated or reported. A valid CMS signature with no successful trust
     path is `policy`, not `pass` (EML-01); an expired Registrar assertion
     is `policy` (EML-02); an aid in the test namespace is `policy` and
     reports no tier or aid (EML-13).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import math
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding

from .cms_signed_data_profile import (
  Mode1CmsProfileViolation,
  check_cms_algorithms_match_header_alg_and_signer_key,
  decode_mode1_detached_signed_data_strictly,
  find_signer_certificate_named_by_signer_info,
  load_every_certificate_in_signed_data_failing_closed,
)
from .parse import (
  parse_hardware_attestation_header,
  replace_single_chain_tag_value_with_empty_value_preserving_other_text,
)
from .signer_certificate_path_building_and_validation import (
  build_and_validate_certificate_path_from_signer_to_trusted_root,
)


from .parse import (
  ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER,
  MODE1_ATTESTATION_INPUT_PURPOSE_LABEL_INCLUDING_THE_TERMINATING_ZERO_OCTET,
  find_duplicate_singleton_header_field_names,
)
from .issuer_key_discovery import TransientExternalLookupFailure

_MINIMUM_HEADERS_FOR_RFC_MESSAGE_BINDING = list(ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER)

_DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS = 300

# Email draft -03 "Header Size Considerations": "A verifier SHOULD reject a field larger than its local limit as
# permerror without decoding it." A CMS object with a certificate chain is a few kilobytes; 64 KiB leaves ample room.
_DEFAULT_MAXIMUM_HEADER_FIELD_VALUE_OCTETS = 65536

# Email draft -03 "Registrar Binding JWS" and EML-13: an aid in the Registry's test namespace carries no production
# assurance. URN namespace identifiers and the "aid" namespace-specific prefix compare case-insensitively.
_REGISTRY_TEST_NAMESPACE_AID_URN_PREFIX_LOWERCASE = "urn:aid:test:"


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
  # Email draft -03 (EML-01): record which trust path(s) succeeded. Only the Registrar-bound path exists in this
  # version; manufacturer_rooted_path_verified stays None (reserved, EML-07: the draft names no evidence profile).
  registrar_binding_verified: bool = False
  manufacturer_rooted_path_verified: Optional[bool] = None
  # The Authentication-Results "path" property: "registrar", "manufacturer", "both", or "" when no path succeeded.
  trust_path_that_succeeded: str = ""
  # True when the CMS signature, the body hash and the structure all verified (steps 1-4), whatever the trust
  # outcome: a valid signature with no trust path is `policy` (EML-01), and this tells the two situations apart.
  cms_signature_and_message_binding_verified: bool = False
  # EML-02: the Registrar binding assertion's exp has passed (every other binding check succeeded).
  registrar_assertion_has_expired: bool = False
  # EML-13: the aid is in the Registry's test namespace (urn:aid:test:), so it carries no production assurance.
  aid_is_in_the_registry_test_namespace: bool = False
  # Result of validating the signer certificate path to caller-supplied roots. This is DIAGNOSTIC ONLY and is never a
  # trust path (EML-07): without a named evidence profile a certificate path to a local root is not manufacturer
  # evidence. None when no roots were supplied.
  signer_certificate_path_to_supplied_roots_is_valid: Optional[bool] = None
  signer_certificate_path_to_supplied_roots_failure: str = ""
  informational_notes: List[str] = field(default_factory=list)
  # Email draft IANA result name: pass / fail / policy / temperror / permerror.
  authentication_results_result: str = "fail"
  # For the Combined-mode checks: h= field names and the RFC 7638 thumbprint
  # of the CMS signer public key (set once the CMS signature verified).
  signed_header_names: List[str] = field(default_factory=list)
  signer_public_key_jwk_thumbprint: str = ""


_ACCEPTED_CMS_ALGORITHMS = {"RS256", "ES256", "PS256"}


def verify_hardware_attestation(
  header_value: str,
  email_headers: Dict[str, str],
  body: bytes,
  ordered_header_pairs: Optional[List[tuple]] = None,
  max_timestamp_skew_seconds: int = _DEFAULT_MAX_TIMESTAMP_SKEW_SECONDS,
  trusted_root_certificates: Optional[List[x509.Certificate]] = None,
  reference_time_unix: Optional[int] = None,
  allow_eddsa: bool = False,
  current_issuer_resolver: Optional[Callable[[str], Optional[str]]] = None,
  maximum_header_field_value_octets: int = _DEFAULT_MAXIMUM_HEADER_FIELD_VALUE_OCTETS,
  max_timestamp_age_seconds: Optional[int] = None,
) -> VerificationResult:
  """Verify a Mode 1 Hardware-Attestation header.

  Args:
    header_value: The raw Hardware-Attestation header value string.
    email_headers: Dict of email header name -> value (must include required headers).
    body: Raw email body bytes.
    max_timestamp_skew_seconds: Maximum allowed time drift (default 300s / 5 minutes): the clock-skew allowance for a
      ts or binding iat in the future and for a binding assertion that expired a moment ago.
    max_timestamp_age_seconds: Local freshness policy for how OLD ts may be (default: the same value as
      max_timestamp_skew_seconds, the strict policy an MSA applies, email draft -03 "Freshness at Submission"). A
      receiver that verifies after queueing and greylisting sets it to the lifetime of the Registrar mail assertions
      without also widening the tolerance for a ts from the future. A stale ts is a `policy` result, never `fail`.
    trusted_root_certificates: Optional trusted root certificates. The signer certificate path is validated to them
      and reported in result.signer_certificate_path_to_supplied_roots_is_valid, but it is diagnostic only: the draft
      (-03, EML-07) names no manufacturer-rooted evidence profile, so a path to a local root is never reported as a
      trust path and never changes the result.
    reference_time_unix: Unix timestamp to use for time checks (default: now).
    maximum_header_field_value_octets: Local size limit (-03 "Header Size Considerations"): a larger field value is
      rejected as permerror without being decoded.

  Returns:
    VerificationResult. is_valid is True only for the result name "pass", which needs at least one successful trust
    path (the Registrar-bound path in this version) and every evaluated path successful (EML-01).
  """
  result = VerificationResult()
  failure_reasons: List[str] = []

  if len(header_value) > maximum_header_field_value_octets:
    return _finish_mode1_result(result, "permerror", [
      f"Hardware-Attestation field value is {len(header_value)} octets, over the local limit of "
      f"{maximum_header_field_value_octets} (rejected without decoding)"
    ])

  parsed = parse_hardware_attestation_header(header_value)
  result.typ = parsed.typ
  result.trust_tier = parsed.trust_tier
  result.alg = parsed.alg
  result.timestamp_unix = parsed.ts
  result.agent_identity_urn = parsed.aid
  result.signed_header_names = list(parsed.signed_header_names)

  # Reject grammar errors before interpreting values; legal FWS is handled by
  # the individual tag grammar and is never globally stripped into validity.
  failure_reasons.extend(parsed.parse_errors)

  if parsed.version != 1:
    failure_reasons.append(f"Unsupported version: v={parsed.version} (expected v=1)")

  if not parsed.typ:
    failure_reasons.append("Missing typ parameter")

  if not parsed.alg:
    failure_reasons.append("Missing alg parameter")
  elif parsed.alg not in _ACCEPTED_CMS_ALGORITHMS:
    if parsed.alg == "EdDSA" and not allow_eddsa:
      failure_reasons.append(
        "EdDSA is not in the Version 1 CMS algorithm table (use --allow-eddsa to accept)"
      )
    elif parsed.alg != "EdDSA":
      failure_reasons.append(f"Unsupported algorithm: {parsed.alg}")

  if not parsed.chain_base64:
    failure_reasons.append("Missing or empty chain parameter")

  if not parsed.bh:
    failure_reasons.append("Missing bh parameter")

  if parsed.ts == 0:
    failure_reasons.append("Missing or invalid ts parameter")

  _REQUIRED_SIGNED_HEADERS = set(ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER)
  duplicate_singleton_names = find_duplicate_singleton_header_field_names(ordered_header_pairs)
  if duplicate_singleton_names:
    failure_reasons.append(
      f"Duplicate singleton headers (permerror): {', '.join(duplicate_singleton_names)}"
    )
  signed_names_lower = {n.strip().lower() for n in parsed.signed_header_names}
  missing_required_headers = _REQUIRED_SIGNED_HEADERS - signed_names_lower
  if missing_required_headers:
    failure_reasons.append(
      f"h= tag missing required headers: {', '.join(sorted(missing_required_headers))}"
    )

  if parsed.aid and not parsed.bind:
    failure_reasons.append(
      "aid is present but bind is absent (sender MUST NOT place aid without Registrar binding)"
    )
  elif parsed.bind and not parsed.aid:
    failure_reasons.append(
      "bind is present but aid is absent (aid and bind must both appear or both be absent)"
    )

  # Draft step 1: duplicates, unsupported versions, malformed encodings and
  # aid/bind without the other are permerror.
  if failure_reasons:
    return _finish_mode1_result(result, "permerror", failure_reasons)

  if reference_time_unix is None:
    reference_time_unix = int(time.time())

  # AUD-F49 / draft step 3: a stale (or future) ts is a local freshness POLICY
  # outcome, not a forged signature; it is reported only if nothing failed.
  # The staleness limit is a separate local policy from the clock-skew allowance (max_timestamp_age_seconds, default
  # equal to the skew): accepting an old ts must not also accept a ts from the future.
  freshness_policy_reason = ""
  allowed_timestamp_age_seconds = (
    max_timestamp_skew_seconds if max_timestamp_age_seconds is None else max_timestamp_age_seconds
  )
  timestamp_age_seconds = reference_time_unix - parsed.ts
  if timestamp_age_seconds < -max_timestamp_skew_seconds:
    freshness_policy_reason = (
      f"ts is {-timestamp_age_seconds}s in the future (local freshness "
      f"policy allows {max_timestamp_skew_seconds}s of clock skew)"
    )
  elif timestamp_age_seconds > allowed_timestamp_age_seconds:
    freshness_policy_reason = (
      f"ts is {timestamp_age_seconds}s old (local freshness "
      f"policy allows {allowed_timestamp_age_seconds}s)"
    )

  try:
    chain_der_bytes = base64.b64decode(parsed.chain_base64)
  except Exception as decode_error:
    failure_reasons.append(f"Could not base64-decode chain parameter: {decode_error}")
    return _finish_mode1_result(result, "permerror", failure_reasons)

  # AUD-F78: decode the chain= CMS strictly and fail closed on any deviation
  # from the Version 1 profile (the old byte-search helpers skipped unknown
  # structure and their SHA-256 check passed on unparseable input).
  try:
    decoded_signed_data = decode_mode1_detached_signed_data_strictly(chain_der_bytes)
    signed_data_certificates = load_every_certificate_in_signed_data_failing_closed(decoded_signed_data)
    signer_certificate = find_signer_certificate_named_by_signer_info(decoded_signed_data, signed_data_certificates)
    check_cms_algorithms_match_header_alg_and_signer_key(
      decoded_signed_data, parsed.alg, signer_certificate.public_key(), allow_eddsa=allow_eddsa,
    )
  except (Mode1CmsProfileViolation, ValueError, UnsupportedAlgorithm) as cms_profile_error:
    failure_reasons.append(f"CMS SignedData does not match the Version 1 profile: {cms_profile_error}")
    return _finish_mode1_result(result, "permerror", failure_reasons)

  result.certificate_chain_length = len(signed_data_certificates)

  try:
    header_value_without_chain_for_self_reference = (
      replace_single_chain_tag_value_with_empty_value_preserving_other_text(
        parsed.raw_header_value_with_original_tag_order
      )
    )
  except ValueError as chain_self_reference_error:
    failure_reasons.append(str(chain_self_reference_error))
    return _finish_mode1_result(result, "permerror", failure_reasons)

  attestation_input_92_bytes = _compute_attestation_input(
    email_headers=email_headers,
    body_bytes=body,
    attestation_timestamp_unix=parsed.ts,
    header_value_without_chain=header_value_without_chain_for_self_reference,
    signed_header_names_from_h_tag=parsed.signed_header_names,
    ordered_header_pairs=ordered_header_pairs,
  )

  # RFC 5652 s5.3: the signature is checked with the certificate SignerInfo.sid
  # names, not with whichever bundled certificate happens to verify it.
  leaf_certificate = None
  verification_error = _verify_signature_against_certificate(
    leaf_certificate=signer_certificate,
    signature_bytes=decoded_signed_data.signature_bytes,
    attestation_input_92_bytes=attestation_input_92_bytes,
    algorithm_name=parsed.alg,
  )
  if verification_error is None:
    leaf_certificate = signer_certificate
    result.signer_public_key_jwk_thumbprint = _compute_jwk_thumbprint_from_certificate(signer_certificate) or ""
  else:
    failure_reasons.append(
      f"Signature verification failed with the SignerInfo signer certificate: {verification_error}"
    )

  if leaf_certificate is not None:
    try:
      subject_common_names = leaf_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
      if subject_common_names:
        result.leaf_certificate_subject = subject_common_names[0].value
      else:
        result.leaf_certificate_subject = str(leaf_certificate.subject)
    except Exception:
      result.leaf_certificate_subject = "(could not extract subject)"

  try:
    received_bh_bytes = _base64url_decode(parsed.bh)
  except Exception as bh_decode_error:
    failure_reasons.append(f"Could not base64url-decode bh parameter: {bh_decode_error}")
    received_bh_bytes = None
  if received_bh_bytes is not None:
    canonicalised_body = _canonicalise_body_using_dkim_simple(body)
    recomputed_bh = hashlib.sha256(canonicalised_body).digest()
    if received_bh_bytes != recomputed_bh:
      failure_reasons.append("Body hash (bh) does not match recomputed hash")

  # Steps 1-4 are done: the CMS signature, the body hash and the structure all verified (or failure_reasons says why
  # not). That is a cryptographic fact about the message; whether anything established the property `typ` claims is
  # the separate trust-path question below (EML-01).
  result.cms_signature_and_message_binding_verified = not failure_reasons

  # Email draft -03 Mode 1 has one defined trust path in this version: the Registrar-bound path. A Registrar-bound
  # message (aid + bind) takes its authority from the binding JWS, verified against the AIRS Registry's currentIssuer;
  # its X.509 chain only carries the proof key and MAY be self-signed or otherwise untrusted (AUD-F20). The
  # manufacturer-rooted path is reserved (EML-07): the draft names no evidence profile for it, so it is not evaluated.
  message_is_registrar_bound = bool(parsed.aid and parsed.bind)
  aid_is_in_the_registry_test_namespace = bool(
    parsed.aid and parsed.aid.lower().startswith(_REGISTRY_TEST_NAMESPACE_AID_URN_PREFIX_LOWERCASE)
  )
  result.aid_is_in_the_registry_test_namespace = aid_is_in_the_registry_test_namespace
  transient_lookup_failure_reason = ""
  policy_reasons: List[str] = []
  if message_is_registrar_bound and leaf_certificate is not None and not failure_reasons:
    try:
      bind_verification_errors, bind_policy_reasons = _verify_registrar_binding_jws(
        bind_compact_jws=parsed.bind,
        expected_aid=parsed.aid,
        expected_typ=parsed.typ,
        signer_certificate=leaf_certificate,
        reference_time_unix=reference_time_unix,
        max_timestamp_skew_seconds=max_timestamp_skew_seconds,
        current_issuer_resolver=current_issuer_resolver,
      )
    except TransientExternalLookupFailure as transient_lookup_failure:
      transient_lookup_failure_reason = (
        f"Registrar binding could not be verified now (temperror): {transient_lookup_failure}"
      )
      bind_verification_errors, bind_policy_reasons = [], []
    if bind_verification_errors:
      failure_reasons.extend(bind_verification_errors)
    elif bind_policy_reasons:
      # EML-02: the CMS signature verified and the binding is otherwise sound, but the Registrar's assertion was no
      # longer current when checked. That is `policy` with the cause in the comment, not `fail`.
      result.registrar_assertion_has_expired = True
      policy_reasons.extend(bind_policy_reasons)
    elif not transient_lookup_failure_reason:
      result.registrar_binding_verified = True
      if aid_is_in_the_registry_test_namespace:
        # EML-13: "A verifier applying production policy MUST report it as policy, and MUST NOT report a tier or aid
        # property for it." The binding is checked in full first (a forged test-namespace binding stays a failure);
        # _finish_mode1_result then withholds the tier and aid.
        policy_reasons.append(
          f"aid {parsed.aid!r} is in the Registry's test namespace (urn:aid:test:) and carries no production "
          "assurance; no tier or aid is reported"
        )

  if trusted_root_certificates:
    # AUD-F80/F82: build the path from the SignerInfo signer certificate by issuer name + signature (CertificateSet
    # order means nothing) and apply the RFC 5280 CA rules to every issuing certificate, at reference time. The
    # outcome is DIAGNOSTIC ONLY (EML-07): without a named evidence profile a path to a local root is not
    # manufacturer evidence, so it is never a trust path and never changes the result.
    chain_validation_error = build_and_validate_certificate_path_from_signer_to_trusted_root(
      signer_certificate=signer_certificate,
      other_certificates_from_signed_data=[
        certificate for certificate in signed_data_certificates if certificate is not signer_certificate
      ],
      trusted_root_certificates=trusted_root_certificates,
      validation_time_utc=datetime.datetime.fromtimestamp(reference_time_unix, tz=datetime.timezone.utc),
    )
    result.signer_certificate_path_to_supplied_roots_is_valid = chain_validation_error is None
    result.signer_certificate_path_to_supplied_roots_failure = chain_validation_error or ""
    result.informational_notes.append(
      "The signer certificate path to the supplied roots was checked for information only: the draft names no "
      "manufacturer-rooted evidence profile (EML-07), so it is not a trust path"
    )

  result.trust_path_that_succeeded = "registrar" if result.registrar_binding_verified else ""

  if failure_reasons:
    return _finish_mode1_result(result, "fail", failure_reasons)
  if transient_lookup_failure_reason:
    return _finish_mode1_result(result, "temperror", [transient_lookup_failure_reason])

  if not result.trust_path_that_succeeded and not policy_reasons:
    # EML-01: a valid CMS signature with no successful trust path (for example a self-signed signer certificate with
    # no bind and no accepted manufacturer evidence) is `policy`, because nothing has established what `typ` claims.
    policy_reasons.append(
      "The CMS signature is valid but no trust path was established: the message has no aid/bind (no Registrar "
      "binding) and this version of the draft names no manufacturer-rooted evidence profile (EML-01, EML-07)"
    )
  if freshness_policy_reason:
    policy_reasons.append(freshness_policy_reason)
  if policy_reasons:
    return _finish_mode1_result(result, "policy", policy_reasons)
  return _finish_mode1_result(result, "pass", [])


def _finish_mode1_result(result: VerificationResult, authentication_results_result: str, reasons: List[str]) -> VerificationResult:
  """Set the A-R result name, validity and reasons. Draft: tier and aid are
  reported only when Registrar binding verification succeeded (a
  manufacturer-only or failed result MUST NOT report an authenticated aid), and
  never for an aid in the Registry's test namespace (EML-13)."""
  result.authentication_results_result = authentication_results_result
  result.is_valid = authentication_results_result == "pass"
  result.failure_reasons = list(reasons)
  result.failure_reason = reasons[0] if reasons else ""
  if not result.registrar_binding_verified or result.aid_is_in_the_registry_test_namespace:
    result.agent_identity_urn = None
    result.trust_tier = ""
  return result


_TYP_TO_EXPECTED_TRUST_TIER = {
  "TPM": "sovereign",
  "PIV": "portable",
  "ENC": "enclave",
  "VRT": "virtual",
  "SFT": "declared",
}


def _verify_registrar_binding_jws(
  bind_compact_jws: str,
  expected_aid: str,
  expected_typ: str,
  signer_certificate: x509.Certificate,
  reference_time_unix: int,
  max_timestamp_skew_seconds: int = 300,
  current_issuer_resolver: Optional[Callable[[str], Optional[str]]] = None,
) -> Tuple[List[str], List[str]]:
  """Verify a Registrar Binding JWS per the email draft "Registrar Binding JWS":
  iss MUST equal the Registry's currentIssuer for the aid (resolved via RDAP by
  default), and the key comes ONLY from that issuer's RFC 8414 JWK Set.

  Returns (failure_reasons, policy_reasons). An empty failure list with an empty policy list is success.
  Draft -03 (EML-02): an assertion whose exp has passed is NOT a failure; "a verifier that finds the assertion expired
  reports policy, with the cause in the comment, not fail: the CMS signature verified, and the Registrar's assertion
  was no longer current when checked". Every other check (including the issuer's signature over the assertion) still
  runs, so an expired assertion that is also forged stays a failure."""
  import json
  errors: List[str] = []
  policy_reasons: List[str] = []

  parts = bind_compact_jws.split(".")
  if len(parts) != 3:
    return ["bind JWS is not a valid compact JWS (expected 3 dot-separated parts)"], []

  try:
    header_json = _base64url_decode(parts[0]).decode("utf-8")
    payload_json = _base64url_decode(parts[1]).decode("utf-8")
    signature_bytes = _base64url_decode(parts[2])
  except Exception as decode_error:
    return [f"bind JWS base64url decode failed: {decode_error}"], []

  try:
    header = json.loads(header_json)
  except json.JSONDecodeError:
    return ["bind JWS header is not valid JSON"], []

  try:
    payload = json.loads(payload_json)
  except json.JSONDecodeError:
    return ["bind JWS payload is not valid JSON"], []

  if not isinstance(header, dict) or not isinstance(payload, dict):
    return ["bind JWS header and payload must each be a JSON object"], []

  bind_typ = header.get("typ", "")
  if bind_typ != "airs-email-binding+jwt":
    errors.append(
      f"bind JWS typ must be 'airs-email-binding+jwt' (got {bind_typ!r})"
    )

  bind_alg = header.get("alg", "")
  if not bind_alg or bind_alg in ("none", "HS256", "HS384", "HS512"):
    errors.append(f"bind JWS alg is invalid or symmetric: {bind_alg!r}")

  bind_iss = payload.get("iss", "")
  if not bind_iss:
    errors.append("bind JWS missing iss claim")

  bind_sub = payload.get("sub", "")
  if bind_sub != expected_aid:
    errors.append(
      f"bind JWS sub {bind_sub!r} does not match header aid {expected_aid!r}"
    )

  bind_iat = payload.get("iat")
  bind_exp = payload.get("exp")
  # RFC 7519 section 2: a NumericDate is a JSON number. A string, a boolean, null/NaN/Infinity and so on is a
  # malformed assertion to be rejected, never an exception that escapes the verifier.
  for numeric_date_claim_name, numeric_date_claim_value in (("iat", bind_iat), ("exp", bind_exp)):
    if numeric_date_claim_value is not None and (
      isinstance(numeric_date_claim_value, bool)
      or not isinstance(numeric_date_claim_value, (int, float))
      or not math.isfinite(numeric_date_claim_value)
    ):
      return errors + [f"bind JWS {numeric_date_claim_name} claim is not a finite JSON number"], []
  if bind_iat is None:
    errors.append("bind JWS missing iat claim")
  else:
    if int(bind_iat) > reference_time_unix + max_timestamp_skew_seconds:
      errors.append(f"bind JWS iat is in the future: {bind_iat}")

  if bind_exp is None:
    errors.append("bind JWS missing exp claim")
  else:
    if int(bind_exp) < reference_time_unix - max_timestamp_skew_seconds:
      # EML-02: expired is a `policy` outcome with the cause in the comment, not a failure (see the docstring).
      policy_reasons.append(
        f"The Registrar binding assertion has expired (exp={bind_exp}, now={reference_time_unix}); the CMS signature "
        "verified, but the assertion was no longer current when checked"
      )

  if bind_iat is not None and bind_exp is not None:
    if int(bind_exp) <= int(bind_iat):
      errors.append("bind JWS exp must be later than iat")

  cnf = payload.get("cnf")
  if not isinstance(cnf, dict) or "jwk" not in cnf:
    errors.append("bind JWS missing cnf.jwk claim")
  else:
    bind_jwk = cnf["jwk"]
    if any(k in bind_jwk for k in ("d", "p", "q", "dp", "dq", "qi", "k")):
      errors.append("bind JWS cnf.jwk contains private key parameters")
    else:
      signer_jwk_thumbprint = _compute_jwk_thumbprint_from_certificate(signer_certificate)
      bind_jwk_thumbprint = _compute_jwk_thumbprint_from_jwk_dict(bind_jwk)
      # AUD-F77: a malformed or unsupported cnf.jwk must fail, not skip the check.
      if not signer_jwk_thumbprint:
        errors.append("Could not compute JWK thumbprint from CMS signer certificate")
      elif not bind_jwk_thumbprint:
        errors.append("bind JWS cnf.jwk is malformed or of an unsupported key type")
      elif signer_jwk_thumbprint != bind_jwk_thumbprint:
        errors.append("bind JWS cnf.jwk thumbprint does not match CMS signer public key")

  # Draft -03 "Registrar Binding JWS": the aid claim object is REQUIRED and its trust_tier MUST correspond to typ.
  aid_claim = payload.get("aid")
  if not isinstance(aid_claim, dict) or not aid_claim.get("trust_tier"):
    errors.append("bind JWS missing the aid claim object with its trust_tier member")
  else:
    bind_trust_tier = aid_claim.get("trust_tier", "")
    expected_tier_from_typ = _TYP_TO_EXPECTED_TRUST_TIER.get(expected_typ, "")
    if expected_tier_from_typ and bind_trust_tier != expected_tier_from_typ:
      errors.append(
        f"bind JWS aid.trust_tier {bind_trust_tier!r} does not match "
        f"expected tier for typ={expected_typ!r} ({expected_tier_from_typ!r})"
      )

  if not errors:
    # AUD-F04: the binding must not bootstrap its own authority. Resolve the
    # (TransientExternalLookupFailure propagates to the caller -> temperror.)
    # aid at the Registry, require iss == currentIssuer, and take the key only
    # from that issuer's RFC 8414 JWK Set (AUD-F50: ES256, RS256 and PS256).
    from .issuer_key_discovery import discover_registrar_signing_key, verify_compact_jws_signature
    if current_issuer_resolver is None:
      from .mode2 import _resolve_issuer_via_rdap as current_issuer_resolver
    from .issuer_key_discovery import AirsIdentityResolutionRejected
    try:
      current_issuer = current_issuer_resolver(expected_aid)
    except AirsIdentityResolutionRejected as resolution_rejection:
      return errors + [str(resolution_rejection)], policy_reasons
    if not current_issuer:
      errors.append(f"AIRS identity {expected_aid!r} has no current issuer (Registry resolution failed)")
    elif bind_iss != current_issuer:
      errors.append(f"bind JWS iss {bind_iss!r} does not equal the Registry currentIssuer {current_issuer!r}")
    else:
      issuer_key, discovery_failure = discover_registrar_signing_key(current_issuer, header.get("kid"))
      if issuer_key is None:
        errors.append(f"bind JWS issuer key discovery failed: {discovery_failure}")
      else:
        signature_failure = verify_compact_jws_signature(
          issuer_key, bind_alg, f"{parts[0]}.{parts[1]}".encode("ascii"), signature_bytes)
        if signature_failure:
          errors.append(f"bind JWS: {signature_failure}")

  return errors, policy_reasons


def _compute_jwk_thumbprint_from_certificate(cert: x509.Certificate) -> Optional[str]:
  """Compute RFC 7638 JWK thumbprint from a certificate's public key."""
  pub = cert.public_key()
  return _compute_jwk_thumbprint_from_public_key(pub)


def _compute_jwk_thumbprint_from_public_key(pub) -> Optional[str]:
  """Compute RFC 7638 JWK thumbprint from a public key object."""
  import json

  try:
    if isinstance(pub, ec.EllipticCurvePublicKey):
      numbers = pub.public_numbers()
      curve_name = pub.curve.name
      crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(curve_name)
      if not crv:
        return None
      x_bytes = numbers.x.to_bytes((pub.key_size + 7) // 8, "big")
      y_bytes = numbers.y.to_bytes((pub.key_size + 7) // 8, "big")
      x_b64 = base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode("ascii")
      y_b64 = base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode("ascii")
      thumbprint_input = json.dumps(
        {"crv": crv, "kty": "EC", "x": x_b64, "y": y_b64},
        separators=(",", ":"), sort_keys=True,
      )
    elif isinstance(pub, rsa.RSAPublicKey):
      numbers = pub.public_numbers()
      e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
      n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
      e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode("ascii")
      n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")
      thumbprint_input = json.dumps(
        {"e": e_b64, "kty": "RSA", "n": n_b64},
        separators=(",", ":"), sort_keys=True,
      )
    else:
      return None
    return base64.urlsafe_b64encode(
      hashlib.sha256(thumbprint_input.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
  except Exception:
    return None


def _compute_jwk_thumbprint_from_jwk_dict(jwk: dict) -> Optional[str]:
  """Compute RFC 7638 JWK thumbprint from a JWK dictionary."""
  import json

  try:
    kty = jwk.get("kty", "")
    if kty == "EC":
      thumbprint_input = json.dumps(
        {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True,
      )
    elif kty == "RSA":
      thumbprint_input = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
        separators=(",", ":"), sort_keys=True,
      )
    else:
      return None
    return base64.urlsafe_b64encode(
      hashlib.sha256(thumbprint_input.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
  except (KeyError, Exception):
    return None


def _select_headers_bottom_up_per_dkim(
  header_names_from_h_tag: List[str],
  message_headers: List[tuple],
) -> List[Optional[tuple]]:
  """Select header instances per DKIM RFC 6376 Section 3.7 bottom-up rule.

  For each name in header_names_from_h_tag (left to right), scan
  message_headers from bottom to top and consume the bottommost unused
  instance. If no unused instance remains, return None for that slot
  (absent header -- contributes zero bytes to the hash).
  """
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


def _compute_attestation_input(
  email_headers: Dict[str, str],
  body_bytes: bytes,
  attestation_timestamp_unix: int,
  header_value_without_chain: str,
  signed_header_names_from_h_tag: Optional[List[str]] = None,
  ordered_header_pairs: Optional[List[tuple]] = None,
) -> bytes:
  """Compute the 92-byte attestation-input for Mode 1 (draft -03, EML-12).

  attestation-input = label || h-hash || bh-raw || ts-bytes   (exactly 92 octets)
  label = "AIRS-Email-Mode1-v1" || 0x00                       (20 octets)

  Per the draft: "The externally supplied detached content is the exact 92-octet
  attestation-input; implementations MUST NOT pre-hash that value and then
  present the digest to CMS as though it were the content." The label separates
  Mode 1 signing from every other use of the same proof key, so a proof key
  asked to sign arbitrary data cannot be tricked into producing a Mode 1 proof.
  """
  canonicalised_header_bytes = _canonicalise_headers_for_direct_attestation(
    email_headers, header_value_without_chain,
    signed_header_names_from_h_tag=signed_header_names_from_h_tag,
    ordered_header_pairs=ordered_header_pairs,
  )
  h_hash = hashlib.sha256(canonicalised_header_bytes).digest()

  canonicalised_body = _canonicalise_body_using_dkim_simple(body_bytes)
  bh_raw = hashlib.sha256(canonicalised_body).digest()

  ts_bytes = struct.pack(">Q", attestation_timestamp_unix)

  return (
    MODE1_ATTESTATION_INPUT_PURPOSE_LABEL_INCLUDING_THE_TERMINATING_ZERO_OCTET + h_hash + bh_raw + ts_bytes
  )


def _canonicalise_headers_for_direct_attestation(
  email_headers: Dict[str, str],
  header_value_without_chain: str,
  signed_header_names_from_h_tag: Optional[List[str]] = None,
  ordered_header_pairs: Optional[List[tuple]] = None,
) -> bytes:
  """Canonicalise headers for Mode 1 attestation digest, per RFC Section 5.2.

  Uses DKIM bottom-up header selection when ordered_header_pairs and
  signed_header_names_from_h_tag are provided. Absent headers in h=
  contribute zero bytes per RFC 6376 Section 3.7.
  """
  if ordered_header_pairs is not None and signed_header_names_from_h_tag is not None:
    selected = _select_headers_bottom_up_per_dkim(
      signed_header_names_from_h_tag, ordered_header_pairs,
    )
    lines: List[str] = []
    for entry in selected:
      if entry is None:
        continue
      lines.append(_canonicalise_selected_header_field_using_dkim2_header_hash_rules(
        entry[0], entry[1]
      ))
    lines.append(_canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
      header_value_without_chain
    ))
    return "".join(lines).encode("utf-8")

  # Without ordered instances, select by the SIGNED h= list (F44): each
  # listed name contributes its (single) value if present, nothing if absent;
  # repeated listings of a name select nothing more (no further instances).
  lowered = {k.strip().lower(): v for k, v in email_headers.items()}
  lines = []
  already_selected_names = set()
  for listed_name in signed_header_names_from_h_tag or []:
    lowered_listed_name = listed_name.strip().lower()
    if lowered_listed_name in already_selected_names or lowered_listed_name not in lowered:
      continue
    already_selected_names.add(lowered_listed_name)
    lines.append(_canonicalise_selected_header_field_using_dkim2_header_hash_rules(
      lowered_listed_name, lowered[lowered_listed_name]
    ))

  lines.append(_canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
    header_value_without_chain
  ))
  return "".join(lines).encode("utf-8")


def _canonicalise_selected_header_field_using_dkim2_header_hash_rules(
  raw_header_field_name: str,
  raw_header_field_value: str,
) -> str:
  """Apply DKIM2 -06 Section 6.2 mechanics to one AIRS-selected field.

  Draft -03 (EML-10) makes one exception: a Hardware-Trust-Proof field named in h is canonicalized like the
  Hardware-Attestation field itself (name lowercased, unfolded, every WSP character anywhere in the value deleted), so
  that no legal refolding of the long SD-JWT in transit changes the signed input."""
  lowercase_header_field_name = raw_header_field_name.strip(" \t").lower()
  unfolded_header_field_value = re.sub(r"\r?\n(?=[ \t])", "", raw_header_field_value)
  if lowercase_header_field_name == "hardware-trust-proof":
    # Computed outside the f-string: a backslash inside the braces of an f-string is a SyntaxError before Python
    # 3.12, and this package supports Python 3.9 and later.
    header_field_value_with_every_whitespace_character_deleted = re.sub(r"[ \t]+", "", unfolded_header_field_value)
    return f"{lowercase_header_field_name}:{header_field_value_with_every_whitespace_character_deleted}\r\n"
  compressed_header_field_value = re.sub(r"[ \t]+", " ", unfolded_header_field_value)
  header_field_value_without_colon_adjacent_or_trailing_wsp = (
    compressed_header_field_value.strip(" \t")
  )
  return (
    f"{lowercase_header_field_name}:"
    f"{header_field_value_without_colon_adjacent_or_trailing_wsp}\r\n"
  )


def _canonicalise_hardware_attestation_self_reference_using_dkim2_signature_rules(
  hardware_attestation_header_value_with_empty_chain: str,
) -> str:
  """Apply DKIM2 -06 Section 9.6 WSP deletion to the actual AIRS field."""
  unfolded_header_value = re.sub(
    r"\r?\n(?=[ \t])", "", hardware_attestation_header_value_with_empty_chain
  )
  header_value_without_wsp = re.sub(r"[ \t]+", "", unfolded_header_value)
  return f"hardware-attestation:{header_value_without_wsp}\r\n"


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


def _base64url_decode(encoded_string: str) -> bytes:
  """Decode base64url (no padding) to bytes."""
  padded = encoded_string + "=" * ((4 - len(encoded_string) % 4) % 4)
  return base64.urlsafe_b64decode(padded)


# Kept although Mode 1 now uses cms_signed_data_profile.py: the oneid-sdk
# tests import this reader to inspect SDK-built CMS objects.
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


def _verify_signature_against_certificate(
  leaf_certificate: x509.Certificate,
  signature_bytes: bytes,
  attestation_input_92_bytes: bytes,
  algorithm_name: str,
) -> Optional[str]:
  """Verify a CMS signature using the leaf certificate's public key.

  Returns None on success, or an error message string on failure.

  All signers (TPM, PIV, enclave, software) receive the 92-byte
  attestation-input and hash it internally via their sign() method
  (Go crypto.Signer for hardware, cryptography library for software).
  Verification therefore always uses SHA256() over the same 92-byte
  input -- no per-hardware-type branching is needed.
  """
  public_key = leaf_certificate.public_key()

  try:
    if algorithm_name == "ES256":
      if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"Certificate has {type(public_key).__name__}, expected EC for ES256"
      public_key.verify(signature_bytes, attestation_input_92_bytes, ec.ECDSA(hashes.SHA256()))
    elif algorithm_name == "RS256":
      if not isinstance(public_key, rsa.RSAPublicKey):
        return f"Certificate has {type(public_key).__name__}, expected RSA for RS256"
      public_key.verify(
        signature_bytes, attestation_input_92_bytes,
        padding.PKCS1v15(), hashes.SHA256(),
      )
    elif algorithm_name == "PS256":
      if not isinstance(public_key, rsa.RSAPublicKey):
        return f"Certificate has {type(public_key).__name__}, expected RSA for PS256"
      public_key.verify(
        signature_bytes, attestation_input_92_bytes,
        # AUD-F79: the Version 1 PS256 profile fixes the salt at 32 octets
        # (PSS.AUTO accepted any recoverable salt length).
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
      )
    elif algorithm_name == "EdDSA":
      if not isinstance(public_key, ed25519.Ed25519PublicKey):
        return f"Certificate has {type(public_key).__name__}, expected Ed25519 for EdDSA"
      public_key.verify(signature_bytes, attestation_input_92_bytes)
    else:
      return f"Unsupported algorithm: {algorithm_name}"
  except InvalidSignature:
    return "Cryptographic signature does not match"
  except Exception as unexpected_error:
    return f"Unexpected error during signature verification: {unexpected_error}"

  return None
