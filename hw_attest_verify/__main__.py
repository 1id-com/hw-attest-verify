"""
CLI entry point for hw-attest-verify.

Usage:
  python -m hw_attest_verify [options] [path/to/email.eml]
  python -m hw_attest_verify [options] < raw_email.eml

Options:
  --auth-results       Output Authentication-Results lines (default: JSON)
  --hostname NAME      Hostname for A-R header (default: mailpal.com)
  --no-time-check      Skip timestamp/expiry checks (for archived emails)
  --allow-self-signed  Accept self-signed certificates (INSECURE -- testing only)
  --trust-store PATH   PEM file containing trusted root CAs for chain validation
                       (the manufacturer-rooted Mode 1 path; Registrar-bound
                       Mode 1 with aid/bind needs no trust store)
  --trust-hidden-issuer URI
                       Local policy: trust this issuer for hidden-identity
                       Mode 2 (no sub). Repeatable. Without it hidden mode
                       yields hw-trust=policy.

Parses a raw email (RFC 5322 format), checks for Hardware-Attestation
and/or Hardware-Trust-Proof headers, and prints verification results.
"""

from __future__ import annotations

import email
import json
import re
import sys
from email.policy import compat32 as compat32_policy
from typing import List, Optional

from .combined import apply_combined_mode_requirements_to_mode2_result
from .mode1 import verify_hardware_attestation, VerificationResult
from .mode2 import verify_hardware_trust_proof, Mode2VerificationResult


def _unfold_rfc5322_header_value(folded_value: str) -> str:
  """Unfold an RFC 5322 header value per Section 2.2.3: remove CRLF, keep WSP."""
  return re.sub(r'\r?\n(?=[ \t])', '', folded_value)


def _extract_email_headers_as_ordered_pairs(msg: email.message.Message) -> list:
  """Extract email headers as an ordered list of (name, value) tuples.

  Preserves duplicate headers and original ordering, which is required
  for DKIM-compatible bottom-up header selection (RFC 6376 Section 3.7).
  Values are unfolded per RFC 5322 Section 2.2.3.
  """
  # raw_items() preserves the value belonging to each duplicate instance;
  # msg[key] would return the first instance repeatedly and break bottom-up h=.
  return [
    (key, _unfold_rfc5322_header_value(value))
    for key, value in msg.raw_items()
  ]


def _extract_email_headers_as_dict(msg: email.message.Message) -> dict:
  """Extract email headers into a lowercased dict (last value wins for duplicates).

  Values are unfolded per RFC 5322 Section 2.2.3.
  """
  headers = {}
  for key, value in msg.raw_items():
    headers[key.strip().lower()] = _unfold_rfc5322_header_value(value)
  return headers


def _extract_body_bytes_from_raw_email(raw_email: str) -> bytes:
  """Extract the raw body bytes from an RFC 5322 message.

  The body is everything after the first blank line (CRLFCRLF or LFLF).
  This preserves MIME boundaries, transfer encoding, and exact bytes
  needed for DKIM-compatible body hashing (bh).
  """
  raw_bytes = raw_email.encode("utf-8") if isinstance(raw_email, str) else raw_email
  for separator in (b"\r\n\r\n", b"\n\n"):
    separator_position = raw_bytes.find(separator)
    if separator_position >= 0:
      return raw_bytes[separator_position + len(separator):]
  return b""


def _sanitize_auth_results_token(value: str) -> str:
  """Remove characters that could inject into Authentication-Results parsing.

  Strips control characters, semicolons, parentheses, and newlines
  to prevent header injection via attacker-controlled field values.
  """
  import re
  sanitized = re.sub(r"[\x00-\x1f\x7f;()\r\n]", "", str(value))
  return sanitized.strip() or "unknown"


_RFC2045_TOKEN_CHARACTERS = set(
  "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz{|}~"
)


def _authentication_results_property_value(value: str) -> str:
  """RFC 8601 pvalue: an RFC 2045 token as is, anything else (a URN or URL
  contains ':' and '/') as a quoted-string (review 072 #10)."""
  sanitized = _sanitize_auth_results_token(value)
  if sanitized and all(character in _RFC2045_TOKEN_CHARACTERS for character in sanitized):
    return sanitized
  return '"' + sanitized.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _format_mode1_auth_results_line(
  hostname: str,
  mode1_result: VerificationResult,
) -> str:
  """Format a Mode 1 result as an Authentication-Results header line. tier and
  aid appear only when Registrar binding verification succeeded."""
  status = mode1_result.authentication_results_result
  line = (
    f"Authentication-Results: {hostname}; hw-attest={status}"
    f" header.typ={_authentication_results_property_value(mode1_result.typ)}"
    f" header.alg={_authentication_results_property_value(mode1_result.alg)}"
  )
  if mode1_result.trust_tier:
    line += f" header.tier={_authentication_results_property_value(mode1_result.trust_tier)}"
  if mode1_result.agent_identity_urn:
    line += f" header.aid={_authentication_results_property_value(mode1_result.agent_identity_urn)}"
  if not mode1_result.is_valid and mode1_result.failure_reason:
    line += f" ({_sanitize_auth_results_token(mode1_result.failure_reason)})"
  return line


def _format_mode2_auth_results_line(
  hostname: str,
  mode2_result: Mode2VerificationResult,
) -> str:
  """Format a Mode 2 result as an Authentication-Results header line.

  Per draft-drake-email-hardware-attestation Section 8 (IANA):
    hw-trust=pass header.mode=identified header.tier=sovereign
      header.issuer=https://1id.com header.aid=urn:aid:global:id-...
  """
  status = mode2_result.authentication_results_result
  mode_value = "identified" if mode2_result.is_identified_mode else "hidden"

  # OWN-033: a property whose value is not known is omitted (like the MailPal
  # milter does) rather than reported as "unknown", which is no tier value.
  line = (
    f"Authentication-Results: {hostname}; hw-trust={status}"
    f" header.mode={mode_value}"
  )
  if mode2_result.trust_tier:
    line += f" header.tier={_authentication_results_property_value(mode2_result.trust_tier)}"
  if mode2_result.issuer:
    line += f" header.issuer={_authentication_results_property_value(mode2_result.issuer)}"
  if mode2_result.is_identified_mode and mode2_result.agent_identity_urn:
    line += f" header.aid={_authentication_results_property_value(mode2_result.agent_identity_urn)}"
  if not mode2_result.is_valid and mode2_result.failure_reason:
    line += f" ({_sanitize_auth_results_token(mode2_result.failure_reason)})"
  return line


def _load_trusted_root_certificates_from_pem_file(pem_file_path: str):
  """Load X.509 certificates from a PEM file for use as trusted roots."""
  from cryptography import x509
  certificates = []
  try:
    with open(pem_file_path, "rb") as pem_file:
      pem_data = pem_file.read()
    for match in pem_data.split(b"-----END CERTIFICATE-----"):
      block = match.strip()
      if b"-----BEGIN CERTIFICATE-----" in block:
        full_pem = block + b"\n-----END CERTIFICATE-----\n"
        try:
          cert = x509.load_pem_x509_certificate(full_pem)
          certificates.append(cert)
        except Exception:
          continue
  except (FileNotFoundError, OSError):
    pass
  return certificates


def verify_email_from_raw(
  raw_email: str,
  skip_time_checks: bool = False,
  allow_self_signed: bool = False,
  trust_store_pem_path: Optional[str] = None,
  allow_eddsa: bool = False,
  trusted_hidden_mode_issuers: Optional[List[str]] = None,
) -> dict:
  """Parse a raw email and verify any attestation headers found.

  Returns a dict with mode1 and/or mode2 results, plus _raw result objects.
  """
  trusted_root_certificates = None
  if trust_store_pem_path:
    trusted_root_certificates = _load_trusted_root_certificates_from_pem_file(trust_store_pem_path)
    if not trusted_root_certificates:
      import logging
      logging.getLogger("hw_attest_verify").warning(
        "Trust store %s loaded but contained no parseable certificates", trust_store_pem_path
      )
  msg = email.message_from_string(raw_email, policy=compat32_policy)
  headers = _extract_email_headers_as_dict(msg)
  ordered_header_pairs = _extract_email_headers_as_ordered_pairs(msg)
  body = _extract_body_bytes_from_raw_email(raw_email)

  results = {}
  time_kwargs = {}
  if skip_time_checks:
    time_kwargs["max_timestamp_skew_seconds"] = 999_999_999

  from .parse import SINGLETON_HEADER_FIELD_NAMES_FOR_VERIFICATION
  _SINGLETON_HEADERS = SINGLETON_HEADER_FIELD_NAMES_FOR_VERIFICATION
  header_name_counts: dict = {}
  for name, _value in ordered_header_pairs:
    lowered_name = name.strip().lower()
    header_name_counts[lowered_name] = header_name_counts.get(lowered_name, 0) + 1
  duplicate_header_violations = [
    name for name, count in header_name_counts.items()
    if count > 1 and name in _SINGLETON_HEADERS
  ]

  if duplicate_header_violations:
    duplicate_error_message = (
      f"Duplicate singleton headers (permerror): {', '.join(sorted(duplicate_header_violations))}"
    )

  mode1_header_value = headers.get("hardware-attestation")
  if mode1_header_value:
    if duplicate_header_violations:
      mode1_result = VerificationResult()
      mode1_result.is_valid = False
      mode1_result.authentication_results_result = "permerror"
      mode1_result.failure_reason = duplicate_error_message
      mode1_result.failure_reasons = [duplicate_error_message]
    else:
      mode1_result = verify_hardware_attestation(
        header_value=mode1_header_value,
        email_headers=headers,
        body=body,
        ordered_header_pairs=ordered_header_pairs,
        allow_self_signed=allow_self_signed,
        trusted_root_certificates=trusted_root_certificates,
        allow_eddsa=allow_eddsa,
        **{k: v for k, v in time_kwargs.items() if k == "max_timestamp_skew_seconds"},
      )
    results["mode1_hardware_attestation"] = {
      "is_valid": mode1_result.is_valid,
      "result": mode1_result.authentication_results_result,
      "registrar_binding_verified": mode1_result.registrar_binding_verified,
      "manufacturer_rooted_path_verified": mode1_result.manufacturer_rooted_path_verified,
      "trust_tier": mode1_result.trust_tier,
      "typ": mode1_result.typ,
      "alg": mode1_result.alg,
      "timestamp_unix": mode1_result.timestamp_unix,
      "agent_identity_urn": mode1_result.agent_identity_urn,
      "leaf_certificate_subject": mode1_result.leaf_certificate_subject,
      "certificate_chain_length": mode1_result.certificate_chain_length,
      "failure_reason": mode1_result.failure_reason,
      "failure_reasons": mode1_result.failure_reasons,
    }
    results["_mode1_result_object"] = mode1_result

  mode2_header_value = headers.get("hardware-trust-proof")
  if mode2_header_value:
    if duplicate_header_violations:
      mode2_result = Mode2VerificationResult()
      mode2_result.is_valid = False
      mode2_result.authentication_results_result = "permerror"
      mode2_result.failure_reason = duplicate_error_message
      mode2_result.failure_reasons = [duplicate_error_message]
    else:
      mode2_result = verify_hardware_trust_proof(
        header_value=mode2_header_value,
        email_headers=headers,
        body=body,
        ordered_header_pairs=ordered_header_pairs,
        skip_time_checks=skip_time_checks,
        trusted_hidden_mode_issuers=trusted_hidden_mode_issuers,
      )
    if mode1_header_value:
      combined_mode_errors = apply_combined_mode_requirements_to_mode2_result(
        results["_mode1_result_object"], mode2_result,
      )
      if combined_mode_errors:
        results["combined_mode_errors"] = combined_mode_errors
    results["mode2_hardware_trust_proof"] = {
      "is_valid": mode2_result.is_valid,
      "result": mode2_result.authentication_results_result,
      "mode": "identified" if mode2_result.is_identified_mode else "hidden",
      "trust_tier": mode2_result.trust_tier,
      "agent_identity_urn": mode2_result.agent_identity_urn,
      "issuer": mode2_result.issuer,
      "issued_at_unix": mode2_result.issued_at_unix,
      "expires_at_unix": mode2_result.expires_at_unix,
      "disclosed_claims": mode2_result.disclosed_claims,
      "failure_reason": mode2_result.failure_reason,
      "failure_reasons": mode2_result.failure_reasons,
    }
    results["_mode2_result_object"] = mode2_result

  if not any(k.startswith("mode") for k in results):
    results["error"] = "No Hardware-Attestation or Hardware-Trust-Proof headers found"

  return results


def main() -> None:
  auth_results_output_mode = False
  auth_results_hostname = "mailpal.com"
  skip_time_checks = False
  allow_self_signed = False
  allow_eddsa = False
  trust_store_pem_path: Optional[str] = None
  trusted_hidden_mode_issuers: List[str] = []
  file_path: Optional[str] = None

  positional_args: List[str] = []
  arg_index = 1
  while arg_index < len(sys.argv):
    arg = sys.argv[arg_index]
    if arg == "--auth-results":
      auth_results_output_mode = True
    elif arg == "--no-time-check":
      skip_time_checks = True
    elif arg == "--allow-self-signed":
      allow_self_signed = True
    elif arg == "--allow-eddsa":
      allow_eddsa = True
    elif arg == "--trust-store" and arg_index + 1 < len(sys.argv):
      arg_index += 1
      trust_store_pem_path = sys.argv[arg_index]
    elif arg == "--trust-hidden-issuer" and arg_index + 1 < len(sys.argv):
      arg_index += 1
      trusted_hidden_mode_issuers.append(sys.argv[arg_index])
    elif arg == "--hostname" and arg_index + 1 < len(sys.argv):
      arg_index += 1
      auth_results_hostname = sys.argv[arg_index]
    elif not arg.startswith("-"):
      positional_args.append(arg)
    arg_index += 1

  if positional_args:
    file_path = positional_args[0]

  if file_path and file_path != "-":
    with open(file_path, "r", encoding="utf-8", errors="replace") as email_file:
      raw_email = email_file.read()
  else:
    raw_email = sys.stdin.read()

  results = verify_email_from_raw(
    raw_email,
    skip_time_checks=skip_time_checks,
    allow_self_signed=allow_self_signed,
    trust_store_pem_path=trust_store_pem_path,
    allow_eddsa=allow_eddsa,
    trusted_hidden_mode_issuers=trusted_hidden_mode_issuers,
  )

  if auth_results_output_mode:
    mode1_obj = results.get("_mode1_result_object")
    mode2_obj = results.get("_mode2_result_object")
    if mode1_obj:
      print(_format_mode1_auth_results_line(auth_results_hostname, mode1_obj))
    if mode2_obj:
      print(_format_mode2_auth_results_line(auth_results_hostname, mode2_obj))
    if not mode1_obj and not mode2_obj:
      print(f"Authentication-Results: {auth_results_hostname}; none")
  else:
    output = {k: v for k, v in results.items() if not k.startswith("_")}
    print(json.dumps(output, indent=2, default=str))

  any_valid = any(
    r.get("is_valid", False) for k, r in results.items()
    if isinstance(r, dict) and not k.startswith("_")
  )
  sys.exit(0 if any_valid else 1)


if __name__ == "__main__":
  main()
