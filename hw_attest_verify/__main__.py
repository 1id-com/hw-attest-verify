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

from .mode1 import verify_hardware_attestation, VerificationResult
from .mode2 import verify_hardware_trust_proof, Mode2VerificationResult


def _unfold_rfc5322_header_value(folded_value: str) -> str:
  """Unfold an RFC 5322 header value by removing CRLF+WSP continuations."""
  return re.sub(r'\r?\n[ \t]', '', folded_value)


def _extract_email_headers_as_ordered_pairs(msg: email.message.Message) -> list:
  """Extract email headers as an ordered list of (name, value) tuples.

  Preserves duplicate headers and original ordering, which is required
  for DKIM-compatible bottom-up header selection (RFC 6376 Section 3.7).
  Values are unfolded per RFC 5322 Section 2.2.3.
  """
  return [(key, _unfold_rfc5322_header_value(msg[key])) for key in msg.keys()]


def _extract_email_headers_as_dict(msg: email.message.Message) -> dict:
  """Extract email headers into a lowercased dict (last value wins for duplicates).

  Values are unfolded per RFC 5322 Section 2.2.3.
  """
  headers = {}
  for key in msg.keys():
    headers[key.strip().lower()] = _unfold_rfc5322_header_value(msg[key])
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


def _format_mode1_auth_results_line(
  hostname: str,
  mode1_result: VerificationResult,
) -> str:
  """Format a Mode 1 result as an Authentication-Results header line."""
  status = "pass" if mode1_result.is_valid else "fail"
  line = (
    f"Authentication-Results: {hostname}; hw-attest={status}"
    f" header.typ={_sanitize_auth_results_token(mode1_result.typ)}"
    f" header.alg={_sanitize_auth_results_token(mode1_result.alg)}"
    f" header.tier={_sanitize_auth_results_token(mode1_result.trust_tier)}"
  )
  if mode1_result.agent_identity_urn:
    line += f" header.aid={_sanitize_auth_results_token(mode1_result.agent_identity_urn)}"
  if not mode1_result.is_valid and mode1_result.failure_reason:
    line += f" ({_sanitize_auth_results_token(mode1_result.failure_reason)})"
  return line


def _format_mode2_auth_results_line(
  hostname: str,
  mode2_result: Mode2VerificationResult,
) -> str:
  """Format a Mode 2 result as an Authentication-Results header line.

  Per draft-drake-email-hardware-attestation-03 Section 8 (IANA):
    hw-trust=pass header.mode=identified header.tier=sovereign
      header.issuer=https://1id.com header.aid=urn:aid:global:id-...
  """
  status = "pass" if mode2_result.is_valid else "fail"
  tier = _sanitize_auth_results_token(mode2_result.trust_tier or "unknown")
  mode_value = "identified" if mode2_result.is_identified_mode else "hidden"

  line = (
    f"Authentication-Results: {hostname}; hw-trust={status}"
    f" header.mode={mode_value}"
    f" header.tier={tier}"
    f" header.issuer={_sanitize_auth_results_token(mode2_result.issuer or 'unknown')}"
  )
  if mode2_result.is_identified_mode and mode2_result.agent_identity_urn:
    line += f" header.aid={_sanitize_auth_results_token(mode2_result.agent_identity_urn)}"
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


def _verify_combined_mode_cross_checks(
  mode1_result: VerificationResult,
  mode2_result: Mode2VerificationResult,
  headers: dict,
  ordered_header_pairs,
) -> List[str]:
  """Cross-check consistency when both Mode 1 and Mode 2 are present.

  If both passed independently, verify that:
   - aid matches between Mode 1 and Mode 2 (if both disclose identity)
   - trust_tier is consistent
  """
  combined_mode_cross_check_errors: List[str] = []

  if mode1_result.agent_identity_urn and mode2_result.agent_identity_urn:
    if mode1_result.agent_identity_urn != mode2_result.agent_identity_urn:
      combined_mode_cross_check_errors.append(
        f"Mode 1 aid={mode1_result.agent_identity_urn!r} differs from "
        f"Mode 2 aid={mode2_result.agent_identity_urn!r}"
      )

  if mode1_result.trust_tier and mode2_result.trust_tier:
    if mode1_result.trust_tier != mode2_result.trust_tier:
      combined_mode_cross_check_errors.append(
        f"Mode 1 trust_tier={mode1_result.trust_tier!r} differs from "
        f"Mode 2 trust_tier={mode2_result.trust_tier!r}"
      )

  return combined_mode_cross_check_errors


def verify_email_from_raw(
  raw_email: str,
  skip_time_checks: bool = False,
  allow_self_signed: bool = False,
  trust_store_pem_path: Optional[str] = None,
  allow_eddsa: bool = False,
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

  _SINGLETON_HEADERS = {
    "hardware-attestation", "hardware-trust-proof",
    "from", "to", "subject", "date", "message-id",
  }
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
      mode2_result.failure_reason = duplicate_error_message
      mode2_result.failure_reasons = [duplicate_error_message]
    else:
      mode2_result = verify_hardware_trust_proof(
        header_value=mode2_header_value,
        email_headers=headers,
        body=body,
        ordered_header_pairs=ordered_header_pairs,
        skip_time_checks=skip_time_checks,
      )
    results["mode2_hardware_trust_proof"] = {
      "is_valid": mode2_result.is_valid,
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

  mode1_obj = results.get("_mode1_result_object")
  mode2_obj = results.get("_mode2_result_object")
  if mode1_obj and mode2_obj and mode1_obj.is_valid and mode2_obj.is_valid:
    combined_mode_errors = _verify_combined_mode_cross_checks(
      mode1_obj, mode2_obj, headers, ordered_header_pairs,
    )
    if combined_mode_errors:
      results["combined_mode_errors"] = combined_mode_errors

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

