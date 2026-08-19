"""
CLI entry point for hw-attest-verify.

Usage:
  python -m hw_attest_verify [options] [path/to/email.eml]
  python -m hw_attest_verify [options] < raw_email.eml

Options:
  --auth-results     Output Authentication-Results lines (default: JSON)
  --hostname NAME    Hostname for A-R header (default: mailpal.com)
  --no-time-check    Skip timestamp/expiry checks (for archived emails)

Parses a raw email (RFC 5322 format), checks for Hardware-Attestation
and/or Hardware-Trust-Proof headers, and prints verification results.
"""

from __future__ import annotations

import email
import json
import sys
from email.policy import default as default_policy
from typing import List, Optional

from .mode1 import verify_hardware_attestation, VerificationResult
from .mode2 import verify_hardware_trust_proof, Mode2VerificationResult


def _extract_email_headers_as_ordered_pairs(msg: email.message.Message) -> list:
  """Extract email headers as an ordered list of (name, value) tuples.

  Preserves duplicate headers and original ordering, which is required
  for DKIM-compatible bottom-up header selection (RFC 6376 Section 3.7).
  """
  return [(key, msg[key]) for key in msg.keys()]


def _extract_email_headers_as_dict(msg: email.message.Message) -> dict:
  """Extract email headers into a lowercased dict (last value wins for duplicates)."""
  headers = {}
  for key in msg.keys():
    headers[key.strip().lower()] = msg[key]
  return headers


def _extract_body_bytes(msg: email.message.Message) -> bytes:
  """Extract the email body as bytes."""
  if msg.is_multipart():
    for part in msg.walk():
      content_type = part.get_content_type()
      if content_type == "text/plain":
        payload = part.get_payload(decode=True)
        if payload is not None:
          return payload
    first_payload = msg.get_payload(0)
    if first_payload is not None:
      body = first_payload.get_payload(decode=True)
      if body is not None:
        return body
  payload = msg.get_payload(decode=True)
  if payload is not None:
    return payload
  raw_payload = msg.get_payload()
  if isinstance(raw_payload, str):
    return raw_payload.encode("utf-8")
  return b""


def _format_mode1_auth_results_line(
  hostname: str,
  mode1_result: VerificationResult,
) -> str:
  """Format a Mode 1 result as an Authentication-Results header line."""
  status = "pass" if mode1_result.is_valid else "fail"
  line = (
    f"Authentication-Results: {hostname}; hw-attest={status}"
    f" header.typ={mode1_result.typ}"
    f" header.alg={mode1_result.alg}"
    f" header.tier={mode1_result.trust_tier}"
  )
  if mode1_result.agent_identity_urn:
    line += f" header.aid={mode1_result.agent_identity_urn}"
  if not mode1_result.is_valid and mode1_result.failure_reason:
    line += f" ({mode1_result.failure_reason})"
  return line


def _format_mode2_auth_results_line(
  hostname: str,
  mode2_result: Mode2VerificationResult,
) -> str:
  """Format a Mode 2 result as an Authentication-Results header line.

  Emits header.issuer (email-03): the property is the Issuer domain, not
  "registry" -- in the companion architecture "Registry" is the distinct
  Registry Operator role, while the party that signs the trust proof is
  the Issuer (Registrar). See draft-drake-email-hardware-attestation-03.
  """
  status = "pass" if mode2_result.is_valid else "fail"
  tier = mode2_result.trust_tier or "unknown"
  issuer_domain = "1id.com"
  issuer = mode2_result.issuer
  if issuer and "://" in issuer:
    from urllib.parse import urlparse
    issuer_domain = urlparse(issuer).hostname or issuer_domain
  line = (
    f"Authentication-Results: {hostname}; hw-trust={status}"
    f" header.trust_tier={tier}"
    f" header.issuer={issuer_domain}"
  )
  if not mode2_result.is_valid and mode2_result.failure_reason:
    line += f" ({mode2_result.failure_reason})"
  return line


def verify_email_from_raw(
  raw_email: str,
  skip_time_checks: bool = False,
) -> dict:
  """Parse a raw email and verify any attestation headers found.

  Returns a dict with mode1 and/or mode2 results, plus _raw result objects.
  """
  msg = email.message_from_string(raw_email, policy=default_policy)
  headers = _extract_email_headers_as_dict(msg)
  ordered_header_pairs = _extract_email_headers_as_ordered_pairs(msg)
  body = _extract_body_bytes(msg)

  results = {}
  time_kwargs = {}
  if skip_time_checks:
    time_kwargs["max_timestamp_skew_seconds"] = 999_999_999

  mode1_header_value = headers.get("hardware-attestation")
  if mode1_header_value:
    mode1_result = verify_hardware_attestation(
      header_value=mode1_header_value,
      email_headers=headers,
      body=body,
      ordered_header_pairs=ordered_header_pairs,
      allow_self_signed=True,
      **time_kwargs,
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
    mode2_result = verify_hardware_trust_proof(
      header_value=mode2_header_value,
      email_headers=headers,
      body=body,
      ordered_header_pairs=ordered_header_pairs,
      **time_kwargs,
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

  if not any(k.startswith("mode") for k in results):
    results["error"] = "No Hardware-Attestation or Hardware-Trust-Proof headers found"

  return results


def main() -> None:
  auth_results_output_mode = False
  auth_results_hostname = "mailpal.com"
  skip_time_checks = False
  file_path: Optional[str] = None

  positional_args: List[str] = []
  arg_index = 1
  while arg_index < len(sys.argv):
    arg = sys.argv[arg_index]
    if arg == "--auth-results":
      auth_results_output_mode = True
    elif arg == "--no-time-check":
      skip_time_checks = True
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

  results = verify_email_from_raw(raw_email, skip_time_checks=skip_time_checks)

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

