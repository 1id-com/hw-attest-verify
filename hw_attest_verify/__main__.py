"""
CLI entry point for hw-attest-verify.

Usage:
  python -m hw_attest_verify < raw_email.eml
  python -m hw_attest_verify path/to/email.eml

Parses a raw email (RFC 5322 format), checks for Hardware-Attestation
and/or Hardware-Trust-Proof headers, and prints verification results.
"""

from __future__ import annotations

import email
import json
import sys
from email.policy import default as default_policy
from typing import Optional

from .mode1 import verify_hardware_attestation
from .mode2 import verify_hardware_trust_proof


def _extract_email_headers_as_dict(msg: email.message.Message) -> dict:
  """Extract email headers into a lowercased dict."""
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


def verify_email_from_raw(raw_email: str) -> dict:
  """Parse a raw email and verify any attestation headers found.

  Returns a dict with mode1 and/or mode2 results.
  """
  msg = email.message_from_string(raw_email, policy=default_policy)
  headers = _extract_email_headers_as_dict(msg)
  body = _extract_body_bytes(msg)

  results = {}

  mode1_header_value = headers.get("hardware-attestation")
  if mode1_header_value:
    mode1_result = verify_hardware_attestation(
      header_value=mode1_header_value,
      email_headers=headers,
      body=body,
      allow_self_signed=True,
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

  mode2_header_value = headers.get("hardware-trust-proof")
  if mode2_header_value:
    mode2_result = verify_hardware_trust_proof(
      header_value=mode2_header_value,
      email_headers=headers,
      body=body,
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

  if not results:
    results["error"] = "No Hardware-Attestation or Hardware-Trust-Proof headers found"

  return results


def main() -> None:
  if len(sys.argv) > 1 and sys.argv[1] != "-":
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as email_file:
      raw_email = email_file.read()
  else:
    raw_email = sys.stdin.read()

  results = verify_email_from_raw(raw_email)
  print(json.dumps(results, indent=2, default=str))

  any_valid = any(
    r.get("is_valid", False) for r in results.values() if isinstance(r, dict)
  )
  sys.exit(0 if any_valid else 1)


if __name__ == "__main__":
  main()

