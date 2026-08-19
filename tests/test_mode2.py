"""Tests for Mode 2 (Hardware-Trust-Proof / SD-JWT) verification."""

import base64
import hashlib
import json
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from hw_attest_verify.mode2 import (
  verify_hardware_trust_proof,
  _parse_sd_jwt_presentation,
  _compute_message_binding_nonce,
  _raw_rs_to_der,
  _verify_and_extract_disclosures,
  _base64url_encode_no_padding,
)


def _b64url_encode(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_test_ec_keypair():
  private_key = ec.generate_private_key(ec.SECP256R1())
  public_key = private_key.public_key()
  return private_key, public_key


def _sign_jwt_es256(private_key, header_json: str, payload_json: str) -> str:
  """Create a signed JWT using ES256."""
  header_b64 = _b64url_encode(header_json.encode("utf-8"))
  payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
  signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

  der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
  r, s = _decode_der_ecdsa_to_raw_rs(der_signature)
  raw_sig = r + s
  sig_b64 = _b64url_encode(raw_sig)

  return f"{header_b64}.{payload_b64}.{sig_b64}"


def _decode_der_ecdsa_to_raw_rs(der_sig: bytes) -> tuple:
  """Extract R and S from a DER-encoded ECDSA signature, zero-padded to 32 bytes."""
  if der_sig[0] != 0x30:
    raise ValueError("Not a DER SEQUENCE")
  offset = 2
  if der_sig[1] & 0x80:
    offset += der_sig[1] & 0x7f

  def _read_integer(data, pos):
    if data[pos] != 0x02:
      raise ValueError("Not a DER INTEGER")
    length = data[pos + 1]
    value_bytes = data[pos + 2:pos + 2 + length]
    return value_bytes.lstrip(b"\x00").rjust(32, b"\x00"), pos + 2 + length

  r_bytes, next_pos = _read_integer(der_sig, offset)
  s_bytes, _ = _read_integer(der_sig, next_pos)
  return r_bytes, s_bytes


def _make_disclosure(salt: str, claim_name: str, claim_value) -> str:
  """Create a base64url-encoded disclosure."""
  disclosure_json = json.dumps([salt, claim_name, claim_value])
  return _b64url_encode(disclosure_json.encode("utf-8"))


def _make_test_email_headers():
  return {
    "from": "agent@mailpal.com",
    "to": "bob@example.com",
    "subject": "Test message",
    "date": "Thu, 19 Mar 2026 10:00:00 +0000",
    "message-id": "<test-123@mailpal.com>",
  }


def _make_test_sd_jwt(private_key, email_headers, body, extra_claims=None):
  """Build a complete SD-JWT presentation with message-binding nonce."""
  iat = int(time.time())
  exp = iat + 300

  nonce = _compute_message_binding_nonce(email_headers, body, iat)

  trust_tier_disclosure = _make_disclosure("salt1", "trust_tier", "sovereign")
  trust_tier_hash = _b64url_encode(
    hashlib.sha256(trust_tier_disclosure.encode("ascii")).digest()
  )

  payload = {
    "iss": "https://1id.com",
    "sub": "urn:aid:1id.com:test-agent",
    "iat": iat,
    "exp": exp,
    "nonce": nonce,
    "_sd": [trust_tier_hash],
  }
  if extra_claims:
    payload.update(extra_claims)

  header = {"alg": "ES256", "typ": "sd-jwt"}

  jwt_compact = _sign_jwt_es256(
    private_key,
    json.dumps(header),
    json.dumps(payload),
  )

  return f"{jwt_compact}~{trust_tier_disclosure}~"


class TestSdJwtParsing:
  def test_parse_valid_sd_jwt_presentation(self):
    presentation = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.AAAA~disc1~disc2~"
    result = _parse_sd_jwt_presentation(presentation)
    assert result is not None
    header_json, payload_json, sig_bytes, disclosures = result
    assert "alg" in header_json
    assert "iss" in payload_json
    assert len(disclosures) == 2

  def test_parse_sd_jwt_without_disclosures(self):
    presentation = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.AAAA"
    result = _parse_sd_jwt_presentation(presentation)
    assert result is not None
    _, _, _, disclosures = result
    assert len(disclosures) == 0

  def test_parse_malformed_jwt_returns_none(self):
    result = _parse_sd_jwt_presentation("not-a-jwt")
    assert result is None

  def test_parse_empty_string_returns_none(self):
    result = _parse_sd_jwt_presentation("")
    assert result is None


class TestMessageBindingNonce:
  def test_nonce_computation_produces_base64url_string(self):
    headers = _make_test_email_headers()
    body = b"Hello, world!\r\n"
    nonce = _compute_message_binding_nonce(headers, body, 1710849600)
    assert isinstance(nonce, str)
    assert "=" not in nonce
    decoded = base64.urlsafe_b64decode(nonce + "==")
    assert len(decoded) == 32

  def test_nonce_changes_with_different_body(self):
    headers = _make_test_email_headers()
    nonce_a = _compute_message_binding_nonce(headers, b"Body A\r\n", 1710849600)
    nonce_b = _compute_message_binding_nonce(headers, b"Body B\r\n", 1710849600)
    assert nonce_a != nonce_b

  def test_nonce_changes_with_different_timestamp(self):
    headers = _make_test_email_headers()
    body = b"Same body\r\n"
    nonce_a = _compute_message_binding_nonce(headers, body, 1710849600)
    nonce_b = _compute_message_binding_nonce(headers, body, 1710849601)
    assert nonce_a != nonce_b


class TestDisclosureVerification:
  def test_valid_disclosure_extracts_claim(self):
    disclosure = _make_disclosure("salt", "trust_tier", "sovereign")
    disclosure_hash = _b64url_encode(
      hashlib.sha256(disclosure.encode("ascii")).digest()
    )
    claims, errors = _verify_and_extract_disclosures([disclosure], [disclosure_hash])
    assert errors == []
    assert claims["trust_tier"] == "sovereign"

  def test_disclosure_with_wrong_hash_reports_error(self):
    disclosure = _make_disclosure("salt", "trust_tier", "sovereign")
    claims, errors = _verify_and_extract_disclosures([disclosure], ["wrong_hash"])
    assert len(errors) == 1
    assert "not found in _sd array" in errors[0]


class TestRawRsToDer:
  def test_roundtrip_with_known_size(self):
    r = b"\x01" * 32
    s = b"\x02" * 32
    raw = r + s
    der = _raw_rs_to_der(raw)
    assert der[0] == 0x30
    assert len(der) > 64


class TestEndToEndMode2Verification:
  def test_valid_sd_jwt_verifies_successfully(self):
    private_key, public_key = _generate_test_ec_keypair()
    headers = _make_test_email_headers()
    body = b"Test email body content.\r\n"

    sd_jwt_presentation = _make_test_sd_jwt(private_key, headers, body)

    result = verify_hardware_trust_proof(
      header_value=sd_jwt_presentation,
      email_headers=headers,
      body=body,
      issuer_public_key_override=public_key,
    )
    assert result.is_valid, f"Expected valid but got: {result.failure_reasons}"
    assert result.trust_tier == "sovereign"
    assert result.issuer == "https://1id.com"

  def test_wrong_key_fails_verification(self):
    private_key, _ = _generate_test_ec_keypair()
    _, wrong_public_key = _generate_test_ec_keypair()
    headers = _make_test_email_headers()
    body = b"Test body.\r\n"

    sd_jwt_presentation = _make_test_sd_jwt(private_key, headers, body)

    result = verify_hardware_trust_proof(
      header_value=sd_jwt_presentation,
      email_headers=headers,
      body=body,
      issuer_public_key_override=wrong_public_key,
    )
    assert not result.is_valid
    assert any("Signature" in r or "signature" in r for r in result.failure_reasons)

  def test_modified_body_fails_nonce_check(self):
    private_key, public_key = _generate_test_ec_keypair()
    headers = _make_test_email_headers()
    original_body = b"Original body.\r\n"

    sd_jwt_presentation = _make_test_sd_jwt(private_key, headers, original_body)

    result = verify_hardware_trust_proof(
      header_value=sd_jwt_presentation,
      email_headers=headers,
      body=b"Modified body.\r\n",
      issuer_public_key_override=public_key,
    )
    assert not result.is_valid
    assert any("nonce" in r.lower() for r in result.failure_reasons)

  def test_expired_token_fails(self):
    private_key, public_key = _generate_test_ec_keypair()
    headers = _make_test_email_headers()
    body = b"Body.\r\n"

    old_time = int(time.time()) - 7200

    nonce = _compute_message_binding_nonce(headers, body, old_time)
    trust_tier_disclosure = _make_disclosure("salt1", "trust_tier", "sovereign")
    trust_tier_hash = _b64url_encode(
      hashlib.sha256(trust_tier_disclosure.encode("ascii")).digest()
    )

    payload = json.dumps({
      "iss": "https://1id.com",
      "sub": "urn:aid:1id.com:test",
      "iat": old_time,
      "exp": old_time + 300,
      "nonce": nonce,
      "_sd": [trust_tier_hash],
    })
    header = json.dumps({"alg": "ES256", "typ": "sd-jwt"})
    jwt = _sign_jwt_es256(private_key, header, payload)
    presentation = f"{jwt}~{trust_tier_disclosure}~"

    result = verify_hardware_trust_proof(
      header_value=presentation,
      email_headers=headers,
      body=body,
      issuer_public_key_override=public_key,
    )
    assert not result.is_valid
    assert any("expired" in r.lower() or "iat" in r.lower() for r in result.failure_reasons)

