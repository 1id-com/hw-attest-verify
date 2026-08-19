"""Tests for Hardware-Attestation header parsing."""

import pytest
from hw_attest_verify.parse import parse_hardware_attestation_header


def test_parse_complete_header():
  header = (
    "v=1; typ=TPM; alg=RS256; "
    "h=from:to:subject:date:message-id; "
    "bh=abc123; ts=1710849600; "
    "chain=DEADBEEF; aid=urn:1id:agent:test-agent-id"
  )
  parsed = parse_hardware_attestation_header(header)

  assert parsed.version == 1
  assert parsed.typ == "TPM"
  assert parsed.trust_tier == "sovereign"
  assert parsed.alg == "RS256"
  assert parsed.signed_header_names == ["from", "to", "subject", "date", "message-id"]
  assert parsed.bh == "abc123"
  assert parsed.ts == 1710849600
  assert parsed.chain_base64 == "DEADBEEF"
  assert parsed.aid == "urn:1id:agent:test-agent-id"


def test_parse_enclave_header():
  header = "v=1; typ=ENC; alg=ES256; h=from:to:subject:date:message-id; bh=xyz; ts=1710849600; chain=ABCD"
  parsed = parse_hardware_attestation_header(header)
  assert parsed.trust_tier == "enclave"
  assert parsed.alg == "ES256"


def test_parse_piv_header():
  header = "v=1; typ=PIV; alg=ES256; h=from:to:subject:date:message-id; bh=xyz; ts=1710849600; chain=ABCD"
  parsed = parse_hardware_attestation_header(header)
  assert parsed.trust_tier == "portable"


def test_parse_unknown_typ():
  header = "v=1; typ=UNKNOWN; alg=RS256; h=from:to; bh=xyz; ts=1; chain=X"
  parsed = parse_hardware_attestation_header(header)
  assert parsed.trust_tier == "unknown"
  assert parsed.typ == "UNKNOWN"


def test_parse_missing_parameters():
  header = "v=1; typ=TPM"
  parsed = parse_hardware_attestation_header(header)
  assert parsed.version == 1
  assert parsed.typ == "TPM"
  assert parsed.alg == ""
  assert parsed.chain_base64 == ""
  assert parsed.bh == ""
  assert parsed.ts == 0
  assert parsed.aid is None


def test_parse_empty_string():
  parsed = parse_hardware_attestation_header("")
  assert parsed.version == 0
  assert parsed.typ == ""


def test_parse_preserves_raw_parameters():
  header = "v=1; typ=TPM; custom=hello"
  parsed = parse_hardware_attestation_header(header)
  assert parsed.raw_parameters["custom"] == "hello"

