"""Tests for Hardware-Attestation header parsing."""

import pytest
from hw_attest_verify.parse import (
  ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER,
  find_duplicate_singleton_header_field_names,
  parse_hardware_attestation_header,
  replace_single_chain_tag_value_with_empty_value_preserving_other_text,
)


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


def test_parse_preserves_raw_parameters_of_known_tags_only():
  # Email draft: this version defines no extension tags (AUD-F25).
  parsed = parse_hardware_attestation_header("v=1; typ=TPM; custom=hello")
  assert parsed.raw_parameters["typ"] == "TPM"
  assert "custom" not in parsed.raw_parameters
  assert any("Unrecognized tag 'custom'" in error for error in parsed.parse_errors)


def test_legal_fws_is_removed_from_h_chain_and_bind_values():
  header = (
    "v=1; typ=TPM; alg=RS256; h=from : to; bh=abc123; ts=1710849600; "
    "chain=REVB\r\n REJFRUY=; aid=id-abcde; bind=YWJj.\r\n ZGVm.Z2hp"
  )
  parsed = parse_hardware_attestation_header(header)
  assert parsed.signed_header_names == ["from", "to"]
  assert parsed.chain_base64 == "REVBREJFRUY="
  assert parsed.bind == "YWJj.ZGVm.Z2hp"
  assert parsed.parse_errors == []


@pytest.mark.parametrize(
  ("folded_fragment", "parsed_attribute_name", "expected_value_after_fws_removal"),
  [
    ("ts=1710 849600", "ts", 1710849600),
    ("h=from:messag\r\n e-id", "signed_header_names", ["from", "message-id"]),
    ("bh=abc 123", "bh", "abc123"),
    ("aid=urn:1id: agent:test", "aid", "urn:1id:agent:test"),
  ],
)
def test_embedded_wsp_inside_multi_character_values_is_removed_aud_f26(
  folded_fragment,
  parsed_attribute_name,
  expected_value_after_fws_removal,
):
  # Email draft: WSP/FWS anywhere inside a tag value is not part of the value
  # (the DKIM b=/bh= rule applied to every multi-character tag value).
  tag_segments = [
    "v=1", "typ=TPM", "alg=RS256", "h=from:to", "bh=abc123", "ts=1710849600",
    "chain=REVBREJFRUY=", "aid=id-abcde", "bind=YWJj.ZGVm.Z2hp",
  ]
  folded_tag_name = folded_fragment.split("=", 1)[0]
  header = "; ".join(
    folded_fragment if tag_segment.startswith(folded_tag_name + "=") else tag_segment
    for tag_segment in tag_segments
  )
  parsed = parse_hardware_attestation_header(header)
  assert parsed.parse_errors == []
  assert getattr(parsed, parsed_attribute_name) == expected_value_after_fws_removal


def test_duplicate_known_tag_and_unknown_tags_make_the_field_malformed():
  parsed = parse_hardware_attestation_header(
    "v=1; typ=TPM; alg=RS256; h=from:to; bh=abc123; ts=1; ts=2; "
    "chain=REVBREJFRUY=; future=one"
  )
  assert parsed.ts == 1
  assert "Duplicate parameter: ts" in parsed.parse_errors
  assert any("Unrecognized tag 'future'" in error for error in parsed.parse_errors)


def test_chain_is_emptied_without_reordering_or_dropping_extension_tags():
  actual_header_value = (
    "future=alpha; chain=REVB\r\n REJFRUY=; v=1; typ=TPM; alg=RS256; "
    "h=from:to; bh=abc123; ts=1"
  )
  emptied_header_value = replace_single_chain_tag_value_with_empty_value_preserving_other_text(
    actual_header_value
  )
  assert emptied_header_value == (
    "future=alpha; chain=; v=1; typ=TPM; alg=RS256; h=from:to; bh=abc123; ts=1"
  )


# Email draft (2026-09-24): both modes always cover these nine fields, in this order.
def test_always_covered_header_fields_are_the_nine_in_spec_order():
  assert list(ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER) == [
    "from", "to", "subject", "date", "message-id",
    "reply-to", "mime-version", "content-type", "content-transfer-encoding",
  ]


def test_each_duplicated_always_covered_or_attestation_field_is_reported_case_insensitively():
  ordered_header_pairs = [
    ("From", "a@example.com"),
    ("Content-Type", "text/plain"),
    ("content-type", "text/html"),
    ("Received", "by mx1"),
    ("Received", "by mx2"),
    ("Hardware-Trust-Proof", "x"),
    ("hardware-trust-proof", "y"),
  ]
  assert sorted(find_duplicate_singleton_header_field_names(ordered_header_pairs)) == [
    "content-type", "hardware-trust-proof",
  ]


_WELL_FORMED_TAGS_IN_ABNF_ORDER = [
  "v=1", "typ=TPM", "alg=RS256", "h=from:to", "bh=abc123", "ts=1710849600", "chain=QUJD",
]


def test_unrecognized_tag_makes_the_field_malformed_aud_f25():
  parsed = parse_hardware_attestation_header("; ".join(_WELL_FORMED_TAGS_IN_ABNF_ORDER + ["future=alpha"]))
  assert any("Unrecognized tag 'future'" in error for error in parsed.parse_errors)


def test_tags_out_of_abnf_order_make_the_field_malformed_aud_f74():
  swapped_tags = list(_WELL_FORMED_TAGS_IN_ABNF_ORDER)
  swapped_tags[0], swapped_tags[1] = swapped_tags[1], swapped_tags[0]
  parsed = parse_hardware_attestation_header("; ".join(swapped_tags))
  assert any("required order" in error for error in parsed.parse_errors)
  assert not parse_hardware_attestation_header("; ".join(_WELL_FORMED_TAGS_IN_ABNF_ORDER) + ";").parse_errors


def test_fws_inside_every_multi_character_value_is_removed_aud_f26():
  folded_header_value = (
    "v=1; typ=TPM; alg=RS256; h=fr\r\n om:to :\r\n\tsubj ect; bh=ab\r\n c123; ts=17108\r\n 49600; "
    "chain=QU\r\n JD; aid=id-abcde-\r\n fghij; bind=aaa.\r\n bbb.ccc"
  )
  parsed = parse_hardware_attestation_header(folded_header_value)
  assert parsed.parse_errors == []
  assert parsed.signed_header_names == ["from", "to", "subject"]
  assert parsed.bh == "abc123"
  assert parsed.ts == 1710849600
  assert parsed.chain_base64 == "QUJD"
  assert parsed.aid == "id-abcde-fghij"
  assert parsed.bind == "aaa.bbb.ccc"


def test_whitespace_inside_single_token_values_is_still_malformed():
  parsed = parse_hardware_attestation_header("v=1; typ=T PM; alg=RS256; h=from; bh=abc; ts=1; chain=QUJD")
  assert parsed.parse_errors


def test_no_duplicates_and_missing_pairs_report_nothing():
  assert not find_duplicate_singleton_header_field_names([("From", "a"), ("To", "b")])
  assert not find_duplicate_singleton_header_field_names(None)
