"""
Combined mode end to end under email draft -03: a complete RFC 5322 message that carries BOTH Hardware-Attestation
(Mode 1, Registrar-bound) and Hardware-Trust-Proof (Mode 2, SD-JWT with cnf), built here from the draft's text alone
(an independent producer: no library function computes any signed input), then verified with the public CLI entry
point verify_email_from_raw().

What this proves that the unit tests cannot:
  - all thirteen always-covered fields present in one message are covered by BOTH proofs (EML-11);
  - the 92-octet attestation-input with its purpose label verifies (EML-12);
  - a Hardware-Trust-Proof named in `h` is canonicalized by deleting every WSP, so any legal refolding of the long
    SD-JWT in transit leaves the Mode 1 signature valid (EML-10) -- the reason that rule exists;
  - the Combined-mode relationship (cnf.jwk equals the CMS signer key, equal aid, equal tier) holds (EML-09);
  - an expired binding assertion and an expired SD-JWT are `policy` with the cause, not `fail` (EML-02).

The real captures of the draft's appendix are -02 messages and cannot verify here; they are replaced by captures made
through the live system (see test_combined_mode_and_real_example_emails.py).
"""

import base64
import hashlib
import json
import re
import struct
import time

import pytest

from hw_attest_verify import issuer_key_discovery, mode2
from hw_attest_verify.__main__ import verify_email_from_raw
from tests.test_mode1_cms_profile_and_certificate_path import (
  MODE1_LABEL,
  SIGNATURE_ALGORITHM_BY_NAME,
  THIRTEEN_ALWAYS_COVERED_FIELDS,
  GeneratedPkiForMode1Tests,
  build_signed_data,
)
from tests.test_mode1_registrar_binding_trust_path import (
  AID,
  REGISTRAR_ISSUER,
  REGISTRAR_JWKS_URL,
  REGISTRAR_METADATA_URL,
  Registrar,
  b64url,
  ec_public_jwk,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

THE_MESSAGE_BODY = "Hello from the revision 03 combined-mode end to end test.\r\nSecond line.\r\n"

# Every one of the thirteen always-covered fields is present, so a verifier that covers fewer cannot agree with the
# producer below. Values are plain single-line ASCII (they are not folded; only the two Hardware-* fields are).
ALL_THIRTEEN_FIELD_VALUES = {
  "from": "Agent <agent@mailpal.example>",
  "to": "Human <human@example.org>",
  "cc": "Copy <copy@example.org>",
  "subject": "Combined   mode   test",  # runs of spaces: relaxed canonicalization compresses them
  "date": "Mon, 21 Sep 2026 14:13:20 +0000",
  "message-id": "<combined-03@mailpal.example>",
  "sender": "Bot <bot@mailpal.example>",
  "reply-to": "Replies <replies@mailpal.example>",
  "in-reply-to": "<earlier@example.org>",
  "references": "<earlier@example.org> <earlier2@example.org>",
  "mime-version": "1.0",
  "content-type": "text/plain; charset=us-ascii",
  "content-transfer-encoding": "7bit",
}


@pytest.fixture(scope="module")
def pki():
  return GeneratedPkiForMode1Tests()


@pytest.fixture(scope="module")
def registrar():
  return Registrar()


@pytest.fixture
def registrar_documents_and_registry(registrar, monkeypatch):
  """The Registrar's RFC 8414 metadata and JWK Set, and the Registry's currentIssuer answer, served from memory."""
  documents = {
    REGISTRAR_METADATA_URL: {"issuer": REGISTRAR_ISSUER, "jwks_uri": REGISTRAR_JWKS_URL},
    REGISTRAR_JWKS_URL: registrar.jwk_set,
  }
  issuer_key_discovery._registrar_jwk_set_cache.clear()
  monkeypatch.setattr(issuer_key_discovery, "_fetch_json_document", lambda url: documents[url])
  monkeypatch.setattr(mode2, "_resolve_issuer_via_rdap",
                      lambda aid: REGISTRAR_ISSUER if aid.startswith("urn:aid:") else None)
  yield documents
  issuer_key_discovery._registrar_jwk_set_cache.clear()


# --- the independent producer, written from the draft's text ------------------------------------------------------

def simple_canonicalized_body(body_text: str) -> bytes:
  body = body_text.encode("ascii")
  while body.endswith(b"\r\n\r\n"):
    body = body[:-2]
  return body


def relaxed_header_line(name: str, value: str) -> str:
  """DKIM relaxed header canonicalization of one single-line field, followed by CRLF."""
  return f"{name.lower()}:{' '.join(value.split())}\r\n"


def every_wsp_deleted_header_line(name: str, value: str) -> str:
  """The two Hardware-* fields: name lowercased, unfolded, every WSP character anywhere in the value deleted."""
  value_with_every_whitespace_character_deleted = re.sub(r"[ \t\r\n]+", "", value)
  return f"{name.lower()}:{value_with_every_whitespace_character_deleted}\r\n"


def fold_arbitrarily(name: str, value: str, width: int) -> str:
  """RFC 5322 folding at arbitrary positions (legal for these two fields: no WSP in them is significant)."""
  chunks = [value[position:position + width] for position in range(0, len(value), width)]
  return f"{name}: " + "\r\n ".join(chunks)


def unfold_and_refold(folded_field_text: str, new_width: int) -> str:
  name, _separator, value = folded_field_text.partition(":")
  unfolded_value = re.sub(r"\r\n[ \t]+", "", value).strip()
  return fold_arbitrarily(name, unfolded_value, new_width)


def message_binding_nonce_for_mode2(field_values: dict, body_text: str, iat: int) -> str:
  canonical = "".join(relaxed_header_line(name, field_values[name])
                      for name in THIRTEEN_ALWAYS_COVERED_FIELDS if name in field_values)
  canonical += "hardware-trust-proof:"
  message_binding = (hashlib.sha256(canonical.encode()).digest()
                     + hashlib.sha256(simple_canonicalized_body(body_text)).digest() + struct.pack(">Q", iat))
  return b64url(hashlib.sha256(message_binding).digest())


def build_combined_mode_message(pki, registrar, now, *, binding_exp_offset=86400, sd_jwt_exp_offset=300,
                                mode1_covers_hardware_trust_proof=True, include_sub_disclosure=True, aid=AID,
                                field_values=None, html_fold_width=60, attestation_fold_width=72,
                                attestation_input_transform=None):
  """Return (raw_email_text, parts) for a Combined-mode message made only from the draft's rules.
  attestation_input_transform, when given, changes the bytes that are signed (to build a deliberately wrong message)."""
  field_values = dict(ALL_THIRTEEN_FIELD_VALUES if field_values is None else field_values)
  signer_jwk = ec_public_jwk(pki.ec_leaf_key.public_key())

  # Mode 2: the SD-JWT with a non-selective cnf.jwk equal to the CMS signer key, disclosing aid.trust_tier and sub.
  tier_disclosure = b64url(json.dumps(["salt-tier", "aid", {"trust_tier": "declared"}]).encode())
  sub_disclosure = b64url(json.dumps(["salt-sub", "sub", aid]).encode())
  disclosures = [tier_disclosure] + ([sub_disclosure] if include_sub_disclosure else [])
  digest_of = lambda text: b64url(hashlib.sha256(text.encode("ascii")).digest())
  sd_jwt_payload = {
    "iss": REGISTRAR_ISSUER, "iat": now, "exp": now + sd_jwt_exp_offset, "_sd_alg": "sha-256",
    "nonce": message_binding_nonce_for_mode2(field_values, THE_MESSAGE_BODY, now),
    "cnf": {"jwk": signer_jwk}, "_sd": [digest_of(text) for text in [tier_disclosure, sub_disclosure]],
  }
  issuer_signed_jwt = registrar.sign(
    "ES256", {"alg": "ES256", "kid": "reg-es256", "typ": "airs-email+sd-jwt"}, sd_jwt_payload)
  sd_jwt = issuer_signed_jwt + "~" + "".join(f"{text}~" for text in disclosures)

  # Mode 1: Registrar binding JWS (aid + bind) and the CMS signature over the 92-octet attestation-input.
  binding = registrar.binding_jws(signer_jwk, iat=min(now - 60, now + binding_exp_offset - 60),
                                  exp=now + binding_exp_offset, sub=aid)
  covered_names = THIRTEEN_ALWAYS_COVERED_FIELDS + (["hardware-trust-proof"] if mode1_covers_hardware_trust_proof else [])
  body_hash = b64url(hashlib.sha256(simple_canonicalized_body(THE_MESSAGE_BODY)).digest())
  tags_with_empty_chain = (f"v=1; typ=SFT; alg=ES256; h={':'.join(covered_names)}; bh={body_hash}; ts={now}; chain=; "
                           f"aid={aid}; bind={binding}")
  header_lines = "".join(
    every_wsp_deleted_header_line(name, sd_jwt) if name == "hardware-trust-proof"
    else relaxed_header_line(name, field_values[name]) if name in field_values else ""
    for name in covered_names)
  canonical_headers = header_lines + "hardware-attestation:" + re.sub(r"\s+", "", tags_with_empty_chain) + "\r\n"
  attestation_input = (MODE1_LABEL + hashlib.sha256(canonical_headers.encode()).digest()
                       + hashlib.sha256(simple_canonicalized_body(THE_MESSAGE_BODY)).digest() + struct.pack(">Q", now))
  assert len(attestation_input) == 92
  signed_bytes = attestation_input_transform(attestation_input) if attestation_input_transform else attestation_input
  cms = build_signed_data(
    signature=pki.ec_leaf_key.sign(signed_bytes, ec.ECDSA(hashes.SHA256())),
    certificates_in_set_order=[pki.ec_leaf, pki.intermediate, pki.root],
    signature_algorithm=SIGNATURE_ALGORITHM_BY_NAME["ES256"], sid_certificate=pki.ec_leaf)
  hardware_attestation_value = tags_with_empty_chain.replace("chain=;", f"chain={base64.b64encode(cms).decode()};", 1)

  ordinary_field_lines = [f"{name.title() if name != 'message-id' else 'Message-ID'}: {value}"
                          for name, value in field_values.items()]
  raw_email = "\r\n".join(
    ordinary_field_lines + [
      fold_arbitrarily("Hardware-Trust-Proof", sd_jwt, html_fold_width),
      fold_arbitrarily("Hardware-Attestation", hardware_attestation_value, attestation_fold_width),
    ]) + "\r\n\r\n" + THE_MESSAGE_BODY
  return raw_email, {
    "sd_jwt": sd_jwt, "hardware_attestation_value": hardware_attestation_value, "attestation_input": attestation_input,
    "signer_jwk": signer_jwk, "now": now,
  }


def verify(raw_email, **keyword_arguments):
  return verify_email_from_raw(raw_email, **keyword_arguments)


def assert_both_pass(results):
  mode1_result, mode2_result = results["_mode1_result_object"], results["_mode2_result_object"]
  assert mode1_result.authentication_results_result == "pass", mode1_result.failure_reasons
  assert mode2_result.authentication_results_result == "pass", mode2_result.failure_reasons
  assert "combined_mode_errors" not in results
  return mode1_result, mode2_result


# --- the tests ---------------------------------------------------------------------------------------------------

class TestCombinedModeMessageBuiltFromTheDraftText:
  def test_a_message_with_all_thirteen_fields_passes_both_modes(self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()))
    mode1_result, mode2_result = assert_both_pass(verify(raw_email))
    assert mode1_result.trust_path_that_succeeded == "registrar"
    assert (mode1_result.trust_tier, mode1_result.agent_identity_urn) == ("declared", AID)
    assert (mode2_result.trust_tier, mode2_result.agent_identity_urn) == ("declared", AID)
    assert mode2_result.cnf_jwk_thumbprint == mode1_result.signer_public_key_jwk_thumbprint
    assert [name.lower() for name in mode1_result.signed_header_names] == \
      THIRTEEN_ALWAYS_COVERED_FIELDS + ["hardware-trust-proof"]

  def test_the_signed_input_is_ninety_two_octets_beginning_with_the_label(self, pki, registrar, registrar_documents_and_registry):
    _raw_email, parts = build_combined_mode_message(pki, registrar, int(time.time()))
    assert len(parts["attestation_input"]) == 92
    assert parts["attestation_input"].startswith(b"AIRS-Email-Mode1-v1\x00")

  def test_the_legacy_72_octet_input_without_the_label_is_rejected(self, pki, registrar, registrar_documents_and_registry):
    # The same message, but signed over the -02 72-octet input (the 92 octets without the 20-octet label): the
    # signature must not verify, so a -03 verifier cannot be fed a -02 proof.
    raw_email, _parts = build_combined_mode_message(
      pki, registrar, int(time.time()), attestation_input_transform=lambda attestation_input: attestation_input[20:])
    results = verify(raw_email)
    assert results["_mode1_result_object"].authentication_results_result == "fail"
    assert any("Signature verification failed" in reason
               for reason in results["_mode1_result_object"].failure_reasons)

  def test_a_wrong_label_is_rejected(self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(
      pki, registrar, int(time.time()),
      attestation_input_transform=lambda attestation_input: b"AIRS-Email-Mode1-v2\x00" + attestation_input[20:])
    assert verify(raw_email)["_mode1_result_object"].authentication_results_result == "fail"

  @pytest.mark.parametrize("refold_width", [30, 45, 68, 77, 200])
  def test_any_legal_refolding_of_hardware_trust_proof_in_transit_keeps_mode_1_valid_eml10(
      self, pki, registrar, registrar_documents_and_registry, refold_width):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()))
    original_field = re.search(r"Hardware-Trust-Proof:.*?(?=\r\nHardware-Attestation:)", raw_email, re.S).group(0)
    refolded_message = raw_email.replace(original_field, unfold_and_refold(original_field, refold_width))
    assert refolded_message != raw_email or refold_width == 60
    assert_both_pass(verify(refolded_message))

  @pytest.mark.parametrize("refold_width", [25, 50, 90])
  def test_any_legal_refolding_of_hardware_attestation_in_transit_keeps_mode_1_valid(
      self, pki, registrar, registrar_documents_and_registry, refold_width):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()))
    original_field = re.search(r"Hardware-Attestation:.*?(?=\r\n\r\n)", raw_email, re.S).group(0)
    refolded_message = raw_email.replace(original_field, unfold_and_refold(original_field, refold_width))
    assert refolded_message != raw_email
    assert_both_pass(verify(refolded_message))

  def test_an_lf_only_copy_of_the_message_still_verifies(self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()))
    assert_both_pass(verify(raw_email.replace("\r\n", "\n")))


class TestEachOfTheFieldsAddedIn03IsCoveredByBothProofs:
  @pytest.mark.parametrize("field_name", ["cc", "sender", "in-reply-to", "references"])
  def test_changing_a_field_after_signing_breaks_both_proofs(self, pki, registrar, registrar_documents_and_registry, field_name):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()))
    original_line = f"{field_name.title()}: {ALL_THIRTEEN_FIELD_VALUES[field_name]}"
    assert original_line in raw_email
    results = verify(raw_email.replace(original_line, f"{field_name.title()}: changed@example.net"))
    assert results["_mode1_result_object"].authentication_results_result == "fail"
    assert results["_mode2_result_object"].authentication_results_result == "fail"

  @pytest.mark.parametrize("field_name", ["cc", "sender", "in-reply-to", "references"])
  def test_adding_a_field_that_was_absent_when_signed_breaks_both_proofs(
      self, pki, registrar, registrar_documents_and_registry, field_name):
    # "Listing a field that is absent at signing therefore also protects against later addition of that field."
    values_without_the_field = {name: value for name, value in ALL_THIRTEEN_FIELD_VALUES.items() if name != field_name}
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()), field_values=values_without_the_field)
    assert_both_pass(verify(raw_email))
    with_the_field_added = raw_email.replace("\r\n\r\n", f"\r\n{field_name.title()}: added-later@example.net\r\n\r\n", 1)
    results = verify(with_the_field_added)
    assert results["_mode1_result_object"].authentication_results_result in ("fail", "permerror")
    assert results["_mode2_result_object"].authentication_results_result in ("fail", "permerror")

  def test_a_message_with_none_of_the_optional_fields_present_still_passes(self, pki, registrar, registrar_documents_and_registry):
    only_required = {name: value for name, value in ALL_THIRTEEN_FIELD_VALUES.items()
                     if name in ("from", "to", "subject", "date", "message-id", "mime-version", "content-type")}
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()), field_values=only_required)
    assert_both_pass(verify(raw_email))


class TestCombinedModeRelationshipEml09:
  def test_mode_1_that_does_not_cover_hardware_trust_proof_fails_the_cnf_bearing_mode_2(
      self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(
      pki, registrar, int(time.time()), mode1_covers_hardware_trust_proof=False)
    results = verify(raw_email)
    assert results["_mode1_result_object"].authentication_results_result == "pass"
    assert results["_mode2_result_object"].authentication_results_result == "fail"
    assert any("does not cover Hardware-Trust-Proof" in problem for problem in results["combined_mode_errors"])

  def test_removing_hardware_attestation_fails_the_cnf_bearing_mode_2(self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()))
    without_mode1 = re.sub(r"Hardware-Attestation:.*?(?=\r\n\r\n)", "X-Removed: yes", raw_email, flags=re.S)
    results = verify(without_mode1)
    assert "_mode1_result_object" not in results
    assert results["_mode2_result_object"].authentication_results_result == "fail"
    assert "no Hardware-Attestation field" in results["_mode2_result_object"].failure_reason

  def test_withholding_the_sub_disclosure_breaks_both_proofs(self, pki, registrar, registrar_documents_and_registry):
    # The sender chose not to disclose sub in the message it signed: Mode 1 carries an aid, so Combined mode needs Mode 2
    # to disclose the same sub. (The disclosure selection is covered by Mode 1, so it cannot be stripped in transit.)
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()), include_sub_disclosure=False)
    results = verify(raw_email)
    assert results["_mode2_result_object"].authentication_results_result != "pass"

  def test_stripping_the_sub_disclosure_in_transit_breaks_mode_1_because_it_covers_the_field(
      self, pki, registrar, registrar_documents_and_registry):
    raw_email, parts = build_combined_mode_message(pki, registrar, int(time.time()))
    sub_disclosure = b64url(json.dumps(["salt-sub", "sub", AID]).encode())
    assert sub_disclosure in parts["sd_jwt"]
    stripped_sd_jwt = parts["sd_jwt"].replace(sub_disclosure + "~", "")
    original_field = re.search(r"Hardware-Trust-Proof:.*?(?=\r\nHardware-Attestation:)", raw_email, re.S).group(0)
    stripped_message = raw_email.replace(original_field, fold_arbitrarily("Hardware-Trust-Proof", stripped_sd_jwt, 60))
    results = verify(stripped_message)
    assert results["_mode1_result_object"].authentication_results_result == "fail"
    assert results["_mode2_result_object"].authentication_results_result != "pass"


class TestExpiryIsPolicyWithTheCauseEml02:
  def test_an_expired_registrar_binding_assertion_is_policy_for_mode_1(self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()), binding_exp_offset=-1000)
    results = verify(raw_email)
    mode1_result = results["_mode1_result_object"]
    assert mode1_result.authentication_results_result == "policy"
    assert mode1_result.registrar_assertion_has_expired
    assert any("binding assertion has expired" in reason for reason in mode1_result.failure_reasons)
    assert mode1_result.cms_signature_and_message_binding_verified
    # Combined mode: the cnf-bearing Mode 2 depends on Mode 1, so it follows it to policy rather than passing.
    assert results["_mode2_result_object"].authentication_results_result == "policy"

  def test_an_expired_sd_jwt_is_policy_for_mode_2(self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()), sd_jwt_exp_offset=-1000)
    results = verify(raw_email)
    assert results["_mode1_result_object"].authentication_results_result == "pass"
    assert results["_mode2_result_object"].authentication_results_result == "policy"
    assert any("expired" in reason for reason in results["_mode2_result_object"].failure_reasons)


class TestTestNamespaceIdentityEml13:
  TEST_AID = "urn:aid:test:id-qkckh-xxtcw-cxbvp-gpskg"

  def test_a_test_namespace_identity_is_policy_in_both_modes_with_no_tier_and_no_aid(
      self, pki, registrar, registrar_documents_and_registry):
    raw_email, _parts = build_combined_mode_message(pki, registrar, int(time.time()), aid=self.TEST_AID)
    results = verify(raw_email)
    mode1_result, mode2_result = results["_mode1_result_object"], results["_mode2_result_object"]
    assert mode1_result.authentication_results_result == "policy"
    assert mode2_result.authentication_results_result == "policy"
    assert mode1_result.agent_identity_urn is None and mode1_result.trust_tier == ""
    assert mode2_result.agent_identity_urn == "" and mode2_result.trust_tier == ""


# --- a known-answer vector computed outside every implementation ------------------------------------------------------

# The 92 octets below were computed from the fixed message in KNOWN_ANSWER_MESSAGE_FIELDS with coreutils only (printf,
# sha256sum, xxd, base64): see fixtures/known_answer_mode1_attestation_input/compute_the_vector_with_coreutils_only.sh.
# The signature is made over THESE BYTES, not over anything this library computed, so the signature verifies only if the
# verifier derives exactly the same 92 octets from the message: the label, the thirteen-field list order with absent
# fields contributing nothing, relaxed canonicalization, the self reference with chain= emptied and every WSP removed,
# the body hash and the big-endian ts. A change in any of those (in either direction) fails this test.
KNOWN_ANSWER_TS = 1792000000
KNOWN_ANSWER_BH_BASE64URL = "ttKhgiw89GbZvp4BR4bLADTgBKVW8gtxkZRwEuryXrI"
KNOWN_ANSWER_ATTESTATION_INPUT_HEX = (
  "414952532d456d61696c2d4d6f6465312d7631003061ef38718036f65a7d7d5517f1afc14bfb3c8636874ddb01fa6acde0d9852f"
  "b6d2a1822c3cf466d9be9e014786cb0034e004a556f20b7191947012eaf25eb2000000006acfc000")
KNOWN_ANSWER_MESSAGE_FIELDS = [
  ("From", "alice@example.com"),
  ("To", "bob@example.org"),
  ("Subject", "Known answer"),
  ("Date", "Mon, 26 Oct 2026 10:00:00 +0000"),
  ("Message-ID", "<known-answer-1@example.com>"),
  ("MIME-Version", "1.0"),
  ("Content-Type", "text/plain; charset=utf-8"),
  ("Content-Transfer-Encoding", "7bit"),
]
KNOWN_ANSWER_BODY = "Known answer body.\r\n"
KNOWN_ANSWER_H_TAG = ("from:to:cc:subject:date:message-id:sender:reply-to:in-reply-to:references:mime-version:"
                      "content-type:content-transfer-encoding")


def known_answer_message(pki, signed_bytes, fields=None, body=KNOWN_ANSWER_BODY, fold_width=None):
  cms = build_signed_data(
    signature=pki.ec_leaf_key.sign(signed_bytes, ec.ECDSA(hashes.SHA256())),
    certificates_in_set_order=[pki.ec_leaf, pki.intermediate, pki.root],
    signature_algorithm=SIGNATURE_ALGORITHM_BY_NAME["ES256"], sid_certificate=pki.ec_leaf)
  hardware_attestation_value = (f"v=1; typ=SFT; alg=ES256; h={KNOWN_ANSWER_H_TAG}; bh={KNOWN_ANSWER_BH_BASE64URL}; "
                                f"ts={KNOWN_ANSWER_TS}; chain={base64.b64encode(cms).decode()}")
  field_lines = [f"{name}: {value}" for name, value in (KNOWN_ANSWER_MESSAGE_FIELDS if fields is None else fields)]
  hardware_attestation_field = (fold_arbitrarily("Hardware-Attestation", hardware_attestation_value, fold_width)
                                if fold_width else f"Hardware-Attestation: {hardware_attestation_value}")
  return "\r\n".join(field_lines + [hardware_attestation_field]) + "\r\n\r\n" + body


class TestKnownAnswerAttestationInputComputedWithCoreutilsEml12:
  def test_the_vector_is_ninety_two_octets_beginning_with_the_label(self):
    vector = bytes.fromhex(KNOWN_ANSWER_ATTESTATION_INPUT_HEX)
    assert len(vector) == 92
    assert vector[:20] == b"AIRS-Email-Mode1-v1\x00"
    assert vector[-8:] == struct.pack(">Q", KNOWN_ANSWER_TS)

  def test_a_signature_over_the_known_answer_bytes_verifies(self, pki):
    raw_email = known_answer_message(pki, bytes.fromhex(KNOWN_ANSWER_ATTESTATION_INPUT_HEX))
    mode1_result = verify(raw_email, skip_time_checks=True)["_mode1_result_object"]
    assert mode1_result.failure_reasons == [] or all("trust path" in reason for reason in mode1_result.failure_reasons), \
      mode1_result.failure_reasons
    assert mode1_result.cms_signature_and_message_binding_verified is True
    # No Registrar binding was carried, so no trust path exists: EML-01 says policy, not pass.
    assert mode1_result.authentication_results_result == "policy"

  def test_the_known_answer_still_verifies_when_the_hardware_attestation_field_is_folded(self, pki):
    raw_email = known_answer_message(pki, bytes.fromhex(KNOWN_ANSWER_ATTESTATION_INPUT_HEX), fold_width=50)
    assert verify(raw_email, skip_time_checks=True)["_mode1_result_object"].cms_signature_and_message_binding_verified is True

  @pytest.mark.parametrize("changed_field_name, changed_value", [
    ("Subject", "Known answer!"), ("From", "mallory@example.com"), ("Date", "Mon, 26 Oct 2026 10:00:01 +0000")])
  def test_changing_a_covered_field_breaks_the_known_answer_signature(self, pki, changed_field_name, changed_value):
    fields = [(name, changed_value if name == changed_field_name else value) for name, value in KNOWN_ANSWER_MESSAGE_FIELDS]
    raw_email = known_answer_message(pki, bytes.fromhex(KNOWN_ANSWER_ATTESTATION_INPUT_HEX), fields=fields)
    mode1_result = verify(raw_email, skip_time_checks=True)["_mode1_result_object"]
    assert mode1_result.cms_signature_and_message_binding_verified is False
    assert mode1_result.authentication_results_result == "fail"

  def test_a_signature_over_the_input_without_the_label_does_not_verify(self, pki):
    raw_email = known_answer_message(pki, bytes.fromhex(KNOWN_ANSWER_ATTESTATION_INPUT_HEX)[20:])
    assert verify(raw_email, skip_time_checks=True)["_mode1_result_object"].cms_signature_and_message_binding_verified is False
