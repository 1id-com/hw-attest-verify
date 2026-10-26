"""
Combined mode (AUD-F19) and the five real example emails of the draft's
appendix (sent 2026-10-27 through the live MailPal.com with the published oneid 4.0.0 SDK
and oneid-enroll 3.0.0 helper on a TPM, a YubiKey PIV, an Apple Secure Enclave, a VMware vTPM and a software
key; revision -03 captures, byte-identical to rfc/rfc_examples_2026-10-27/).

The real emails are verified offline with the answers the live AIRS Registry
(RDAP currentIssuer) and https://1id.com (RFC 8414 metadata, JWK Set) gave on
2026-10-27, recorded under fixtures/real_examples_2026_10_27/ (byte-identical to the 2026-09-24 recording: the
Registrar's signing keys did not change).

The five revision -02 captures of 2026-09-24 are kept under fixtures/revision_02_captures_2026_09_24/ for one
purpose: to prove that a revision -03 verifier rejects them (TestRevision02CapturesAreRejectedUnderRevision03).
"""

import json
import os
import re

import pytest

from hw_attest_verify import apply_combined_mode_requirements_to_mode2_result, issuer_key_discovery, mode2
from hw_attest_verify.__main__ import verify_email_from_raw
from hw_attest_verify.mode1 import VerificationResult
from hw_attest_verify.mode2 import Mode2VerificationResult

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "real_examples_2026_10_27")
REVISION_02_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "revision_02_captures_2026_09_24")
REAL_ISSUER = "https://1id.com/realms/agents"
REAL_EXAMPLES = {
  "example_1_sovereign_tpm_combined.eml": ("TPM", "sovereign", "urn:aid:global:id-vwgkj-mhtjp-mfscq-bdchb"),
  "example_2_portable_piv_combined.eml": ("PIV", "portable", "urn:aid:global:id-csnxq-phcmb-pvcmm-xcdmb"),
  "example_3_enclave_secure_enclave_combined.eml": ("ENC", "enclave", "urn:aid:global:id-ddmzh-dpcfv-fqrxj-xmxsj"),
  "example_4_virtual_vtpm_combined.eml": ("VRT", "virtual", "urn:aid:global:id-tpfkx-qdzts-wmtbm-rnjpc"),
  "example_5_declared_software_combined.eml": ("SFT", "declared", "urn:aid:global:id-hgsst-vgcfx-pwdvw-jkbjq"),
}
# The 2026-09-24 captures (revision -02): same file names, different identities (that run was before the reset).
REVISION_02_CAPTURES = {
  "example_1_sovereign_tpm_combined.eml": ("TPM", "sovereign", "urn:aid:global:id-zjxfv-kmkrf-dgfwt-kzmsz"),
  "example_2_portable_piv_combined.eml": ("PIV", "portable", "urn:aid:global:id-vhfxn-wxmgc-hqtnb-jhvjs"),
  "example_3_enclave_secure_enclave_combined.eml": ("ENC", "enclave", "urn:aid:global:id-xzxgq-ftzrr-zdfvq-gjghn"),
  "example_4_virtual_vtpm_combined.eml": ("VRT", "virtual", "urn:aid:global:id-bcgnx-ccwrw-xvtgn-vrbxd"),
  "example_5_declared_software_combined.eml": ("SFT", "declared", "urn:aid:global:id-tzptt-rthrs-jfnnf-ppzbp"),
}


def passing_mode1(aid="urn:aid:global:id-a", tier="sovereign", thumbprint="T1", covers_mode2=True) -> VerificationResult:
  names = ["from", "to", "cc", "subject", "date", "message-id", "sender", "reply-to", "in-reply-to", "references",
           "mime-version", "content-type", "content-transfer-encoding"] + (["hardware-trust-proof"] if covers_mode2 else [])
  return VerificationResult(is_valid=True, authentication_results_result="pass", agent_identity_urn=aid,
                            trust_tier=tier, signed_header_names=names, signer_public_key_jwk_thumbprint=thumbprint)


def passing_mode2(sub="urn:aid:global:id-a", tier="sovereign", thumbprint="T1") -> Mode2VerificationResult:
  return Mode2VerificationResult(is_valid=True, authentication_results_result="pass", agent_identity_urn=sub or "",
                                 is_identified_mode=bool(sub), trust_tier=tier, carries_cnf_claim=bool(thumbprint),
                                 cnf_jwk_thumbprint=thumbprint)


class TestCombinedModeRequirementsAudF19:
  def test_consistent_pair_is_unchanged(self):
    mode2_result = passing_mode2()
    assert apply_combined_mode_requirements_to_mode2_result(passing_mode1(), mode2_result) == []
    assert mode2_result.authentication_results_result == "pass"

  @pytest.mark.parametrize("mode1_result, mode2_result, reason_fragment", [
    (passing_mode1(covers_mode2=False), passing_mode2(), "does not cover Hardware-Trust-Proof"),
    (passing_mode1(), passing_mode2(thumbprint=""), "no non-selective cnf.jwk"),
    (passing_mode1(), passing_mode2(thumbprint="T2"), "not the CMS signer public key"),
    (passing_mode1(), passing_mode2(sub=""), "does not disclose sub"),
    (passing_mode1(), passing_mode2(sub="urn:aid:global:id-b"), "differs from Mode 2 sub"),
    (passing_mode1(), passing_mode2(tier="declared"), "trust tier"),
  ])
  def test_broken_relationship_fails_mode2(self, mode1_result, mode2_result, reason_fragment):
    problems = apply_combined_mode_requirements_to_mode2_result(mode1_result, mode2_result)
    assert any(reason_fragment in problem for problem in problems), problems
    assert mode2_result.authentication_results_result == "fail" and not mode2_result.is_valid

  def test_manufacturer_only_mode1_needs_no_sub(self):
    mode2_result = passing_mode2(sub="")
    assert apply_combined_mode_requirements_to_mode2_result(passing_mode1(aid=None, tier=""), mode2_result) == []

  @pytest.mark.parametrize("mode1_outcome, expected_mode2_outcome", [
    ("fail", "fail"), ("permerror", "fail"), ("temperror", "temperror"), ("policy", "policy"),
  ])
  def test_mode2_follows_the_mode1_proof_it_depends_on(self, mode1_outcome, expected_mode2_outcome):
    mode1_result = VerificationResult(authentication_results_result=mode1_outcome, failure_reason="x")
    mode2_result = passing_mode2()
    apply_combined_mode_requirements_to_mode2_result(mode1_result, mode2_result)
    assert mode2_result.authentication_results_result == expected_mode2_outcome

  def test_mode2_that_already_failed_is_left_alone(self):
    mode2_result = Mode2VerificationResult(authentication_results_result="policy", failure_reason="old")
    assert apply_combined_mode_requirements_to_mode2_result(passing_mode1(), mode2_result) == []
    assert mode2_result.failure_reason == "old"


@pytest.fixture
def recorded_live_answers(monkeypatch):
  documents = {
    "https://1id.com/.well-known/oauth-authorization-server/realms/agents":
      json.load(open(os.path.join(FIXTURES, "rfc8414_metadata_1id_com_realms_agents.json"))),
    "https://1id.com/.well-known/jwks.json": json.load(open(os.path.join(FIXTURES, "jwks_1id_com.json"))),
  }
  issuer_key_discovery._registrar_jwk_set_cache.clear()
  monkeypatch.setattr(issuer_key_discovery, "_fetch_json_document", lambda url: documents[url])
  all_aids_of_the_recorded_captures = (
    {v[2] for v in REAL_EXAMPLES.values()} | {v[2] for v in REVISION_02_CAPTURES.values()}
  )
  monkeypatch.setattr(mode2, "_resolve_issuer_via_rdap",
                      lambda aid: REAL_ISSUER if aid in all_aids_of_the_recorded_captures else None)
  yield
  issuer_key_discovery._registrar_jwk_set_cache.clear()


def read_example(file_name: str, fixtures_directory: str = FIXTURES) -> str:
  with open(os.path.join(fixtures_directory, file_name), "r", encoding="utf-8", newline="") as example_file:
    return example_file.read()


# The captures in fixtures/revision_02_captures_2026_09_24 were made under revision -02 of the email draft: their
# Mode 1 `h` lists nine fields and their signed input is 72 octets with no label. Revision -03 requires thirteen
# fields and 92 octets (EML-11, EML-12), so a -03 verifier correctly rejects them. They are kept so that this
# rejection stays tested; the captures that must PASS are the revision -03 ones in fixtures/real_examples_2026_10_27
# (made through the live system after the -03 deployment, replacing the strict expected failures that stood here
# between the 3.0.0 release preparation and the regeneration of the examples).
class TestRevision02CapturesAreRejectedUnderRevision03:
  @pytest.mark.parametrize("file_name", sorted(REVISION_02_CAPTURES))
  def test_mode_1_of_a_revision_02_capture_is_permerror_naming_the_missing_fields(self, recorded_live_answers, file_name):
    results = verify_email_from_raw(read_example(file_name, REVISION_02_FIXTURES), skip_time_checks=True)
    mode1_result = results["_mode1_result_object"]
    assert mode1_result.authentication_results_result == "permerror"
    assert any("h= tag missing required headers: cc, in-reply-to, references, sender" in reason
               for reason in mode1_result.failure_reasons), mode1_result.failure_reasons
    assert not mode1_result.is_valid and mode1_result.trust_tier == "" and mode1_result.agent_identity_urn is None

  @pytest.mark.parametrize("file_name", sorted(REVISION_02_CAPTURES))
  def test_the_cnf_bearing_mode_2_of_a_revision_02_capture_does_not_pass_without_its_mode_1(self, recorded_live_answers, file_name):
    # Mode 2's own nonce is unchanged by -03 when none of the four added fields is present, so the SD-JWT itself still
    # verifies; but it carries cnf (Combined mode), so it depends on a Mode 1 that no longer verifies and must not pass.
    results = verify_email_from_raw(read_example(file_name, REVISION_02_FIXTURES), skip_time_checks=True)
    mode2_result = results["_mode2_result_object"]
    assert mode2_result.authentication_results_result == "fail"
    assert any("Combined mode" in problem for problem in results["combined_mode_errors"])


class TestRealExampleEmails:
  @pytest.mark.parametrize("file_name", sorted(REAL_EXAMPLES))
  def test_real_example_passes_both_modes_without_a_trust_store(self, recorded_live_answers, file_name):
    expected_typ, expected_tier, expected_aid = REAL_EXAMPLES[file_name]
    results = verify_email_from_raw(read_example(file_name), skip_time_checks=True)
    mode1_result, mode2_result = results["_mode1_result_object"], results["_mode2_result_object"]
    assert mode1_result.authentication_results_result == "pass", mode1_result.failure_reasons
    assert mode1_result.registrar_binding_verified
    assert (mode1_result.typ, mode1_result.trust_tier, mode1_result.agent_identity_urn) == (expected_typ, expected_tier, expected_aid)
    assert mode2_result.authentication_results_result == "pass", mode2_result.failure_reasons
    assert mode2_result.is_identified_mode and mode2_result.issuer == REAL_ISSUER
    assert (mode2_result.trust_tier, mode2_result.agent_identity_urn) == (expected_tier, expected_aid)
    assert mode2_result.cnf_jwk_thumbprint == mode1_result.signer_public_key_jwk_thumbprint
    assert "combined_mode_errors" not in results

  def test_lf_only_copy_as_printed_in_the_draft_appendix_still_verifies(self, recorded_live_answers):
    lf_only_copy = read_example("example_2_portable_piv_combined.eml").replace("\r\n", "\n")
    results = verify_email_from_raw(lf_only_copy, skip_time_checks=True)
    assert results["_mode1_result_object"].authentication_results_result == "pass"
    assert results["_mode2_result_object"].authentication_results_result == "pass"

  def test_real_example_is_expired_when_checked_as_current(self, recorded_live_answers, monkeypatch):
    # Draft -03 (EML-02): an expired SD-JWT is `policy` with the cause in the comment, not `fail` (it was `fail` in -02).
    # The capture's SD-JWT and binding JWS lived one hour (exp - iat = 3600, the Registrar's mail assertion lifetime).
    # The clock is set two hours after the capture so that the test means the same on every day: with the real clock it
    # would fail during the capture's first hour, when the proof is merely "old" under the local age policy.
    raw = read_example("example_5_declared_software_combined.eml")
    capture_time = int(re.search(r"ts=(\d+)", raw).group(1))
    monkeypatch.setattr("time.time", lambda: float(capture_time + 2 * 3600))
    results = verify_email_from_raw(raw)
    assert results["_mode2_result_object"].authentication_results_result == "policy"
    assert "expired" in results["_mode2_result_object"].failure_reason

  def test_removing_hardware_attestation_fails_the_cnf_bearing_mode2(self, recorded_live_answers):
    raw = read_example("example_5_declared_software_combined.eml")
    without_mode1 = re.sub(r"(?im)^Hardware-Attestation:.*(?:\r?\n[ \t].*)*\r?\n", "", raw)
    assert "Hardware-Attestation:" not in without_mode1
    results = verify_email_from_raw(without_mode1, skip_time_checks=True)
    assert "_mode1_result_object" not in results
    assert results["_mode2_result_object"].authentication_results_result == "fail"
    assert "no Hardware-Attestation field" in results["_mode2_result_object"].failure_reason

  def test_withholding_the_sub_disclosure_breaks_both_proofs(self, recorded_live_answers):
    raw = read_example("example_5_declared_software_combined.eml")
    field_match = re.search(r"(?im)^Hardware-Trust-Proof:(.*(?:\r?\n[ \t].*)*)", raw)
    compact = re.sub(r"\s+", "", field_match.group(1))
    issuer_jwt, *disclosures = [part for part in compact.split("~") if part]
    import base64
    kept = [d for d in disclosures if json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))[1] != "sub"]
    assert len(kept) == len(disclosures) - 1
    rewritten = raw[:field_match.start(1)] + " " + issuer_jwt + "~" + "".join(d + "~" for d in kept) + raw[field_match.end(1):]
    results = verify_email_from_raw(rewritten, skip_time_checks=True)
    # Mode 1 h= covers Hardware-Trust-Proof, so the disclosure selection is signed.
    assert results["_mode1_result_object"].authentication_results_result == "fail"
    assert results["_mode2_result_object"].authentication_results_result != "pass"
