"""hw-attest-verify 2.0.2: the Resolution draft's RDAP response checks
(review 072 #2) and RFC 8601 quoted property values (review 072 #10)."""

import pytest

from hw_attest_verify import AirsIdentityResolutionRejected
from hw_attest_verify.__main__ import (
  _authentication_results_property_value,
  _format_mode1_auth_results_line,
  _format_mode2_auth_results_line,
)
from hw_attest_verify.mode1 import VerificationResult
from hw_attest_verify.mode2 import Mode2VerificationResult, current_issuer_from_rdap_aid_identity_response

AID = "urn:aid:global:id-zjxfv-kmkrf-dgfwt-kzmsz"
ISSUER = "https://1id.com/realms/agents"


def rdap_answer(**aid_data_overrides):
  aid_data = {"canonical": AID, "lifecycleState": "operational", "currentIssuer": ISSUER}
  aid_data.update(aid_data_overrides)
  for key in [key for key, value in aid_data.items() if value is None]:
    del aid_data[key]
  return {"objectClassName": "aid_agentIdentity", "handle": AID, "status": ["active"], "aid_data": aid_data}


class TestRdapResponseValidation:
  def test_operational_identity_yields_its_current_issuer(self):
    assert current_issuer_from_rdap_aid_identity_response(AID, rdap_answer()) == ISSUER

  def test_decommissioned_identity_is_rejected(self):
    with pytest.raises(AirsIdentityResolutionRejected, match="decommissioned"):
      current_issuer_from_rdap_aid_identity_response(AID, rdap_answer(lifecycleState="decommissioned", currentIssuer=None))

  def test_unknown_or_missing_lifecycle_state_is_rejected(self):
    for lifecycle_state in ("active", None):
      with pytest.raises(AirsIdentityResolutionRejected, match="must be operational"):
        current_issuer_from_rdap_aid_identity_response(AID, rdap_answer(lifecycleState=lifecycle_state))

  def test_answer_for_another_identity_is_rejected(self):
    with pytest.raises(AirsIdentityResolutionRejected, match="not the requested"):
      current_issuer_from_rdap_aid_identity_response(AID, rdap_answer(canonical="urn:aid:global:id-other-other-other-other"))
    answer = rdap_answer()
    answer["handle"] = "urn:aid:global:id-other-other-other-other"
    with pytest.raises(AirsIdentityResolutionRejected, match="not the requested"):
      current_issuer_from_rdap_aid_identity_response(AID, answer)

  def test_operational_identity_without_a_current_issuer_has_none(self):
    assert current_issuer_from_rdap_aid_identity_response(AID, rdap_answer(currentIssuer=None)) is None

  def test_answer_that_is_not_an_aid_identity_object_is_rejected(self):
    with pytest.raises(AirsIdentityResolutionRejected, match="aid_agentIdentity"):
      current_issuer_from_rdap_aid_identity_response(AID, {"objectClassName": "domain"})


class TestVerifiersFailOnRejectedResolution:
  def test_mode2_identified_presentation_fails_with_the_reason(self):
    from tests.test_mode2_draft_verification_algorithm import presentation, verify

    def rejecting_resolver(aid):
      raise AirsIdentityResolutionRejected("AIRS identity is decommissioned")
    result = verify(presentation(), current_issuer=None)  # baseline: no issuer -> fail
    assert result.authentication_results_result == "fail"
    from hw_attest_verify.mode2 import verify_hardware_trust_proof
    from tests.test_mode2_draft_verification_algorithm import BODY, EC_ISSUER_KEY, HEADERS, NOW
    result = verify_hardware_trust_proof(
      header_value=presentation(), email_headers=HEADERS, body=BODY, reference_time_unix=NOW,
      issuer_public_key_override=EC_ISSUER_KEY.public_key(), current_issuer_resolver=rejecting_resolver)
    assert result.authentication_results_result == "fail"
    assert "decommissioned" in result.failure_reason

  def test_mode1_binding_fails_with_the_reason(self, monkeypatch):
    from tests import test_mode1_registrar_binding_trust_path as mode1_tests
    pki = mode1_tests.GeneratedPkiForMode1Tests()
    registrar = mode1_tests.Registrar()
    result = mode1_tests.verify(mode1_tests.bound_header(pki, registrar),
                                current_issuer=AirsIdentityResolutionRejected("AIRS identity is decommissioned"))
    assert result.authentication_results_result == "fail"
    assert any("decommissioned" in reason for reason in result.failure_reasons)


class TestAuthenticationResultsPropertyValues:
  def test_tokens_stay_bare_and_urns_and_urls_are_quoted(self):
    assert _authentication_results_property_value("sovereign") == "sovereign"
    assert _authentication_results_property_value("RS256") == "RS256"
    assert _authentication_results_property_value(AID) == f'"{AID}"'
    assert _authentication_results_property_value(ISSUER) == f'"{ISSUER}"'
    assert _authentication_results_property_value('a"b\\c') == '"a\\"b\\\\c"'

  def test_formatted_lines_quote_aid_and_issuer(self):
    mode1 = VerificationResult(is_valid=True, authentication_results_result="pass", typ="TPM", alg="RS256",
                               trust_tier="sovereign", agent_identity_urn=AID)
    assert _format_mode1_auth_results_line("mailpal.com", mode1) == (
      f'Authentication-Results: mailpal.com; hw-attest=pass header.typ=TPM header.alg=RS256 '
      f'header.tier=sovereign header.aid="{AID}"')
    mode2 = Mode2VerificationResult(is_valid=True, authentication_results_result="pass", trust_tier="sovereign",
                                    issuer=ISSUER, agent_identity_urn=AID, is_identified_mode=True)
    assert _format_mode2_auth_results_line("mailpal.com", mode2) == (
      f'Authentication-Results: mailpal.com; hw-trust=pass header.mode=identified header.tier=sovereign '
      f'header.issuer="{ISSUER}" header.aid="{AID}"')
