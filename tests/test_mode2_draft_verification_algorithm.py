"""
Mode 2 per the email draft's verification algorithm (hw-attest-verify 2.0.1):
AUD-F03 (identified mode needs a resolved currentIssuer), AUD-F16 (hidden mode
needs a locally trusted issuer), AUD-F17 (aid.trust_tier must be disclosed),
AUD-F18 (asymmetric algorithms beyond ES256), AUD-F49 (age is policy; future
iat and exp are failures), AUD-F51 (kid required), AUD-F52 (RFC 9901
disclosure processing, nested and array digests), the cnf rule, duplicate
fields (AUD-F76) and RFC 8414 key discovery.

Presentations are really signed; only the Registry answer and the issuer's
HTTPS documents are stubbed.
"""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hw_attest_verify import TransientExternalLookupFailure, issuer_key_discovery
from hw_attest_verify.mode2 import _compute_message_binding_nonce, verify_hardware_trust_proof

ISSUER = "https://registrar.example/agents"
AID = "urn:aid:global:id-qkckh-xxtcw-cxbvp-gpskg"
NOW = 1_790_000_000
HEADERS = {
  "from": "agent@example.com", "to": "human@example.org", "subject": "Mode 2 test",
  "date": "Mon, 21 Sep 2026 14:13:20 +0000", "message-id": "<mode2@example.com>",
}
BODY = b"Mode 2 draft algorithm test body.\r\n"

EC_ISSUER_KEY = ec.generate_private_key(ec.SECP256R1())
RSA_ISSUER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def disclosure(*elements) -> str:
  return b64url(json.dumps(list(elements)).encode())


def digest_of(disclosure_b64: str) -> str:
  return b64url(hashlib.sha256(disclosure_b64.encode("ascii")).digest())


AID_DISCLOSURE = disclosure("salt-aid", "aid", {"trust_tier": "sovereign"})
SUB_DISCLOSURE = disclosure("salt-sub", "sub", AID)


def presentation(payload_overrides=None, header_overrides=None, disclosures=(AID_DISCLOSURE, SUB_DISCLOSURE),
                 digests=None, signing_key=None, iat=NOW, headers=HEADERS):
  header = {"alg": "ES256", "kid": "reg-es256", "typ": "airs-email+sd-jwt"}
  header.update(header_overrides or {})
  payload = {"iss": ISSUER, "iat": iat, "exp": iat + 300, "_sd_alg": "sha-256",
             "nonce": _compute_message_binding_nonce(headers, BODY, iat),
             "_sd": digests if digests is not None else [digest_of(item) for item in disclosures]}
  payload.update(payload_overrides or {})
  for claim_name in [name for name, value in payload.items() if value is None]:
    del payload[claim_name]
  signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}".encode()
  alg = header["alg"]
  if alg == "RS256":
    signature = (signing_key or RSA_ISSUER_KEY).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
  elif alg == "PS256":
    signature = (signing_key or RSA_ISSUER_KEY).sign(
      signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
  else:
    r, s = decode_dss_signature((signing_key or EC_ISSUER_KEY).sign(signing_input, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
  return f"{signing_input.decode()}.{b64url(signature)}~" + "".join(f"{item}~" for item in disclosures)


def verify(header_value, current_issuer=ISSUER, trusted_hidden=(), key="auto", headers=HEADERS,
           ordered_header_pairs=None, reference_time=NOW, **keyword_arguments):
  def resolver(aid):
    if isinstance(current_issuer, Exception):
      raise current_issuer
    return current_issuer
  if key == "auto":
    key = RSA_ISSUER_KEY.public_key() if '"alg": "RS' in _decoded_header(header_value) or '"alg": "PS' in _decoded_header(header_value) \
      else EC_ISSUER_KEY.public_key()
  return verify_hardware_trust_proof(
    header_value=header_value, email_headers=headers, body=BODY, ordered_header_pairs=ordered_header_pairs,
    reference_time_unix=reference_time, issuer_public_key_override=key, current_issuer_resolver=resolver,
    trusted_hidden_mode_issuers=list(trusted_hidden), **keyword_arguments,
  )


def _decoded_header(header_value: str) -> str:
  encoded = header_value.split(".")[0]
  return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()


def assert_result(result, expected_result, reason_fragment=""):
  assert result.authentication_results_result == expected_result, result.failure_reasons
  assert result.is_valid == (expected_result == "pass")
  if reason_fragment:
    assert any(reason_fragment in reason for reason in result.failure_reasons), result.failure_reasons


class TestIdentifiedModeResolutionAudF03:
  def test_identified_presentation_passes_with_the_current_issuer(self):
    result = verify(presentation())
    assert_result(result, "pass")
    assert result.is_identified_mode and result.rdap_issuer_verified
    assert result.agent_identity_urn == AID and result.trust_tier == "sovereign"

  def test_identity_without_a_current_issuer_fails(self):
    assert_result(verify(presentation(), current_issuer=None), "fail", "no current issuer")

  def test_registry_that_cannot_be_reached_is_temperror_not_pass(self):
    assert_result(verify(presentation(), current_issuer=TransientExternalLookupFailure("timed out")), "temperror", "timed out")

  def test_other_current_issuer_fails(self):
    assert_result(verify(presentation(), current_issuer="https://other.example/agents"), "fail", "does not match JWT iss")


class TestHiddenModeIssuerPolicyAudF16:
  def test_untrusted_issuer_is_policy(self):
    assert_result(verify(presentation(disclosures=(AID_DISCLOSURE,))), "policy", "local policy does not trust")

  def test_trusted_issuer_passes_as_hidden(self):
    result = verify(presentation(disclosures=(AID_DISCLOSURE,)), trusted_hidden=[ISSUER])
    assert_result(result, "pass")
    assert not result.is_identified_mode and result.agent_identity_urn == ""

  def test_hidden_mode_does_not_consult_the_registry(self):
    result = verify(presentation(disclosures=(AID_DISCLOSURE,)), trusted_hidden=[ISSUER],
                    current_issuer=AssertionError("resolver must not be called"))
    assert_result(result, "pass")


class TestTrustTierDisclosureAudF17:
  def test_missing_trust_tier_disclosure_fails(self):
    assert_result(verify(presentation(disclosures=(SUB_DISCLOSURE,))), "fail", "aid.trust_tier is not disclosed")


class TestAlgorithmsAudF18AndKidAudF51:
  @pytest.mark.parametrize("alg", ["RS256", "PS256"])
  def test_rsa_issuer_algorithms_verify(self, alg):
    assert_result(verify(presentation(header_overrides={"alg": alg, "kid": "reg-rsa"})), "pass")

  @pytest.mark.parametrize("alg", ["none", "HS256", "ES384", ""])
  def test_other_algorithms_are_permerror(self, alg):
    assert_result(verify(presentation(header_overrides={"alg": alg})), "permerror", "Unsupported algorithm")

  def test_missing_kid_is_permerror(self):
    assert_result(verify(presentation(header_overrides={"kid": None})), "permerror", "kid")

  def test_signature_with_the_wrong_key_fails(self):
    assert_result(verify(presentation(signing_key=ec.generate_private_key(ec.SECP256R1()))), "fail", "Signature")


class TestRfc9901DisclosureProcessingAudF52:
  def test_nested_trust_tier_disclosure_inside_a_visible_aid_object(self):
    trust_tier_disclosure = disclosure("salt-tier", "trust_tier", "portable")
    result = verify(presentation(payload_overrides={"aid": {"_sd": [digest_of(trust_tier_disclosure)]}},
                                 disclosures=(trust_tier_disclosure, SUB_DISCLOSURE),
                                 digests=[digest_of(SUB_DISCLOSURE)]))
    assert_result(result, "pass")
    assert result.trust_tier == "portable"

  def test_array_element_disclosure_is_processed_and_decoys_are_ignored(self):
    element_disclosure = disclosure("salt-element", "second")
    result = verify(presentation(
      payload_overrides={"items": ["first", {"...": digest_of(element_disclosure)}, {"...": "decoy-digest"}]},
      disclosures=(AID_DISCLOSURE, SUB_DISCLOSURE, element_disclosure),
      digests=[digest_of(AID_DISCLOSURE), digest_of(SUB_DISCLOSURE), "another-decoy"]))
    assert_result(result, "pass")
    assert result.disclosed_claims["items"] == ["first", "second"]

  def test_digest_that_appears_twice_fails(self):
    digest = digest_of(AID_DISCLOSURE)
    assert_result(verify(presentation(digests=[digest, digest, digest_of(SUB_DISCLOSURE)])), "fail", "more than once")

  def test_disclosure_not_referenced_by_any_digest_fails(self):
    stray = disclosure("salt-stray", "extra", 1)
    result = verify(presentation(disclosures=(AID_DISCLOSURE, SUB_DISCLOSURE, stray),
                                 digests=[digest_of(AID_DISCLOSURE), digest_of(SUB_DISCLOSURE)]))
    assert_result(result, "fail", "not referenced")

  def test_selectively_disclosed_iss_is_rejected(self):
    # Without a visible iss the presentation is malformed; with one, a
    # disclosed iss collides with it -- either way it never verifies.
    iss_disclosure = disclosure("salt-iss", "iss", "https://attacker.example")
    assert_result(verify(presentation(payload_overrides={"iss": None},
                                      disclosures=(AID_DISCLOSURE, SUB_DISCLOSURE, iss_disclosure))), "permerror", "iss")
    assert_result(verify(presentation(disclosures=(AID_DISCLOSURE, SUB_DISCLOSURE, iss_disclosure))), "fail", "already present")

  def test_selectively_disclosed_cnf_is_rejected(self):
    cnf_disclosure = disclosure("salt-cnf", "cnf", {"jwk": {"kty": "EC"}})
    result = verify(presentation(disclosures=(AID_DISCLOSURE, SUB_DISCLOSURE, cnf_disclosure)))
    assert_result(result, "fail", "MUST NOT be selectively disclosable")

  def test_disclosure_that_overwrites_a_visible_claim_fails(self):
    overwrite = disclosure("salt-overwrite", "aid", {"trust_tier": "sovereign"})
    result = verify(presentation(payload_overrides={"aid": {"trust_tier": "declared"}},
                                 disclosures=(overwrite, SUB_DISCLOSURE)))
    assert_result(result, "fail", "already present")


class TestTimeRulesAudF49:
  def test_old_proof_without_exp_is_policy(self):
    result = verify(presentation(payload_overrides={"exp": None}), reference_time=NOW + 3600)
    assert_result(result, "policy", "local age policy")

  def test_expired_proof_fails(self):
    assert_result(verify(presentation(), reference_time=NOW + 3600), "fail", "expired")

  def test_materially_future_iat_fails(self):
    assert_result(verify(presentation(), reference_time=NOW - 3600), "fail", "future")

  def test_archival_verification_skips_the_time_rules(self):
    assert_result(verify(presentation(), reference_time=NOW + 86400 * 30, skip_time_checks=True), "pass")


class TestCnfAndMessageStructure:
  CNF = {"jwk": {"kty": "EC", "crv": "P-256",
                 "x": b64url(EC_ISSUER_KEY.public_key().public_numbers().x.to_bytes(32, "big")),
                 "y": b64url(EC_ISSUER_KEY.public_key().public_numbers().y.to_bytes(32, "big"))}}

  def test_cnf_without_a_hardware_attestation_field_fails(self):
    assert_result(verify(presentation(payload_overrides={"cnf": self.CNF})), "fail", "no Hardware-Attestation field")

  def test_cnf_with_a_hardware_attestation_field_records_the_thumbprint(self):
    headers_with_mode1 = dict(HEADERS, **{"hardware-attestation": "v=1; ..."})
    result = verify(presentation(payload_overrides={"cnf": self.CNF}, headers=headers_with_mode1), headers=headers_with_mode1)
    assert_result(result, "pass")
    assert result.carries_cnf_claim and len(result.cnf_jwk_thumbprint) == 43

  def test_duplicate_singleton_field_is_permerror(self):
    ordered_pairs = list(HEADERS.items()) + [("Subject", "second subject")]
    assert_result(verify(presentation(), ordered_header_pairs=ordered_pairs), "permerror", "Duplicate")

  def test_modified_body_fails_the_nonce(self):
    result = verify_hardware_trust_proof(
      header_value=presentation(), email_headers=HEADERS, body=b"changed\r\n", reference_time_unix=NOW,
      issuer_public_key_override=EC_ISSUER_KEY.public_key(), current_issuer_resolver=lambda aid: ISSUER)
    assert_result(result, "fail", "nonce")


class TestRfc8414KeyDiscovery:
  @pytest.fixture
  def issuer_documents(self, monkeypatch):
    documents = {
      "https://registrar.example/.well-known/oauth-authorization-server/agents":
        {"issuer": ISSUER, "jwks_uri": "https://registrar.example/jwks"},
      "https://registrar.example/jwks": {"keys": [
        {"kty": "EC", "crv": "P-256", "kid": "reg-es256", "use": "sig",
         "x": b64url(EC_ISSUER_KEY.public_key().public_numbers().x.to_bytes(32, "big")),
         "y": b64url(EC_ISSUER_KEY.public_key().public_numbers().y.to_bytes(32, "big"))}]},
    }
    issuer_key_discovery._registrar_jwk_set_cache.clear()
    monkeypatch.setattr(issuer_key_discovery, "_fetch_json_document", lambda url: documents[url])
    yield documents
    issuer_key_discovery._registrar_jwk_set_cache.clear()

  def test_key_is_discovered_from_the_issuer_metadata(self, issuer_documents):
    assert_result(verify(presentation(), key=None), "pass")

  def test_unknown_kid_fails(self, issuer_documents):
    assert_result(verify(presentation(header_overrides={"kid": "other"}), key=None), "fail", "not found in the JWK Set")

  def test_rfc8414_metadata_url_inserts_the_well_known_segment_before_the_path(self):
    assert issuer_key_discovery.build_rfc8414_metadata_url_for_issuer("https://1id.com/realms/agents") == \
      "https://1id.com/.well-known/oauth-authorization-server/realms/agents"
    assert issuer_key_discovery.build_rfc8414_metadata_url_for_issuer("http://1id.com/realms/agents") is None
