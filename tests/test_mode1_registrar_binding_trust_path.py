"""
Mode 1 Registrar-bound trust path: AUD-F20 (no trust store needed when
aid/bind verify), AUD-F04 (iss must equal the Registry's currentIssuer; key
only from that issuer's RFC 8414 JWK Set), AUD-F50 (ES256, RS256 and PS256
binding JWS), AUD-F77 (a malformed cnf.jwk fails), plus the draft's A-R result
names and "tier and aid only after Registrar binding".

Draft -03 changes tested here: the Registrar-bound path is the ONLY trust path
(EML-01, EML-07: the manufacturer-rooted path is reserved, so a certificate path
to a local root never makes `pass`), a valid signature with no trust path is
`policy`, an expired binding assertion is `policy` with the cause (EML-02), an
aid in the test namespace is `policy` with no tier or aid (EML-13), and the
binding must carry its aid claim object.

Real Mode 1 messages are signed with the generated PKI of the CMS profile
tests over the independently computed 92-octet attestation-input; the Registry
(currentIssuer) and the issuer's HTTPS documents are the only stubbed inputs.
"""

import base64
import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hw_attest_verify import TransientExternalLookupFailure, verify_hardware_attestation
from hw_attest_verify import issuer_key_discovery
from tests.test_mode1_cms_profile_and_certificate_path import (
  BODY,
  EMAIL_HEADERS,
  MODE1_LABEL,
  THIRTEEN_ALWAYS_COVERED_FIELDS,
  REFERENCE_TIME_UNIX,
  SIGNATURE_ALGORITHM_BY_NAME,
  GeneratedPkiForMode1Tests,
  build_signed_data,
)

REGISTRAR_ISSUER = "https://registrar.example/agents"
REGISTRAR_METADATA_URL = "https://registrar.example/.well-known/oauth-authorization-server/agents"
REGISTRAR_JWKS_URL = "https://registrar.example/keys/jwks.json"
AID = "urn:aid:global:id-qkckh-xxtcw-cxbvp-gpskg"


def b64url(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def ec_public_jwk(public_key, kid=None) -> dict:
  numbers = public_key.public_numbers()
  jwk = {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}
  if kid:
    jwk["kid"] = kid
  return jwk


def rsa_public_jwk(public_key, kid=None) -> dict:
  numbers = public_key.public_numbers()
  jwk = {"kty": "RSA", "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
         "e": b64url(numbers.e.to_bytes(3, "big"))}
  if kid:
    jwk["kid"] = kid
  return jwk


class Registrar:
  def __init__(self):
    self.ec_key = ec.generate_private_key(ec.SECP256R1())
    self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    self.jwk_set = {"keys": [ec_public_jwk(self.ec_key.public_key(), "reg-es256"),
                             rsa_public_jwk(self.rsa_key.public_key(), "reg-rsa")]}

  def sign(self, alg: str, header: dict, payload: dict, signing_key=None) -> str:
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}".encode()
    if alg == "ES256":
      r, s = decode_dss_signature((signing_key or self.ec_key).sign(signing_input, ec.ECDSA(hashes.SHA256())))
      signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif alg == "RS256":
      signature = (signing_key or self.rsa_key).sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:
      signature = (signing_key or self.rsa_key).sign(
        signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return f"{signing_input.decode()}.{b64url(signature)}"

  def binding_jws(self, cnf_jwk, alg="ES256", kid=None, iss=REGISTRAR_ISSUER, trust_tier="declared", signing_key=None,
                  sub=AID, iat=REFERENCE_TIME_UNIX, exp=REFERENCE_TIME_UNIX + 300, payload_overrides=None,
                  omit_claims=()):
    header = {"alg": alg, "kid": kid or ("reg-es256" if alg == "ES256" else "reg-rsa"), "typ": "airs-email-binding+jwt"}
    payload = {"iss": iss, "sub": sub, "iat": iat, "exp": exp,
               "cnf": {"jwk": cnf_jwk}, "aid": {"trust_tier": trust_tier}}
    payload.update(payload_overrides or {})
    for claim_name in omit_claims:
      payload.pop(claim_name, None)
    return self.sign(alg, header, payload, signing_key)


@pytest.fixture(scope="module")
def pki():
  return GeneratedPkiForMode1Tests()


@pytest.fixture(scope="module")
def registrar():
  return Registrar()


@pytest.fixture
def issuer_documents(registrar, monkeypatch):
  """The issuer's RFC 8414 metadata and JWK Set, served from a dict."""
  documents = {
    REGISTRAR_METADATA_URL: {"issuer": REGISTRAR_ISSUER, "jwks_uri": REGISTRAR_JWKS_URL},
    REGISTRAR_JWKS_URL: registrar.jwk_set,
  }

  def fetch(url):
    if url not in documents:
      raise ValueError(f"HTTP 404 for {url}")
    document = documents[url]
    if isinstance(document, Exception):
      raise document
    return document

  issuer_key_discovery._registrar_jwk_set_cache.clear()
  monkeypatch.setattr(issuer_key_discovery, "_fetch_json_document", fetch)
  yield documents
  issuer_key_discovery._registrar_jwk_set_cache.clear()


def signed_header_value(pki, tail_tags: str, typ="SFT") -> str:
  """A real Mode 1 header: ES256 over the draft's 92-octet attestation-input, with the
  chain value empty in the signed copy (self-reference) and aid/bind after it."""
  bh = b64url(hashlib.sha256(BODY).digest())
  head = f"v=1; typ={typ}; alg=ES256; h={':'.join(THIRTEEN_ALWAYS_COVERED_FIELDS)}; bh={bh}; ts={REFERENCE_TIME_UNIX}; chain="
  lowered = {name.lower(): value for name, value in EMAIL_HEADERS.items()}
  canonical = "".join(f"{name}:{lowered[name]}\r\n" for name in THIRTEEN_ALWAYS_COVERED_FIELDS if name in lowered)
  canonical += "hardware-attestation:" + (head + tail_tags).replace(" ", "") + "\r\n"
  attestation_input = (MODE1_LABEL + hashlib.sha256(canonical.encode()).digest() + hashlib.sha256(BODY).digest()
                       + struct.pack(">Q", REFERENCE_TIME_UNIX))
  assert len(attestation_input) == 92
  cms = build_signed_data(
    signature=pki.ec_leaf_key.sign(attestation_input, ec.ECDSA(hashes.SHA256())),
    certificates_in_set_order=[pki.ec_leaf, pki.intermediate, pki.root],
    signature_algorithm=SIGNATURE_ALGORITHM_BY_NAME["ES256"],
    sid_certificate=pki.ec_leaf,
  )
  return head + base64.b64encode(cms).decode() + tail_tags


def verify(header_value, current_issuer=REGISTRAR_ISSUER, trusted_roots=None, reference_time=REFERENCE_TIME_UNIX,
           expected_aid=AID, **verifier_policy_arguments):
  def resolver(aid):
    assert aid == expected_aid
    if isinstance(current_issuer, Exception):
      raise current_issuer
    return current_issuer
  return verify_hardware_attestation(
    header_value=header_value, email_headers=EMAIL_HEADERS, body=BODY,
    trusted_root_certificates=trusted_roots, reference_time_unix=reference_time,
    current_issuer_resolver=resolver, **verifier_policy_arguments,
  )


def bound_header(pki, registrar, aid=AID, **binding_arguments):
  cnf_jwk = binding_arguments.pop("cnf_jwk", None) or ec_public_jwk(pki.ec_leaf_key.public_key())
  binding_arguments.setdefault("sub", aid)
  return signed_header_value(pki, f"; aid={aid}; bind={registrar.binding_jws(cnf_jwk, **binding_arguments)}")


def assert_result(result, expected_result, reason_fragment=""):
  assert result.authentication_results_result == expected_result, result.failure_reasons
  assert result.is_valid == (expected_result == "pass")
  if reason_fragment:
    assert any(reason_fragment in reason for reason in result.failure_reasons), result.failure_reasons


class TestRegistrarBoundPathNeedsNoTrustStoreAudF20:
  def test_bound_message_passes_without_any_trust_store(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar))
    assert_result(result, "pass")
    assert result.registrar_binding_verified
    assert result.trust_path_that_succeeded == "registrar"
    assert result.manufacturer_rooted_path_verified is None
    assert result.agent_identity_urn == AID
    assert result.trust_tier == "declared"
    assert result.cms_signature_and_message_binding_verified

  def test_a_failed_path_to_local_roots_does_not_fail_a_verified_binding(self, pki, registrar, issuer_documents):
    # Draft -03 (EML-07): a certificate path to a local root is diagnostic only, never a trust path, so it cannot
    # fail (or help) a message whose Registrar binding verified.
    result = verify(bound_header(pki, registrar), trusted_roots=[pki.unrelated_root])
    assert_result(result, "pass")
    assert result.manufacturer_rooted_path_verified is None
    assert result.signer_certificate_path_to_supplied_roots_is_valid is False

  def test_a_valid_path_to_local_roots_is_not_reported_as_a_manufacturer_path(self, pki, registrar, issuer_documents):
    # EML-07: this version names no manufacturer-rooted evidence profile; "invent such evidence and report it as this
    # profile" is forbidden, so the path stays "registrar" even when the signer certificate chains to a supplied root.
    result = verify(bound_header(pki, registrar), trusted_roots=[pki.root])
    assert_result(result, "pass")
    assert result.registrar_binding_verified and result.trust_path_that_succeeded == "registrar"
    assert result.manufacturer_rooted_path_verified is None
    assert result.signer_certificate_path_to_supplied_roots_is_valid is True

  def test_unbound_message_has_no_trust_path_and_is_policy_not_fail(self, pki, issuer_documents):
    # EML-01: "a valid CMS signature with no successful path ... is reported as policy".
    result = verify(signed_header_value(pki, ""))
    assert_result(result, "policy", "no trust path was established")
    assert result.cms_signature_and_message_binding_verified and result.trust_path_that_succeeded == ""

  def test_unbound_message_with_a_valid_path_to_local_roots_is_still_policy(self, pki, issuer_documents):
    result = verify(signed_header_value(pki, ""), trusted_roots=[pki.root])
    assert_result(result, "policy", "no trust path was established")
    assert result.manufacturer_rooted_path_verified is None
    assert result.signer_certificate_path_to_supplied_roots_is_valid is True
    assert result.agent_identity_urn is None and result.trust_tier == ""
    assert not result.registrar_binding_verified


class TestBindingAuthorityComesFromTheRegistryAudF04:
  def test_iss_that_is_not_the_current_issuer_fails(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar), current_issuer="https://other-registrar.example/agents")
    assert_result(result, "fail", "does not equal the Registry currentIssuer")
    assert result.agent_identity_urn is None and result.trust_tier == ""

  def test_identity_without_a_current_issuer_fails(self, pki, registrar, issuer_documents):
    assert_result(verify(bound_header(pki, registrar), current_issuer=None), "fail", "no current issuer")

  def test_registry_that_cannot_be_reached_is_temperror(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar), current_issuer=TransientExternalLookupFailure("timed out"))
    assert_result(result, "temperror", "timed out")

  def test_issuer_metadata_that_cannot_be_fetched_is_temperror(self, pki, registrar, issuer_documents):
    issuer_documents[REGISTRAR_METADATA_URL] = TransientExternalLookupFailure("HTTP 503")
    assert_result(verify(bound_header(pki, registrar)), "temperror", "HTTP 503")

  def test_metadata_naming_another_issuer_is_not_used(self, pki, registrar, issuer_documents):
    issuer_documents[REGISTRAR_METADATA_URL] = {"issuer": "https://registrar.example", "jwks_uri": REGISTRAR_JWKS_URL}
    assert_result(verify(bound_header(pki, registrar)), "fail", "metadata issuer")

  def test_metadata_without_jwks_uri_fails(self, pki, registrar, issuer_documents):
    issuer_documents[REGISTRAR_METADATA_URL] = {"issuer": REGISTRAR_ISSUER}
    assert_result(verify(bound_header(pki, registrar)), "fail", "jwks_uri")

  def test_kid_missing_from_the_jwk_set_fails(self, pki, registrar, issuer_documents):
    assert_result(verify(bound_header(pki, registrar, kid="not-published")), "fail", "not found in the JWK Set")

  def test_binding_signed_by_an_unpublished_key_fails(self, pki, registrar, issuer_documents):
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    assert_result(verify(bound_header(pki, registrar, signing_key=attacker_key)), "fail", "signature verification failed")


class TestBindingAlgorithmsAudF50:
  @pytest.mark.parametrize("alg", ["RS256", "PS256"])
  def test_rsa_binding_algorithms_verify(self, pki, registrar, issuer_documents, alg):
    assert_result(verify(bound_header(pki, registrar, alg=alg)), "pass")

  def test_rs256_signature_presented_as_ps256_fails(self, pki, registrar, issuer_documents):
    rs256_binding = registrar.binding_jws(ec_public_jwk(pki.ec_leaf_key.public_key()), alg="RS256")
    header_b64, payload_b64, signature_b64 = rs256_binding.split(".")
    relabelled_header = b64url(json.dumps({"alg": "PS256", "kid": "reg-rsa", "typ": "airs-email-binding+jwt"}).encode())
    forged = f"{relabelled_header}.{payload_b64}.{signature_b64}"
    assert_result(verify(signed_header_value(pki, f"; aid={AID}; bind={forged}")), "fail", "signature verification failed")


class TestConfirmationKeyAudF77:
  def test_malformed_cnf_jwk_fails_instead_of_skipping_the_key_check(self, pki, registrar, issuer_documents):
    malformed_jwk = {"kty": "EC", "crv": "P-256", "x": "AAAA"}
    assert_result(verify(bound_header(pki, registrar, cnf_jwk=malformed_jwk)), "fail", "cnf.jwk is malformed")

  def test_cnf_jwk_of_another_key_fails(self, pki, registrar, issuer_documents):
    other_key_jwk = ec_public_jwk(pki.unrelated_key.public_key())
    assert_result(verify(bound_header(pki, registrar, cnf_jwk=other_key_jwk)), "fail", "does not match CMS signer")


class TestResultNamesFromTheDraft:
  def test_aid_without_bind_is_permerror(self, pki, issuer_documents):
    assert_result(verify(signed_header_value(pki, f"; aid={AID}")), "permerror", "bind is absent")

  def test_stale_timestamp_is_policy_not_fail(self, pki, issuer_documents):
    result = verify(signed_header_value(pki, ""), trusted_roots=[pki.root], reference_time=REFERENCE_TIME_UNIX + 86400)
    assert_result(result, "policy", "local freshness policy")

  def test_stale_timestamp_on_a_bound_message_is_policy_for_that_reason_alone(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, exp=REFERENCE_TIME_UNIX + 200000),
                    reference_time=REFERENCE_TIME_UNIX + 86400)
    assert_result(result, "policy", "local freshness policy")
    assert len(result.failure_reasons) == 1
    assert result.registrar_binding_verified and result.trust_path_that_succeeded == "registrar"

  def test_signer_key_thumbprint_and_h_list_are_recorded_for_combined_mode(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar))
    from hw_attest_verify.mode1 import _compute_jwk_thumbprint_from_jwk_dict
    assert result.signer_public_key_jwk_thumbprint == _compute_jwk_thumbprint_from_jwk_dict(
      ec_public_jwk(pki.ec_leaf_key.public_key()))
    assert [name.lower() for name in result.signed_header_names] == THIRTEEN_ALWAYS_COVERED_FIELDS


class TestExpiredBindingAssertionIsPolicyEml02:
  """Draft -03 "Registrar Binding JWS": "A verifier that finds the assertion expired reports policy, with the cause in
  the comment, not fail: the CMS signature verified, and the Registrar's assertion was no longer current when
  checked." The skew allowance is the verifier's normal small clock-skew allowance (300 s by default)."""

  def test_expired_but_genuine_binding_is_policy_with_the_cause(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX - 3600, exp=REFERENCE_TIME_UNIX - 600))
    assert_result(result, "policy", "binding assertion has expired")
    assert result.registrar_assertion_has_expired
    assert result.cms_signature_and_message_binding_verified
    assert not result.registrar_binding_verified and result.trust_path_that_succeeded == ""
    assert result.agent_identity_urn is None and result.trust_tier == ""

  def test_expiry_inside_the_clock_skew_allowance_still_passes(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX - 3600, exp=REFERENCE_TIME_UNIX - 300))
    assert_result(result, "pass")
    assert not result.registrar_assertion_has_expired

  def test_expiry_one_second_beyond_the_clock_skew_allowance_is_policy(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX - 3600, exp=REFERENCE_TIME_UNIX - 301))
    assert_result(result, "policy", "binding assertion has expired")

  def test_forged_expired_binding_stays_a_failure(self, pki, registrar, issuer_documents):
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX - 3600, exp=REFERENCE_TIME_UNIX - 600,
                                 signing_key=attacker_key))
    assert_result(result, "fail", "signature verification failed")
    assert not result.registrar_assertion_has_expired

  def test_expired_binding_from_the_wrong_issuer_stays_a_failure(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX - 3600, exp=REFERENCE_TIME_UNIX - 600),
                    current_issuer="https://other-registrar.example/agents")
    assert_result(result, "fail", "does not equal the Registry currentIssuer")

  def test_exp_that_is_not_later_than_iat_is_still_a_failure(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX, exp=REFERENCE_TIME_UNIX))
    assert_result(result, "fail", "exp must be later than iat")

  def test_iat_materially_in_the_future_is_a_failure(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX + 301, exp=REFERENCE_TIME_UNIX + 900))
    assert_result(result, "fail", "iat is in the future")


class TestTestNamespaceIdentityIsPolicyEml13:
  """Draft -03 `agent-identity-format`: "An aid in the Registry's test namespace (urn:aid:test:) carries no
  production assurance. A verifier applying production policy MUST report it as policy, and MUST NOT report a tier or
  aid property for it." The binding is still checked in full, so a forged one is a failure."""

  TEST_AID = "urn:aid:test:id-qkckh-xxtcw-cxbvp-gpskg"

  def test_genuine_test_namespace_binding_is_policy_with_no_tier_and_no_aid(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar, aid=self.TEST_AID), expected_aid=self.TEST_AID)
    assert_result(result, "policy", "test namespace")
    assert result.aid_is_in_the_registry_test_namespace
    assert result.agent_identity_urn is None and result.trust_tier == ""
    assert result.cms_signature_and_message_binding_verified

  def test_the_namespace_prefix_compares_case_insensitively(self, pki, registrar, issuer_documents):
    mixed_case_aid = "URN:AID:Test:id-qkckh-xxtcw-cxbvp-gpskg"
    result = verify(bound_header(pki, registrar, aid=mixed_case_aid), expected_aid=mixed_case_aid)
    assert_result(result, "policy", "test namespace")
    assert result.agent_identity_urn is None and result.trust_tier == ""

  def test_forged_test_namespace_binding_is_still_a_failure(self, pki, registrar, issuer_documents):
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    result = verify(bound_header(pki, registrar, aid=self.TEST_AID, signing_key=attacker_key), expected_aid=self.TEST_AID)
    assert_result(result, "fail", "signature verification failed")
    assert result.agent_identity_urn is None and result.trust_tier == ""

  def test_production_namespace_is_unaffected(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar))
    assert_result(result, "pass")
    assert not result.aid_is_in_the_registry_test_namespace
    assert result.agent_identity_urn == AID and result.trust_tier == "declared"


class TestBindingClaimObjectIsRequiredAndMalformedClaimsFailClosed:
  """Draft -03: the binding's `aid` claim object is REQUIRED ("Its trust_tier member reports the tier of this enrolled
  proof binding") and trust_tier MUST correspond to typ. A hostile claim of the wrong JSON type is a failure, never an
  exception."""

  @pytest.mark.parametrize("payload_overrides, omit_claims, reason_fragment", [
    ({}, ("aid",), "missing the aid claim object"),
    ({"aid": {}}, (), "missing the aid claim object"),
    ({"aid": {"trust_tier": ""}}, (), "missing the aid claim object"),
    ({"aid": "declared"}, (), "missing the aid claim object"),
    ({"aid": ["declared"]}, (), "missing the aid claim object"),
    ({"aid": {"trust_tier": "sovereign"}}, (), "does not match expected tier for typ='SFT'"),
  ])
  def test_aid_claim_object_problems_fail(self, pki, registrar, issuer_documents, payload_overrides, omit_claims, reason_fragment):
    header = bound_header(pki, registrar, payload_overrides=payload_overrides, omit_claims=omit_claims)
    assert_result(verify(header), "fail", reason_fragment)

  @pytest.mark.parametrize("claim_name", ["iat", "exp"])
  @pytest.mark.parametrize("bad_value", ["1790000000", True, None, [1790000000], {"n": 1}])
  def test_a_numeric_date_claim_that_is_not_a_number_is_a_failure_not_an_exception(
      self, pki, registrar, issuer_documents, claim_name, bad_value):
    header = bound_header(pki, registrar, payload_overrides={claim_name: bad_value})
    result = verify(header)
    assert result.authentication_results_result == "fail", result.failure_reasons
    assert any(claim_name in reason for reason in result.failure_reasons), result.failure_reasons

  @pytest.mark.parametrize("claim_name", ["iat", "exp"])
  def test_a_non_finite_numeric_date_is_a_failure_not_an_exception(self, pki, registrar, issuer_documents, claim_name):
    # json.loads accepts the non-standard literals NaN and Infinity by default; int() of either raises.
    bind_value = registrar.binding_jws(ec_public_jwk(pki.ec_leaf_key.public_key()))
    header_b64, payload_b64, signature_b64 = bind_value.split(".")
    payload_text = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode()
    tampered_payload = payload_text.replace(f'"{claim_name}": ', f'"{claim_name}": Infinity, "x": ', 1)
    assert "Infinity" in tampered_payload
    tampered_bind = f"{header_b64}.{b64url(tampered_payload.encode())}.{signature_b64}"
    # The tampered binding is carried inside a freshly CMS-signed header, so the Mode 1 signature itself is valid
    # and only the binding claim is hostile.
    result = verify(signed_header_value(pki, f"; aid={AID}; bind={tampered_bind}"))
    assert result.authentication_results_result == "fail", result.failure_reasons
    assert any(claim_name in reason for reason in result.failure_reasons), result.failure_reasons

  def test_a_binding_whose_header_is_not_a_json_object_is_a_failure(self, pki, registrar, issuer_documents):
    not_an_object = f"{b64url(b'[1]')}.{b64url(b'{}')}.{b64url(b'x')}"
    result = verify(signed_header_value(pki, f"; aid={AID}; bind={not_an_object}"))
    assert_result(result, "fail", "must each be a JSON object")


class TestHeaderSizeLimit:
  """Draft -03 "Header Size Considerations": "A verifier SHOULD reject a field larger than its local limit as permerror
  without decoding it.\""""

  def test_a_field_over_the_local_limit_is_permerror_without_decoding(self, pki, registrar, issuer_documents):
    header = bound_header(pki, registrar)
    result = verify_hardware_attestation(
      header_value=header, email_headers=EMAIL_HEADERS, body=BODY, reference_time_unix=REFERENCE_TIME_UNIX,
      maximum_header_field_value_octets=len(header) - 1,
      current_issuer_resolver=lambda aid: REGISTRAR_ISSUER)
    assert_result(result, "permerror", "over the local limit")

  def test_a_field_exactly_at_the_limit_is_processed(self, pki, registrar, issuer_documents):
    header = bound_header(pki, registrar)
    result = verify_hardware_attestation(
      header_value=header, email_headers=EMAIL_HEADERS, body=BODY, reference_time_unix=REFERENCE_TIME_UNIX,
      maximum_header_field_value_octets=len(header),
      current_issuer_resolver=lambda aid: REGISTRAR_ISSUER)
    assert_result(result, "pass")


class TestTimestampStalenessIsALocalPolicySeparateFromClockSkew:
  """Draft -03 step 3: "Apply local freshness policy to ts. A stale but otherwise cryptographically valid proof is a
  policy outcome." A receiver that verifies after queueing and greylisting (the first trusted MTA) accepts a ts as old
  as the Registrar mail assertion lifetime; that must not also accept a ts from the future."""

  ONE_HOUR = 3600
  A_BINDING_THAT_OUTLIVES_EVERY_REFERENCE_TIME_USED_HERE = REFERENCE_TIME_UNIX + 400000

  def bound(self, pki, registrar):
    # The binding was issued a day before the proof: a binding iat in the future would be a (correct) ail of its own
    # in the from-the-future cases, and these tests are about ts.
    return bound_header(pki, registrar, iat=REFERENCE_TIME_UNIX - 86400,
                        exp=self.A_BINDING_THAT_OUTLIVES_EVERY_REFERENCE_TIME_USED_HERE)

  def test_default_policy_is_unchanged_a_ts_300_seconds_old_passes_and_301_is_policy(self, pki, registrar, issuer_documents):
    assert_result(verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX + 300), "pass")
    assert_result(verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX + 301), "policy", "ts is 301s old")

  def test_a_longer_age_allowance_accepts_a_ts_one_hour_old(self, pki, registrar, issuer_documents):
    result = verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX + self.ONE_HOUR,
                    max_timestamp_age_seconds=self.ONE_HOUR)
    assert_result(result, "pass")

  def test_a_ts_beyond_the_longer_age_allowance_is_policy_and_names_the_allowance(self, pki, registrar, issuer_documents):
    result = verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX + self.ONE_HOUR + 1,
                    max_timestamp_age_seconds=self.ONE_HOUR)
    assert_result(result, "policy", f"ts is {self.ONE_HOUR + 1}s old")
    assert any(f"policy allows {self.ONE_HOUR}s" in reason for reason in result.failure_reasons)
    assert result.registrar_binding_verified

  def test_a_longer_age_allowance_does_not_widen_the_tolerance_for_a_ts_from_the_future(self, pki, registrar, issuer_documents):
    # The reference time is BEFORE the signed ts: the sender's clock is ahead of the receiver's.
    inside_skew = verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX - 300,
                         max_timestamp_age_seconds=86400)
    assert_result(inside_skew, "pass")
    beyond_skew = verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX - 301,
                         max_timestamp_age_seconds=86400)
    assert_result(beyond_skew, "policy", "ts is 301s in the future")

  def test_an_age_allowance_shorter_than_the_skew_makes_the_receiver_stricter_about_old_messages_only(self, pki, registrar, issuer_documents):
    stricter = verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX + 61, max_timestamp_age_seconds=60)
    assert_result(stricter, "policy", "ts is 61s old")
    future_within_skew = verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX - 200,
                                max_timestamp_age_seconds=60)
    assert_result(future_within_skew, "pass")

  def test_widening_the_skew_alone_widens_both_directions_for_the_no_time_check_option(self, pki, registrar, issuer_documents):
    # `python -m hw_attest_verify --no-time-check` passes only the skew (999999999); the age allowance then follows it.
    a_year = 365 * 86400
    assert_result(verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX + a_year,
                         max_timestamp_skew_seconds=999_999_999), "pass")
    assert_result(verify(self.bound(pki, registrar), reference_time=REFERENCE_TIME_UNIX - a_year,
                         max_timestamp_skew_seconds=999_999_999), "pass")