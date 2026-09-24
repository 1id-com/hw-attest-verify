"""
Mode 1 Registrar-bound trust path (hw-attest-verify 2.0.1): AUD-F20 (no trust
store needed when aid/bind verify), AUD-F04 (iss must equal the Registry's
currentIssuer; key only from that issuer's RFC 8414 JWK Set), AUD-F50 (ES256,
RS256 and PS256 binding JWS), AUD-F77 (a malformed cnf.jwk fails), plus the
draft's A-R result names and "tier and aid only after Registrar binding".

Real Mode 1 messages are signed with the generated PKI of the CMS profile
tests; the Registry (currentIssuer) and the issuer's HTTPS documents are the
only stubbed inputs.
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
  NINE_ALWAYS_COVERED_FIELDS,
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

  def binding_jws(self, cnf_jwk, alg="ES256", kid=None, iss=REGISTRAR_ISSUER, trust_tier="declared", signing_key=None):
    header = {"alg": alg, "kid": kid or ("reg-es256" if alg == "ES256" else "reg-rsa"), "typ": "airs-email-binding+jwt"}
    payload = {"iss": iss, "sub": AID, "iat": REFERENCE_TIME_UNIX, "exp": REFERENCE_TIME_UNIX + 300,
               "cnf": {"jwk": cnf_jwk}, "aid": {"trust_tier": trust_tier}}
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
  """A real Mode 1 header: ES256 over the draft's attestation-input, with the
  chain value empty in the signed copy (self-reference) and aid/bind after it."""
  bh = b64url(hashlib.sha256(BODY).digest())
  head = f"v=1; typ={typ}; alg=ES256; h={':'.join(NINE_ALWAYS_COVERED_FIELDS)}; bh={bh}; ts={REFERENCE_TIME_UNIX}; chain="
  lowered = {name.lower(): value for name, value in EMAIL_HEADERS.items()}
  canonical = "".join(f"{name}:{lowered[name]}\r\n" for name in NINE_ALWAYS_COVERED_FIELDS if name in lowered)
  canonical += "hardware-attestation:" + (head + tail_tags).replace(" ", "") + "\r\n"
  attestation_input = (hashlib.sha256(canonical.encode()).digest() + hashlib.sha256(BODY).digest()
                       + struct.pack(">Q", REFERENCE_TIME_UNIX))
  cms = build_signed_data(
    signature=pki.ec_leaf_key.sign(attestation_input, ec.ECDSA(hashes.SHA256())),
    certificates_in_set_order=[pki.ec_leaf, pki.intermediate, pki.root],
    signature_algorithm=SIGNATURE_ALGORITHM_BY_NAME["ES256"],
    sid_certificate=pki.ec_leaf,
  )
  return head + base64.b64encode(cms).decode() + tail_tags


def verify(header_value, current_issuer=REGISTRAR_ISSUER, trusted_roots=None, reference_time=REFERENCE_TIME_UNIX):
  def resolver(aid):
    assert aid == AID
    if isinstance(current_issuer, Exception):
      raise current_issuer
    return current_issuer
  return verify_hardware_attestation(
    header_value=header_value, email_headers=EMAIL_HEADERS, body=BODY,
    trusted_root_certificates=trusted_roots, reference_time_unix=reference_time,
    current_issuer_resolver=resolver,
  )


def bound_header(pki, registrar, **binding_arguments):
  cnf_jwk = binding_arguments.pop("cnf_jwk", None) or ec_public_jwk(pki.ec_leaf_key.public_key())
  return signed_header_value(pki, f"; aid={AID}; bind={registrar.binding_jws(cnf_jwk, **binding_arguments)}")


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
    assert result.manufacturer_rooted_path_verified is None
    assert result.agent_identity_urn == AID
    assert result.trust_tier == "declared"

  def test_failed_manufacturer_path_does_not_fail_a_verified_binding(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar), trusted_roots=[pki.unrelated_root])
    assert_result(result, "pass")
    assert result.manufacturer_rooted_path_verified is False

  def test_both_paths_recorded_when_both_verify(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar), trusted_roots=[pki.root])
    assert_result(result, "pass")
    assert result.registrar_binding_verified and result.manufacturer_rooted_path_verified

  def test_unbound_message_still_needs_the_manufacturer_path(self, pki, issuer_documents):
    assert_result(verify(signed_header_value(pki, "")), "fail", "manufacturer-rooted path")

  def test_manufacturer_only_result_reports_no_aid_and_no_tier(self, pki, issuer_documents):
    result = verify(signed_header_value(pki, ""), trusted_roots=[pki.root])
    assert_result(result, "pass")
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

  def test_signer_key_thumbprint_and_h_list_are_recorded_for_combined_mode(self, pki, registrar, issuer_documents):
    result = verify(bound_header(pki, registrar))
    from hw_attest_verify.mode1 import _compute_jwk_thumbprint_from_jwk_dict
    assert result.signer_public_key_jwk_thumbprint == _compute_jwk_thumbprint_from_jwk_dict(
      ec_public_jwk(pki.ec_leaf_key.public_key()))
    assert [name.lower() for name in result.signed_header_names] == NINE_ALWAYS_COVERED_FIELDS
