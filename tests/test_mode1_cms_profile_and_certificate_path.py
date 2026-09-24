"""
Mode 1 strict CMS profile (AUD-F78), PS256 salt (AUD-F79), certificate path
building (AUD-F80) and CA rules (AUD-F82).

Self-contained: builds its own PKI, signs real Mode 1 messages over an
independently computed 72-octet attestation-input, and wraps the signatures
in CMS SignedData variants with a small DER encoder, then calls the public
verify_hardware_attestation(). Clock is fixed (REFERENCE_TIME_UNIX).
"""

import base64
import datetime
import hashlib
import struct
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from hw_attest_verify import verify_hardware_attestation
from hw_attest_verify.cms_signed_data_profile import (
  Mode1CmsProfileViolation,
  _extract_raw_issuer_name_element_from_certificate_der,
  _read_ber_children,
  decode_mode1_detached_signed_data_strictly,
)
from hw_attest_verify.signer_certificate_path_building_and_validation import (
  MAXIMUM_ISSUER_SIGNATURE_CHECKS_PER_PATH_SEARCH,
  build_and_validate_certificate_path_from_signer_to_trusted_root,
)

REFERENCE_TIME_UNIX = 1_790_000_000  # 2026-09-21T14:13:20Z
REFERENCE_TIME_UTC = datetime.datetime.fromtimestamp(REFERENCE_TIME_UNIX, tz=datetime.timezone.utc)


# --- DER encoding -------------------------------------------------------------

def der_tlv(tag: int, content: bytes) -> bytes:
  if len(content) < 0x80:
    return bytes([tag, len(content)]) + content
  length_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
  return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + content


def der_oid(dotted: str) -> bytes:
  arcs = [int(part) for part in dotted.split(".")]
  encoded = bytearray([40 * arcs[0] + arcs[1]])
  for arc in arcs[2:]:
    chunk = [arc & 0x7F]
    arc >>= 7
    while arc:
      chunk.append(0x80 | (arc & 0x7F))
      arc >>= 7
    encoded.extend(reversed(chunk))
  return der_tlv(0x06, bytes(encoded))


def der_int(value: int) -> bytes:
  return der_tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big", signed=True))


DER_NULL = b"\x05\x00"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SHA1 = "1.3.14.3.2.26"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
OID_ED25519 = "1.3.101.112"


def algorithm_identifier(oid: str, parameters: bytes = None) -> bytes:
  return der_tlv(0x30, der_oid(oid) + (parameters if parameters is not None else b""))


SHA256_ABSENT = algorithm_identifier(OID_SHA256)
SHA256_NULL = algorithm_identifier(OID_SHA256, DER_NULL)


def pss_parameters(salt_length=32, hash_algorithm=SHA256_NULL, include_trailer=None, field_order=None, duplicate_hash=False):
  fields = {
    0xA0: der_tlv(0xA0, hash_algorithm),
    0xA1: der_tlv(0xA1, algorithm_identifier(OID_MGF1, hash_algorithm)),
    0xA2: der_tlv(0xA2, der_int(salt_length)),
  }
  if include_trailer is not None:
    fields[0xA3] = der_tlv(0xA3, der_int(include_trailer))
  ordered = [fields[tag] for tag in (field_order or sorted(fields))]
  if duplicate_hash:
    ordered.insert(1, fields[0xA0])
  return der_tlv(0x30, b"".join(ordered))


SIGNATURE_ALGORITHM_BY_NAME = {
  "RS256": algorithm_identifier(OID_SHA256_WITH_RSA, DER_NULL),
  "ES256": algorithm_identifier(OID_ECDSA_WITH_SHA256),
  "PS256": algorithm_identifier(OID_RSASSA_PSS, pss_parameters()),
  "EdDSA": algorithm_identifier(OID_ED25519),
}


def build_signed_data(
  signature: bytes,
  certificates_in_set_order,
  signature_algorithm: bytes,
  sid_certificate=None,
  sid_subject_key_identifier: bytes = None,
  signer_digest_algorithm: bytes = SHA256_ABSENT,
  signed_data_digest_algorithms=(SHA256_ABSENT,),
  signer_info_version: int = None,
  signed_data_version: int = None,
  signed_data_version_der: bytes = None,
  include_signed_attributes=False,
  include_econtent: bytes = None,
  include_crls=False,
  include_unsigned_attributes=False,
  duplicate_signer_info=False,
  trailing_bytes=b"",
) -> bytes:
  if sid_subject_key_identifier is not None:
    sid = der_tlv(0x80, sid_subject_key_identifier)
    default_version = 3
  else:
    sid = der_tlv(0x30, sid_certificate.issuer.public_bytes() + der_int(sid_certificate.serial_number))
    default_version = 1
  signer_info_fields = der_int(signer_info_version or default_version) + sid + signer_digest_algorithm
  if include_signed_attributes:
    signer_info_fields += der_tlv(0xA0, der_tlv(0x30, der_oid("1.2.840.113549.1.9.3") + der_tlv(0x31, der_oid(OID_DATA))))
  signer_info_fields += signature_algorithm + der_tlv(0x04, signature)
  if include_unsigned_attributes:
    signer_info_fields += der_tlv(0xA1, der_tlv(0x30, der_oid("1.2.840.113549.1.9.6") + der_tlv(0x31, der_tlv(0x04, b"x"))))
  signer_info = der_tlv(0x30, signer_info_fields)
  encapsulated_content = der_oid(OID_DATA)
  if include_econtent is not None:
    encapsulated_content += der_tlv(0xA0, der_tlv(0x04, include_econtent))
  signed_data_fields = (
    (signed_data_version_der or der_int(signed_data_version or default_version))
    + der_tlv(0x31, b"".join(signed_data_digest_algorithms))
    + der_tlv(0x30, encapsulated_content)
  )
  if certificates_in_set_order:
    signed_data_fields += der_tlv(0xA0, b"".join(
      c.public_bytes(serialization.Encoding.DER) if isinstance(c, x509.Certificate) else c
      for c in certificates_in_set_order))
  if include_crls:
    signed_data_fields += der_tlv(0xA1, b"")
  signed_data_fields += der_tlv(0x31, signer_info + (signer_info if duplicate_signer_info else b""))
  return der_tlv(0x30, der_oid(OID_SIGNED_DATA) + der_tlv(0xA0, der_tlv(0x30, signed_data_fields))) + trailing_bytes


# --- PKI ----------------------------------------------------------------------

def name(common_name: str) -> x509.Name:
  return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"), x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def ca_basic_constraints(path_length=None):
  return x509.BasicConstraints(ca=True, path_length=path_length)


LEAF_BASIC_CONSTRAINTS = x509.BasicConstraints(ca=False, path_length=None)


def issue_certificate(
  subject_cn, subject_key, issuer_cn, issuer_key,
  basic_constraints=None, key_usage="ca", extra_extensions=(),
  not_before=None, not_after=None, serial_number=None,
):
  builder = (
    x509.CertificateBuilder()
    .subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
    .public_key(subject_key.public_key())
    .serial_number(serial_number or x509.random_serial_number())
    .not_valid_before(not_before or REFERENCE_TIME_UTC - datetime.timedelta(days=30))
    .not_valid_after(not_after or REFERENCE_TIME_UTC + datetime.timedelta(days=365))
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
  )
  if basic_constraints is not None:
    builder = builder.add_extension(basic_constraints, critical=True)
  if key_usage is not None:
    # "ca": keyCertSign+cRLSign; "leaf" / "ca_without_keycertsign": digitalSignature;
    # "key_agreement_only": keyAgreement (a key that must not sign messages).
    builder = builder.add_extension(x509.KeyUsage(
      digital_signature=key_usage in ("leaf", "ca_without_keycertsign"),
      content_commitment=False, key_encipherment=False, data_encipherment=False,
      key_agreement=key_usage == "key_agreement_only",
      key_cert_sign=key_usage == "ca", crl_sign=key_usage == "ca", encipher_only=False, decipher_only=False,
    ), critical=True)
  for extension_value, critical in extra_extensions:
    builder = builder.add_extension(extension_value, critical=critical)
  signing_hash = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
  return builder.sign(issuer_key, signing_hash)


def build_version_1_certificate(subject_cn, subject_key, issuer_cn, issuer_key) -> x509.Certificate:
  """A certificate WITHOUT the [0] version field and without extensions (X.509 v1)."""
  def utc_time(moment):
    return der_tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())
  tbs = der_tlv(0x30,
    der_int(x509.random_serial_number())
    + algorithm_identifier(OID_ECDSA_WITH_SHA256)
    + name(issuer_cn).public_bytes()
    + der_tlv(0x30, utc_time(REFERENCE_TIME_UTC - datetime.timedelta(days=30)) + utc_time(REFERENCE_TIME_UTC + datetime.timedelta(days=365)))
    + name(subject_cn).public_bytes()
    + subject_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
  signature = issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
  return x509.load_der_x509_certificate(der_tlv(0x30, tbs + algorithm_identifier(OID_ECDSA_WITH_SHA256) + der_tlv(0x03, b"\x00" + signature)))


class GeneratedPkiForMode1Tests:
  def __init__(self):
    self.root_key = ec.generate_private_key(ec.SECP256R1())
    self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
    self.ec_leaf_key = ec.generate_private_key(ec.SECP256R1())
    self.p384_leaf_key = ec.generate_private_key(ec.SECP384R1())
    self.rsa_leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    self.ed25519_leaf_key = ed25519.Ed25519PrivateKey.generate()
    self.unrelated_key = ec.generate_private_key(ec.SECP256R1())
    self.root = issue_certificate("Root", self.root_key, "Root", self.root_key, ca_basic_constraints(1))
    self.intermediate = issue_certificate("Intermediate", self.intermediate_key, "Root", self.root_key, ca_basic_constraints(0))
    self.ec_leaf = self.issue_leaf("EC Leaf", self.ec_leaf_key)
    self.p384_leaf = self.issue_leaf("P-384 Leaf", self.p384_leaf_key)
    self.rsa_leaf = self.issue_leaf("RSA Leaf", self.rsa_leaf_key)
    self.ed25519_leaf = self.issue_leaf("Ed25519 Leaf", self.ed25519_leaf_key)
    self.unrelated_root = issue_certificate("Unrelated", self.unrelated_key, "Unrelated", self.unrelated_key, ca_basic_constraints())

  def issue_leaf(self, common_name, key, issuer_cn="Intermediate", issuer_key=None, key_usage="leaf", extra_extensions=()):
    return issue_certificate(common_name, key, issuer_cn, issuer_key or self.intermediate_key,
                             LEAF_BASIC_CONSTRAINTS, key_usage, extra_extensions)

  def intermediate_variant(self, **overrides):
    arguments = dict(basic_constraints=ca_basic_constraints(0), key_usage="ca")
    arguments.update(overrides)
    return issue_certificate("Intermediate", self.intermediate_key, "Root", self.root_key, **arguments)


@pytest.fixture(scope="module")
def pki():
  return GeneratedPkiForMode1Tests()


# --- one Mode 1 message ---------------------------------------------------------

NINE_ALWAYS_COVERED_FIELDS = ["from", "to", "subject", "date", "message-id", "reply-to",
                              "mime-version", "content-type", "content-transfer-encoding"]
EMAIL_HEADERS = {
  "From": "agent@example.com", "To": "human@example.org", "Subject": "CMS profile test",
  "Date": "Mon, 21 Sep 2026 14:13:20 +0000", "Message-ID": "<cms-profile@example.com>",
  "MIME-Version": "1.0", "Content-Type": "text/plain; charset=us-ascii",
}
BODY = b"Mode 1 CMS profile test body.\r\n"


def header_value_without_chain(alg: str) -> str:
  bh = base64.urlsafe_b64encode(hashlib.sha256(BODY).digest()).rstrip(b"=").decode()
  return (f"v=1; typ=SFT; alg={alg}; h={':'.join(NINE_ALWAYS_COVERED_FIELDS)}; "
          f"bh={bh}; ts={REFERENCE_TIME_UNIX}; chain=")


def attestation_input_72_octets(alg: str) -> bytes:
  """Independent implementation of the draft's attestation-input for simple ASCII headers."""
  lowered = {k.lower(): v for k, v in EMAIL_HEADERS.items()}
  canonical = "".join(f"{field}:{lowered[field]}\r\n" for field in NINE_ALWAYS_COVERED_FIELDS if field in lowered)
  canonical += "hardware-attestation:" + header_value_without_chain(alg).replace(" ", "") + "\r\n"
  return (hashlib.sha256(canonical.encode()).digest() + hashlib.sha256(BODY).digest()
          + struct.pack(">Q", REFERENCE_TIME_UNIX))


def sign_message(alg: str, private_key, salt_length=32) -> bytes:
  data = attestation_input_72_octets(alg)
  if alg == "ES256":
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
  if alg == "RS256":
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
  if alg == "PS256":
    return private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length), hashes.SHA256())
  return private_key.sign(data)  # EdDSA


def verify_message(alg: str, cms_der: bytes, trusted_roots, allow_eddsa=False):
  return verify_hardware_attestation(
    header_value=header_value_without_chain(alg) + base64.b64encode(cms_der).decode(),
    email_headers=EMAIL_HEADERS, body=BODY,
    trusted_root_certificates=list(trusted_roots), reference_time_unix=REFERENCE_TIME_UNIX,
    allow_eddsa=allow_eddsa,
  )


def standard_es256_signed_data(pki, **overrides):
  arguments = dict(
    signature=sign_message("ES256", pki.ec_leaf_key),
    certificates_in_set_order=[pki.ec_leaf, pki.intermediate, pki.root],
    signature_algorithm=SIGNATURE_ALGORITHM_BY_NAME["ES256"],
    sid_certificate=pki.ec_leaf,
  )
  arguments.update(overrides)
  return build_signed_data(**arguments)


def assert_accepted(result):
  assert result.is_valid, result.failure_reasons


def assert_rejected_with(result, expected_reason_fragment: str):
  assert not result.is_valid
  assert any(expected_reason_fragment in reason for reason in result.failure_reasons), result.failure_reasons


# --- AUD-F78: strict CMS profile ---------------------------------------------------

class TestStrictCmsProfileAudF78:
  def test_conforming_es256_signed_data_is_accepted(self, pki):
    assert_accepted(verify_message("ES256", standard_es256_signed_data(pki), [pki.root]))

  @pytest.mark.parametrize("overrides, expected_reason_fragment", [
    (dict(include_signed_attributes=True), "signedAttrs MUST be absent"),
    (dict(include_econtent=b"x" * 72), "eContent MUST be omitted"),
    (dict(duplicate_signer_info=True), "exactly one SignerInfo is required, found 2"),
    (dict(trailing_bytes=b"\x00\x00"), "trailing bytes after ContentInfo"),
    (dict(certificates_in_set_order=[]), "certificates field MUST contain the signer certificate"),
    (dict(signer_digest_algorithm=algorithm_identifier(OID_SHA1)), "MUST identify SHA-256"),
    (dict(signed_data_digest_algorithms=(algorithm_identifier(OID_SHA1),)), "MUST identify SHA-256"),
    (dict(signed_data_digest_algorithms=()), "digestAlgorithms is empty"),
    (dict(signer_info_version=3), "do not match the signer identifier"),
    (dict(signed_data_version=3), "do not match the signer identifier"),
  ])
  def test_non_conforming_structure_is_rejected(self, pki, overrides, expected_reason_fragment):
    result = verify_message("ES256", standard_es256_signed_data(pki, **overrides), [pki.root])
    assert_rejected_with(result, expected_reason_fragment)

  def test_input_that_is_not_asn1_fails_closed(self, pki):
    assert_rejected_with(verify_message("ES256", b"not ASN.1 CMS at all", [pki.root]), "Version 1 profile")

  def test_unparseable_certificate_in_the_set_fails_closed(self, pki):
    garbage_certificate = der_tlv(0x30, der_int(1))
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf, garbage_certificate, pki.root]), [pki.root])
    assert_rejected_with(result, "certificate #1 in SignedData.certificates cannot be parsed")

  def test_optional_crls_and_unsigned_attributes_are_tolerated(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(
      pki, include_crls=True, include_unsigned_attributes=True), [pki.root])
    assert_accepted(result)

  def test_sha256_digest_with_null_parameters_is_accepted_per_rfc5754(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(
      pki, signer_digest_algorithm=SHA256_NULL, signed_data_digest_algorithms=(SHA256_NULL,)), [pki.root])
    assert_accepted(result)

  def test_signature_is_checked_only_with_the_certificate_the_sid_names(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(pki, sid_certificate=pki.intermediate), [pki.root])
    assert_rejected_with(result, "Signature verification failed with the SignerInfo signer certificate")

  def test_sid_naming_a_certificate_outside_the_set_is_rejected(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(pki, sid_certificate=pki.p384_leaf), [pki.root])
    assert_rejected_with(result, "the certificate named by SignerInfo.sid is not in the certificates field")

  def test_subject_key_identifier_sid_with_version_3_is_accepted(self, pki):
    subject_key_identifier = pki.ec_leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    result = verify_message("ES256", standard_es256_signed_data(
      pki, sid_certificate=None, sid_subject_key_identifier=subject_key_identifier), [pki.root])
    assert_accepted(result)

  def test_subject_key_identifier_sid_with_version_1_is_rejected(self, pki):
    subject_key_identifier = pki.ec_leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    result = verify_message("ES256", standard_es256_signed_data(
      pki, sid_certificate=None, sid_subject_key_identifier=subject_key_identifier,
      signer_info_version=1, signed_data_version=1), [pki.root])
    assert_rejected_with(result, "do not match the signer identifier")


class TestCmsAlgorithmMapping:
  def test_es256_signature_algorithm_with_null_parameters_is_rejected(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(
      pki, signature_algorithm=algorithm_identifier(OID_ECDSA_WITH_SHA256, DER_NULL)), [pki.root])
    assert_rejected_with(result, "ES256 requires ecdsa-with-SHA256 with parameters absent")

  def test_signature_algorithm_that_contradicts_alg_is_rejected(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(
      pki, signature_algorithm=SIGNATURE_ALGORITHM_BY_NAME["RS256"]), [pki.root])
    assert_rejected_with(result, "ES256 requires ecdsa-with-SHA256")

  def test_es256_with_a_p384_signer_key_is_rejected(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(
      pki, signature=sign_message("ES256", pki.p384_leaf_key),
      certificates_in_set_order=[pki.p384_leaf, pki.intermediate], sid_certificate=pki.p384_leaf), [pki.root])
    assert_rejected_with(result, "ES256 requires a P-256 signer key")

  def test_rs256_with_an_ec_signer_key_is_rejected(self, pki):
    result = verify_message("RS256", build_signed_data(
      sign_message("ES256", pki.ec_leaf_key), [pki.ec_leaf, pki.intermediate],
      SIGNATURE_ALGORITHM_BY_NAME["RS256"], sid_certificate=pki.ec_leaf), [pki.root])
    assert_rejected_with(result, "RS256 requires an RSA signer key")

  @pytest.mark.parametrize("rs256_signature_algorithm", [
    algorithm_identifier(OID_SHA256_WITH_RSA, DER_NULL),  # as generated
    algorithm_identifier(OID_SHA256_WITH_RSA),  # RFC 5754: absent parameters also accepted
    algorithm_identifier(OID_RSA_ENCRYPTION, DER_NULL),  # RFC 3370 s3.2 / OpenSSL (OWN-021)
  ])
  def test_rs256_signature_algorithm_forms_accepted_by_the_draft(self, pki, rs256_signature_algorithm):
    result = verify_message("RS256", build_signed_data(
      sign_message("RS256", pki.rsa_leaf_key), [pki.rsa_leaf, pki.intermediate],
      rs256_signature_algorithm, sid_certificate=pki.rsa_leaf), [pki.root])
    assert_accepted(result)

  @pytest.mark.parametrize("parameters, accepted", [
    (pss_parameters(), True),
    (pss_parameters(hash_algorithm=SHA256_ABSENT), True),  # RFC 4055: NULL and absent are equivalent
    (pss_parameters(include_trailer=1), True),  # RFC 4055: validators MUST accept an explicit trailerField 1
    (pss_parameters(include_trailer=2), False),
    (pss_parameters(salt_length=20), False),
    (pss_parameters(field_order=[0xA1, 0xA0, 0xA2]), False),
    (pss_parameters(duplicate_hash=True), False),
    (pss_parameters(hash_algorithm=algorithm_identifier(OID_SHA1, DER_NULL)), False),
    (der_tlv(0x30, b""), False),  # all defaults = SHA-1 / salt 20
    (None, False),
  ])
  def test_ps256_rsassa_pss_parameters(self, pki, parameters, accepted):
    result = verify_message("PS256", build_signed_data(
      sign_message("PS256", pki.rsa_leaf_key), [pki.rsa_leaf, pki.intermediate],
      algorithm_identifier(OID_RSASSA_PSS, parameters), sid_certificate=pki.rsa_leaf), [pki.root])
    if accepted:
      assert_accepted(result)
    else:
      assert_rejected_with(result, "PS256 requires id-RSASSA-PSS")


class TestPs256SaltLengthAudF79:
  @pytest.mark.parametrize("salt_length, accepted", [(32, True), (20, False), (0, False), (64, False)])
  def test_only_a_32_octet_salt_verifies(self, pki, salt_length, accepted):
    result = verify_message("PS256", build_signed_data(
      sign_message("PS256", pki.rsa_leaf_key, salt_length=salt_length), [pki.rsa_leaf, pki.intermediate],
      SIGNATURE_ALGORITHM_BY_NAME["PS256"], sid_certificate=pki.rsa_leaf), [pki.root])
    if accepted:
      assert_accepted(result)
    else:
      assert_rejected_with(result, "Signature verification failed")


class TestEdDsaNonStandardTestPath:
  @pytest.mark.parametrize("digest_oid, accepted", [
    (OID_SHA512, True),  # RFC 8419 s3.2
    (OID_ED25519, True),  # what both 1id SDKs emit (OWN-022)
    (OID_SHA256, False),
  ])
  def test_eddsa_digest_algorithms(self, pki, digest_oid, accepted):
    digest_algorithm = algorithm_identifier(digest_oid)
    result = verify_message("EdDSA", build_signed_data(
      sign_message("EdDSA", pki.ed25519_leaf_key), [pki.ed25519_leaf, pki.intermediate],
      SIGNATURE_ALGORITHM_BY_NAME["EdDSA"], sid_certificate=pki.ed25519_leaf,
      signer_digest_algorithm=digest_algorithm, signed_data_digest_algorithms=(digest_algorithm,),
    ), [pki.root], allow_eddsa=True)
    if accepted:
      assert_accepted(result)
    else:
      assert_rejected_with(result, "EdDSA requires digestAlgorithm id-sha512")

  def test_eddsa_is_rejected_without_the_testing_opt_in(self, pki):
    result = verify_message("EdDSA", build_signed_data(
      sign_message("EdDSA", pki.ed25519_leaf_key), [pki.ed25519_leaf, pki.intermediate],
      SIGNATURE_ALGORITHM_BY_NAME["EdDSA"], sid_certificate=pki.ed25519_leaf), [pki.root])
    assert_rejected_with(result, "EdDSA is not in the Version 1 CMS algorithm table")


# --- AUD-F80: path built from the signer, not from CertificateSet order -----------

class TestCertificatePathBuildingAudF80:
  @pytest.mark.parametrize("set_order", [
    ["leaf", "intermediate", "root"],
    ["root", "intermediate", "leaf"],
    ["intermediate", "leaf"],
    ["leaf", "intermediate"],
    ["unrelated", "leaf", "intermediate"],
  ])
  def test_any_certificate_set_order_validates(self, pki, set_order):
    certificates = {"leaf": pki.ec_leaf, "intermediate": pki.intermediate, "root": pki.root, "unrelated": pki.unrelated_root}
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[certificates[label] for label in set_order]), [pki.root])
    assert_accepted(result)

  def test_missing_intermediate_names_the_missing_issuer(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(pki, certificates_in_set_order=[pki.ec_leaf]), [pki.root])
    assert_rejected_with(result, "is named as the issuer 'CN=Intermediate,O=Test'")

  def test_untrusted_root_is_rejected(self, pki):
    result = verify_message("ES256", standard_es256_signed_data(pki), [pki.unrelated_root])
    assert not result.is_valid
    assert any("Certificate chain validation failed" in reason for reason in result.failure_reasons)

  def test_signer_key_pinned_as_trust_anchor_is_accepted(self, pki):
    assert_accepted(verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf]), [pki.ec_leaf]))

  def test_a_second_trust_store_copy_of_the_root_key_is_also_tried(self, pki):
    expired_copy_of_root = issue_certificate("Root", pki.root_key, "Root", pki.root_key, ca_basic_constraints(1),
                                             not_after=REFERENCE_TIME_UTC - datetime.timedelta(days=1))
    assert_accepted(verify_message("ES256", standard_es256_signed_data(pki), [expired_copy_of_root, pki.root]))


# --- AUD-F82: RFC 5280 CA rules -------------------------------------------------------

class TestCertificatePathCaRulesAudF82:
  @pytest.mark.parametrize("intermediate_overrides, expected_reason_fragment", [
    (dict(basic_constraints=None), "has no basicConstraints extension, so it is not a CA"),
    (dict(basic_constraints=LEAF_BASIC_CONSTRAINTS, key_usage="leaf"), "its basicConstraints cA is FALSE"),
    (dict(key_usage="ca_without_keycertsign"), "its KeyUsage lacks keyCertSign"),
    (dict(extra_extensions=[(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.59999.9.9"), DER_NULL), True)]),
     "carries a critical extension 1.3.6.1.4.1.59999.9.9"),
    (dict(not_after=REFERENCE_TIME_UTC - datetime.timedelta(seconds=1)), "has expired"),
    (dict(not_before=REFERENCE_TIME_UTC + datetime.timedelta(seconds=1)), "is not yet valid"),
  ])
  def test_intermediate_that_may_not_issue_is_rejected(self, pki, intermediate_overrides, expected_reason_fragment):
    bad_intermediate = pki.intermediate_variant(**intermediate_overrides)
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf, bad_intermediate, pki.root]), [pki.root])
    assert_rejected_with(result, expected_reason_fragment)

  def test_path_length_constraint_of_the_trust_anchor_is_honoured(self, pki):
    root_with_path_length_zero = issue_certificate("Root", pki.root_key, "Root", pki.root_key, ca_basic_constraints(0))
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf, pki.intermediate]), [root_with_path_length_zero])
    assert_rejected_with(result, "has pathLenConstraint 0 but 1 intermediate certificate(s) follow it")

  def test_bundled_look_alike_root_cannot_drop_the_trust_store_constraints(self, pki):
    root_with_path_length_zero = issue_certificate("Root", pki.root_key, "Root", pki.root_key, ca_basic_constraints(0))
    look_alike_root_without_path_length = issue_certificate("Root", pki.root_key, "Root", pki.root_key, ca_basic_constraints())
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf, pki.intermediate, look_alike_root_without_path_length]),
      [root_with_path_length_zero])
    assert_rejected_with(result, "has pathLenConstraint 0")

  def test_path_length_constraint_of_an_intermediate_is_honoured(self, pki):
    second_level_key = ec.generate_private_key(ec.SECP256R1())
    second_level_intermediate = issue_certificate("Second", second_level_key, "Intermediate", pki.intermediate_key, ca_basic_constraints())
    leaf_under_second_level = issue_certificate("Deep Leaf", pki.ec_leaf_key, "Second", second_level_key, LEAF_BASIC_CONSTRAINTS, "leaf")
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[leaf_under_second_level, second_level_intermediate, pki.intermediate],
      sid_certificate=leaf_under_second_level), [pki.root])
    assert_rejected_with(result, "'CN=Intermediate,O=Test' has pathLenConstraint 0 but 1 intermediate")

  def test_self_issued_intermediate_does_not_count_towards_path_length(self, pki):
    rollover_key = ec.generate_private_key(ec.SECP256R1())
    rollover_intermediate = issue_certificate("Intermediate", rollover_key, "Intermediate", pki.intermediate_key, ca_basic_constraints(0))
    leaf_under_rollover = issue_certificate("Rollover Leaf", pki.ec_leaf_key, "Intermediate", rollover_key, LEAF_BASIC_CONSTRAINTS, "leaf")
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[leaf_under_rollover, rollover_intermediate, pki.intermediate],
      sid_certificate=leaf_under_rollover), [pki.root])
    assert_accepted(result)

  def test_expired_trust_anchor_is_rejected(self, pki):
    expired_root = issue_certificate("Root", pki.root_key, "Root", pki.root_key, ca_basic_constraints(1),
                                     not_after=REFERENCE_TIME_UTC - datetime.timedelta(days=1))
    result = verify_message("ES256", standard_es256_signed_data(pki, certificates_in_set_order=[pki.ec_leaf, pki.intermediate]), [expired_root])
    assert_rejected_with(result, "'CN=Root,O=Test' has expired")

  def test_version_1_trust_anchor_without_extensions_is_accepted(self, pki):
    version_1_root = build_version_1_certificate("Root", pki.root_key, "Root", pki.root_key)
    assert version_1_root.version == x509.Version.v1
    assert_accepted(verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf, pki.intermediate]), [version_1_root]))

  def test_version_1_intermediate_is_rejected(self, pki):
    version_1_intermediate = build_version_1_certificate("Intermediate", pki.intermediate_key, "Root", pki.root_key)
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[pki.ec_leaf, version_1_intermediate]), [pki.root])
    assert_rejected_with(result, "has no basicConstraints extension, so it is not a CA")

  def test_signer_without_digital_signature_key_usage_is_rejected(self, pki):
    leaf_for_key_agreement_only = pki.issue_leaf("EC Leaf", pki.ec_leaf_key, key_usage="key_agreement_only")
    result = verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[leaf_for_key_agreement_only, pki.intermediate],
      sid_certificate=leaf_for_key_agreement_only), [pki.root])
    assert_rejected_with(result, "lacks digitalSignature keyUsage")

  def test_critical_subject_alternative_name_on_the_signer_is_recognised(self, pki):
    leaf_with_critical_san = pki.issue_leaf("EC Leaf", pki.ec_leaf_key, extra_extensions=[
      (x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:aid:example:test")]), True)])
    assert_accepted(verify_message("ES256", standard_es256_signed_data(
      pki, certificates_in_set_order=[leaf_with_critical_san, pki.intermediate],
      sid_certificate=leaf_with_critical_san), [pki.root]))

  def test_path_search_gives_up_after_its_work_limit_and_fails_closed(self, pki):
    # Same issuer name, wrong keys: each costs one signature check. With more
    # of them than the budget placed BEFORE the genuine intermediate, the
    # search must stop (fail closed) before ever reaching the genuine one.
    impostors_named_like_the_intermediate = [
      issue_certificate("Intermediate", ec.generate_private_key(ec.SECP256R1()), "Root", pki.root_key, ca_basic_constraints(0))
      for _ in range(MAXIMUM_ISSUER_SIGNATURE_CHECKS_PER_PATH_SEARCH)]
    started = time.monotonic()
    problem_when_genuine_comes_last = build_and_validate_certificate_path_from_signer_to_trusted_root(
      pki.ec_leaf, impostors_named_like_the_intermediate + [pki.intermediate], [pki.root], REFERENCE_TIME_UTC)
    assert problem_when_genuine_comes_last is not None
    assert time.monotonic() - started < 10
    assert build_and_validate_certificate_path_from_signer_to_trusted_root(
      pki.ec_leaf, [pki.intermediate] + impostors_named_like_the_intermediate, [pki.root], REFERENCE_TIME_UTC) is None


# --- helpers ------------------------------------------------------------------------

class TestStrictDerDecoding:
  def valid_signed_data(self, pki):
    return standard_es256_signed_data(pki)

  def test_valid_object_decodes(self, pki):
    decoded = decode_mode1_detached_signed_data_strictly(self.valid_signed_data(pki))
    assert len(decoded.certificate_der_list) == 3 and decoded.signer_serial_number == pki.ec_leaf.serial_number

  @pytest.mark.parametrize("mutation, expected_reason_fragment", [
    (lambda der: b"\x1f" + der[1:], "high-tag-number form"),
    (lambda der: der[:-1], "overruns its container"),
    (lambda der: der + b"\x00", "trailing bytes after ContentInfo"),
    # indefinite length but the end-of-contents octets are missing
    (lambda der: b"\x30\x80" + der[4:], "lacks its end-of-contents octets"),
    # indefinite length on the (primitive) ContentInfo.contentType OID
    (lambda der: der[:4] + b"\x06\x80" + der[6:], "indefinite length on a primitive encoding"),
  ])
  def test_malformed_ber_encodings_are_rejected(self, pki, mutation, expected_reason_fragment):
    with pytest.raises(Mode1CmsProfileViolation, match=expected_reason_fragment):
      decode_mode1_detached_signed_data_strictly(mutation(self.valid_signed_data(pki)))

  def test_non_minimal_definite_length_is_legal_ber_and_decodes(self, pki):
    # OWN-024 (Chris 2026-09-24): RFC 5652 CMS is BER, so a non-minimal
    # definite length is accepted; only the 72-octet input is signed.
    der = self.valid_signed_data(pki)
    assert der[1] == 0x82
    non_minimal = der[:1] + b"\x84" + len(der[4:]).to_bytes(4, "big") + der[4:]
    assert decode_mode1_detached_signed_data_strictly(non_minimal) == decode_mode1_detached_signed_data_strictly(der)

  def test_bouncycastle_shaped_indefinite_length_ber_decodes_like_the_der_original(self, pki):
    # BouncyCastle 1.78.1 CMSSignedData.getEncoded() makes ContentInfo, its
    # [0], SignedData and the certificates [0] indefinite-length (OWN-024
    # evidence); inner elements stay definite. Rebuild that shape from DER.
    der = self.valid_signed_data(pki)

    def indefinite_length_at_levels(data, start, end, depth, levels_to_convert):
      rebuilt = b""
      for tag, element_start, value_start, value_end, element_end in _read_ber_children(data, start, end):
        if tag & 0x20 and depth in levels_to_convert and (depth != 3 or tag == 0xA0):
          rebuilt += bytes([tag, 0x80]) + indefinite_length_at_levels(
            data, value_start, value_end, depth + 1, levels_to_convert) + b"\x00\x00"
        else:
          rebuilt += data[element_start:element_end]
      return rebuilt

    bouncycastle_shaped_ber = indefinite_length_at_levels(der, 0, len(der), 0, {0, 1, 2, 3})
    assert bouncycastle_shaped_ber[:2] == b"\x30\x80" and bouncycastle_shaped_ber.count(b"\x00\x00") >= 4
    assert decode_mode1_detached_signed_data_strictly(bouncycastle_shaped_ber) == decode_mode1_detached_signed_data_strictly(der)
    assert_accepted(verify_message("ES256", bouncycastle_shaped_ber, [pki.root]))

  def test_non_minimal_version_integer_is_rejected(self, pki):
    signed_data_with_version_encoded_as_00_01 = standard_es256_signed_data(pki, signed_data_version_der=b"\x02\x02\x00\x01")
    with pytest.raises(Mode1CmsProfileViolation, match="INTEGER is not minimally encoded"):
      decode_mode1_detached_signed_data_strictly(signed_data_with_version_encoded_as_00_01)

  def test_raw_issuer_extraction_matches_the_encoded_issuer(self, pki):
    for certificate in (pki.ec_leaf, build_version_1_certificate("V1", pki.ec_leaf_key, "Root", pki.root_key)):
      assert _extract_raw_issuer_name_element_from_certificate_der(
        certificate.public_bytes(serialization.Encoding.DER)) == certificate.issuer.public_bytes()


# --- differential check against cryptography's own PKIX verifier -------------------

class TestAgreementWithCryptographyBuiltInVerifier:
  """Guards the custom path validator: where both apply, the verdicts agree."""

  @pytest.mark.parametrize("intermediate_overrides, trusted_root_path_length, expected_valid", [
    (dict(), 1, True),
    (dict(basic_constraints=None), 1, False),
    (dict(basic_constraints=LEAF_BASIC_CONSTRAINTS, key_usage="leaf"), 1, False),
    (dict(key_usage="ca_without_keycertsign"), 1, False),
    (dict(extra_extensions=[(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.59999.9.9"), DER_NULL), True)]), 1, False),
    (dict(not_after=REFERENCE_TIME_UTC - datetime.timedelta(seconds=1)), 1, False),
    (dict(), 0, False),
  ])
  def test_same_verdict_as_cryptography_x509_verification(self, pki, intermediate_overrides, trusted_root_path_length, expected_valid):
    verification = pytest.importorskip("cryptography.x509.verification")
    if not hasattr(verification.PolicyBuilder, "build_client_verifier"):
      pytest.skip("cryptography too old for the client verifier")
    intermediate = pki.intermediate_variant(**intermediate_overrides)
    root = issue_certificate("Root", pki.root_key, "Root", pki.root_key, ca_basic_constraints(trusted_root_path_length))
    # The built-in (WebPKI-profile) client verifier also demands a
    # subjectAltName on the leaf, which RFC 5280 path validation does not;
    # 1id-issued leaves carry the agent URN there, so compare on such a leaf.
    leaf_with_agent_urn = pki.issue_leaf("EC Leaf", pki.ec_leaf_key, extra_extensions=[
      (x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:aid:example:test")]), False)])
    our_problem = build_and_validate_certificate_path_from_signer_to_trusted_root(
      leaf_with_agent_urn, [intermediate], [root], REFERENCE_TIME_UTC)
    try:
      verification.PolicyBuilder().store(verification.Store([root])).time(REFERENCE_TIME_UTC) \
        .build_client_verifier().verify(leaf_with_agent_urn, [intermediate])
      builtin_valid = True
    except verification.VerificationError:
      builtin_valid = False
    assert (our_problem is None) == builtin_valid == expected_valid, our_problem
