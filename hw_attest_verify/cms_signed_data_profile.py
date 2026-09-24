"""
Strict decoder for the Version 1 Mode 1 CMS SignedData profile.

Email draft (draft-drake-email-hardware-attestation), Hardware-Attestation
`chain` + "CMS Algorithm Mapping":
- ContentInfo(id-signedData) holding SignedData with encapContentInfo present,
  eContentType id-data and eContent omitted (detached 72-octet input);
- exactly one SignerInfo, signedAttrs absent;
- SignedData digestAlgorithms and SignerInfo digestAlgorithm identify SHA-256;
- SignerInfo signatureAlgorithm + parameters match the header `alg`, and the
  signer public key type matches too;
- the certificates field contains the signer certificate.

Every deviation raises Mode1CmsProfileViolation: the decoder fails closed
(AUD-F78). Encoding: BER as RFC 5652 permits -- definite lengths (minimal or
not) and indefinite lengths on constructed encodings, as BouncyCastle emits
by default (OWN-024, Chris 2026-09-24); no trailing bytes. Only the 72-octet
attestation-input is signed, so the container encoding carries no security
meaning. Certificates are loaded exactly as encoded (DER, as X.509 requires).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


class Mode1CmsProfileViolation(ValueError):
  """The CMS object in chain= does not match the Version 1 Mode 1 profile."""


_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_DATA = "1.2.840.113549.1.7.1"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SHA512 = "2.16.840.1.101.3.4.2.3"
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11"
_OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
_OID_MGF1 = "1.2.840.113549.1.1.8"
_OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
_OID_ED25519 = "1.3.101.112"

_DER_NULL = b"\x05\x00"
_REQUIRED_PS256_SALT_LENGTH_OCTETS = 32


@dataclass
class DecodedAlgorithmIdentifier:
  oid: str
  parameters_der: Optional[bytes]  # None = parameters absent


@dataclass
class StrictlyDecodedMode1SignedData:
  certificate_der_list: List[bytes] = field(default_factory=list)
  signed_data_digest_algorithms: List[DecodedAlgorithmIdentifier] = field(default_factory=list)
  signer_info_digest_algorithm: Optional[DecodedAlgorithmIdentifier] = None
  signer_info_signature_algorithm: Optional[DecodedAlgorithmIdentifier] = None
  signer_issuer_name_der: Optional[bytes] = None
  signer_serial_number: Optional[int] = None
  signer_subject_key_identifier: Optional[bytes] = None
  signature_bytes: bytes = b""


# --- strict BER reading (RFC 5652 permits BER; OWN-024) ------------------------

def _read_ber_element(data: bytes, offset: int, end: int) -> Tuple[int, int, int, int]:
  """Return (tag, value_start, value_end, element_end) of the BER element at
  offset. element_end differs from value_end only for an indefinite length,
  whose value is followed by the two end-of-contents octets."""
  if offset + 2 > end:
    raise Mode1CmsProfileViolation("truncated BER element")
  tag = data[offset]
  if tag == 0x00:
    raise Mode1CmsProfileViolation("unexpected end-of-contents octets")
  if tag & 0x1F == 0x1F:
    raise Mode1CmsProfileViolation("high-tag-number form is not used by this profile")
  first_length_octet = data[offset + 1]
  if first_length_octet == 0x80:
    if not tag & 0x20:
      raise Mode1CmsProfileViolation("indefinite length on a primitive encoding (X.690 s8.1.3.2)")
    value_start = offset + 2
    child_offset = value_start
    while True:
      if child_offset + 2 > end:
        raise Mode1CmsProfileViolation("indefinite-length element lacks its end-of-contents octets")
      if data[child_offset] == 0x00 and data[child_offset + 1] == 0x00:
        return tag, value_start, child_offset, child_offset + 2
      child_offset = _read_ber_element(data, child_offset, end)[3]
  if first_length_octet < 0x80:
    length = first_length_octet
    header_length = 2
  else:
    count = first_length_octet & 0x7F
    if count > 4 or offset + 2 + count > end:
      raise Mode1CmsProfileViolation("unsupported or truncated BER length")
    length = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
    header_length = 2 + count
  value_start = offset + header_length
  value_end = value_start + length
  if value_end > end:
    raise Mode1CmsProfileViolation("BER element overruns its container")
  return tag, value_start, value_end, value_end


def _read_ber_children(data: bytes, start: int, end: int) -> List[Tuple[int, int, int, int, int]]:
  """Return [(tag, element_start, value_start, value_end, element_end)] covering start..end exactly."""
  children = []
  offset = start
  while offset < end:
    tag, value_start, value_end, element_end = _read_ber_element(data, offset, end)
    children.append((tag, offset, value_start, value_end, element_end))
    offset = element_end
  return children


def _decode_der_oid(value: bytes) -> str:
  if not value or value[-1] & 0x80:
    raise Mode1CmsProfileViolation("malformed OBJECT IDENTIFIER")
  arcs: List[int] = []
  current = 0
  for octet in value:
    if current == 0 and octet == 0x80:
      raise Mode1CmsProfileViolation("non-minimal OBJECT IDENTIFIER arc")
    current = (current << 7) | (octet & 0x7F)
    if not octet & 0x80:
      arcs.append(current)
      current = 0
  first = arcs[0]
  prefix = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
  return ".".join(str(arc) for arc in prefix + arcs[1:])


def _expect(tag: int, expected_tag: int, what: str) -> None:
  if tag != expected_tag:
    raise Mode1CmsProfileViolation(f"{what}: expected tag 0x{expected_tag:02x}, found 0x{tag:02x}")


def _decode_algorithm_identifier(data: bytes, value_start: int, value_end: int, what: str) -> DecodedAlgorithmIdentifier:
  children = _read_ber_children(data, value_start, value_end)
  if not 1 <= len(children) <= 2:
    raise Mode1CmsProfileViolation(f"{what}: AlgorithmIdentifier must have an OID and at most one parameters element")
  _expect(children[0][0], 0x06, what + " algorithm")
  oid = _decode_der_oid(data[children[0][2]:children[0][3]])
  parameters_der = data[children[1][1]:children[1][4]] if len(children) == 2 else None
  return DecodedAlgorithmIdentifier(oid=oid, parameters_der=parameters_der)


def _decode_small_non_negative_integer(value: bytes, what: str) -> int:
  if not value or value[0] & 0x80:
    raise Mode1CmsProfileViolation(f"{what}: expected a non-negative INTEGER")
  # X.690 s8.3.2 (BER and DER): a leading 0x00 octet is only allowed before an octet
  # whose top bit is set; anything else is a non-minimal encoding.
  if len(value) > 1 and value[0] == 0x00 and not value[1] & 0x80:
    raise Mode1CmsProfileViolation(f"{what}: INTEGER is not minimally encoded (X.690 s8.3.2)")
  return int.from_bytes(value, "big")


# --- profile decoding --------------------------------------------------------

def decode_mode1_detached_signed_data_strictly(cms_der: bytes) -> StrictlyDecodedMode1SignedData:
  """Decode the chain= CMS object, enforcing the Version 1 profile structure."""
  decoded = StrictlyDecodedMode1SignedData()
  total_length = len(cms_der)

  content_info_tag, content_info_start, content_info_end, content_info_element_end = _read_ber_element(cms_der, 0, total_length)
  _expect(content_info_tag, 0x30, "ContentInfo")
  if content_info_element_end != total_length:
    raise Mode1CmsProfileViolation("trailing bytes after ContentInfo")
  content_info_children = _read_ber_children(cms_der, content_info_start, content_info_end)
  if len(content_info_children) != 2:
    raise Mode1CmsProfileViolation("ContentInfo must be contentType + [0] content")
  _expect(content_info_children[0][0], 0x06, "ContentInfo.contentType")
  if _decode_der_oid(cms_der[content_info_children[0][2]:content_info_children[0][3]]) != _OID_SIGNED_DATA:
    raise Mode1CmsProfileViolation("ContentInfo.contentType is not id-signedData")
  _expect(content_info_children[1][0], 0xA0, "ContentInfo.content")
  explicit_children = _read_ber_children(cms_der, content_info_children[1][2], content_info_children[1][3])
  if len(explicit_children) != 1:
    raise Mode1CmsProfileViolation("ContentInfo [0] must hold exactly one SignedData")
  _expect(explicit_children[0][0], 0x30, "SignedData")

  signed_data_children = _read_ber_children(cms_der, explicit_children[0][2], explicit_children[0][3])
  if len(signed_data_children) < 4:
    raise Mode1CmsProfileViolation("SignedData is missing required fields")
  version_tag, _, version_start, version_end, _ = signed_data_children[0]
  _expect(version_tag, 0x02, "SignedData.version")
  signed_data_version = _decode_small_non_negative_integer(cms_der[version_start:version_end], "SignedData.version")

  _expect(signed_data_children[1][0], 0x31, "SignedData.digestAlgorithms")
  for algorithm_tag, _, algorithm_start, algorithm_end, _ in _read_ber_children(cms_der, signed_data_children[1][2], signed_data_children[1][3]):
    _expect(algorithm_tag, 0x30, "SignedData.digestAlgorithms element")
    decoded.signed_data_digest_algorithms.append(
      _decode_algorithm_identifier(cms_der, algorithm_start, algorithm_end, "SignedData.digestAlgorithms"))
  if not decoded.signed_data_digest_algorithms:
    raise Mode1CmsProfileViolation("SignedData.digestAlgorithms is empty")

  _expect(signed_data_children[2][0], 0x30, "SignedData.encapContentInfo")
  encap_children = _read_ber_children(cms_der, signed_data_children[2][2], signed_data_children[2][3])
  if not encap_children:
    raise Mode1CmsProfileViolation("encapContentInfo is empty")
  _expect(encap_children[0][0], 0x06, "encapContentInfo.eContentType")
  if _decode_der_oid(cms_der[encap_children[0][2]:encap_children[0][3]]) != _OID_DATA:
    raise Mode1CmsProfileViolation("encapContentInfo.eContentType is not id-data")
  if len(encap_children) != 1:
    raise Mode1CmsProfileViolation("eContent MUST be omitted (detached attestation-input)")

  remaining_children = signed_data_children[3:]
  if remaining_children and remaining_children[0][0] == 0xA0:
    for certificate_tag, certificate_offset, _, _, certificate_end in _read_ber_children(cms_der, remaining_children[0][2], remaining_children[0][3]):
      if certificate_tag != 0x30:
        raise Mode1CmsProfileViolation("certificates may contain only X.509 certificates")
      decoded.certificate_der_list.append(cms_der[certificate_offset:certificate_end])
    remaining_children = remaining_children[1:]
  if remaining_children and remaining_children[0][0] == 0xA1:
    remaining_children = remaining_children[1:]  # crls: permitted by RFC 5652, not used
  if len(remaining_children) != 1:
    raise Mode1CmsProfileViolation("unexpected fields in SignedData")
  _expect(remaining_children[0][0], 0x31, "SignedData.signerInfos")
  if not decoded.certificate_der_list:
    raise Mode1CmsProfileViolation("certificates field MUST contain the signer certificate")

  signer_infos = _read_ber_children(cms_der, remaining_children[0][2], remaining_children[0][3])
  if len(signer_infos) != 1:
    raise Mode1CmsProfileViolation(f"exactly one SignerInfo is required, found {len(signer_infos)}")
  _expect(signer_infos[0][0], 0x30, "SignerInfo")
  signer_info_children = _read_ber_children(cms_der, signer_infos[0][2], signer_infos[0][3])
  if len(signer_info_children) < 5:
    raise Mode1CmsProfileViolation("SignerInfo is missing required fields")

  _expect(signer_info_children[0][0], 0x02, "SignerInfo.version")
  signer_info_version = _decode_small_non_negative_integer(
    cms_der[signer_info_children[0][2]:signer_info_children[0][3]], "SignerInfo.version")
  sid_tag, _, sid_start, sid_end, _ = signer_info_children[1]
  if sid_tag == 0x30:
    sid_children = _read_ber_children(cms_der, sid_start, sid_end)
    if len(sid_children) != 2 or sid_children[0][0] != 0x30 or sid_children[1][0] != 0x02:
      raise Mode1CmsProfileViolation("malformed issuerAndSerialNumber")
    decoded.signer_issuer_name_der = cms_der[sid_children[0][1]:sid_children[0][4]]
    # The serial is compared by VALUE with the certificate's own serial, which
    # CMS producers copy byte-for-byte; so no DER-minimality check here.
    decoded.signer_serial_number = int.from_bytes(cms_der[sid_children[1][2]:sid_children[1][3]], "big", signed=True)
    expected_versions = (1, 1)
  elif sid_tag == 0x80:
    decoded.signer_subject_key_identifier = cms_der[sid_start:sid_end]
    expected_versions = (3, 3)
  else:
    raise Mode1CmsProfileViolation("SignerInfo.sid must be issuerAndSerialNumber or subjectKeyIdentifier")
  if (signer_info_version, signed_data_version) != expected_versions:
    raise Mode1CmsProfileViolation(
      f"SignerInfo/SignedData versions {signer_info_version}/{signed_data_version} do not match the signer identifier (RFC 5652)")

  _expect(signer_info_children[2][0], 0x30, "SignerInfo.digestAlgorithm")
  decoded.signer_info_digest_algorithm = _decode_algorithm_identifier(
    cms_der, signer_info_children[2][2], signer_info_children[2][3], "SignerInfo.digestAlgorithm")
  field_index = 3
  if signer_info_children[field_index][0] == 0xA0:
    raise Mode1CmsProfileViolation("SignerInfo signedAttrs MUST be absent in version 1")
  _expect(signer_info_children[field_index][0], 0x30, "SignerInfo.signatureAlgorithm")
  decoded.signer_info_signature_algorithm = _decode_algorithm_identifier(
    cms_der, signer_info_children[field_index][2], signer_info_children[field_index][3], "SignerInfo.signatureAlgorithm")
  field_index += 1
  _expect(signer_info_children[field_index][0], 0x04, "SignerInfo.signature")
  decoded.signature_bytes = cms_der[signer_info_children[field_index][2]:signer_info_children[field_index][3]]
  if not decoded.signature_bytes:
    raise Mode1CmsProfileViolation("SignerInfo.signature is empty")
  field_index += 1
  if field_index < len(signer_info_children) and signer_info_children[field_index][0] == 0xA1:
    field_index += 1  # unsignedAttrs: permitted by RFC 5652, not interpreted
  if field_index != len(signer_info_children):
    raise Mode1CmsProfileViolation("unexpected fields in SignerInfo")
  return decoded


# --- algorithm mapping -------------------------------------------------------

def _is_sha256_algorithm_identifier(algorithm: DecodedAlgorithmIdentifier) -> bool:
  """RFC 5754: SHA-256 parameters absent (generated) or NULL (accepted)."""
  return algorithm.oid == _OID_SHA256 and algorithm.parameters_der in (None, _DER_NULL)


def _pss_parameters_are_the_ps256_profile(parameters_der: Optional[bytes]) -> bool:
  """RSASSA-PSS-params (RFC 4055): SHA-256, MGF1-SHA-256, salt 32, trailerField 1."""
  if not parameters_der:
    return False
  try:
    tag, start, end, element_end = _read_ber_element(parameters_der, 0, len(parameters_der))
    if tag != 0x30 or element_end != len(parameters_der):
      return False
    parameter_children = _read_ber_children(parameters_der, start, end)
    # RSASSA-PSS-params is a SEQUENCE: each of [0]..[3] at most once, in
    # ascending order. Reject duplicates/reordering before the dict below
    # could silently merge them.
    parameter_tags_in_encoded_order = [child_tag for child_tag, _, _, _, _ in parameter_children]
    if parameter_tags_in_encoded_order != sorted(set(parameter_tags_in_encoded_order)):
      return False
    fields = {child_tag: (child_start, child_end) for child_tag, _, child_start, child_end, _ in parameter_children}
    if set(fields) - {0xA0, 0xA1, 0xA2, 0xA3} or not {0xA0, 0xA1, 0xA2} <= set(fields):
      return False  # the SHA-1 / salt 20 defaults are not the PS256 profile

    def single_child(explicit_tag):
      children = _read_ber_children(parameters_der, *fields[explicit_tag])
      if len(children) != 1:
        raise Mode1CmsProfileViolation("malformed RSASSA-PSS-params")
      return children[0]

    hash_tag, _, hash_start, hash_end, _ = single_child(0xA0)
    if hash_tag != 0x30 or not _is_sha256_algorithm_identifier(
        _decode_algorithm_identifier(parameters_der, hash_start, hash_end, "PSS hashAlgorithm")):
      return False
    mgf_tag, _, mgf_start, mgf_end, _ = single_child(0xA1)
    if mgf_tag != 0x30:
      return False
    mask_generation = _decode_algorithm_identifier(parameters_der, mgf_start, mgf_end, "PSS maskGenAlgorithm")
    if mask_generation.oid != _OID_MGF1 or mask_generation.parameters_der is None:
      return False
    mgf_hash_tag, mgf_hash_start, mgf_hash_end, _ = _read_ber_element(
      mask_generation.parameters_der, 0, len(mask_generation.parameters_der))
    if mgf_hash_tag != 0x30 or not _is_sha256_algorithm_identifier(
        _decode_algorithm_identifier(mask_generation.parameters_der, mgf_hash_start, mgf_hash_end, "MGF1 hash")):
      return False
    salt_tag, _, salt_start, salt_end, _ = single_child(0xA2)
    if salt_tag != 0x02 or _decode_small_non_negative_integer(parameters_der[salt_start:salt_end], "PSS saltLength") != _REQUIRED_PS256_SALT_LENGTH_OCTETS:
      return False
    if 0xA3 in fields:
      trailer_tag, _, trailer_start, trailer_end, _ = single_child(0xA3)
      if trailer_tag != 0x02 or _decode_small_non_negative_integer(parameters_der[trailer_start:trailer_end], "PSS trailerField") != 1:
        return False
    return True
  except Mode1CmsProfileViolation:
    return False


def check_cms_algorithms_match_header_alg_and_signer_key(
  decoded: StrictlyDecodedMode1SignedData,
  header_alg: str,
  signer_public_key,
  allow_eddsa: bool = False,
) -> None:
  """Email draft "CMS Algorithm Mapping": reject any mismatch between alg,
  digest algorithms, signatureAlgorithm, its parameters and the key type."""
  signature_algorithm = decoded.signer_info_signature_algorithm
  if header_alg == "EdDSA" and allow_eddsa:
    # Non-standard testing path (not in the Version 1 table).
    if signature_algorithm.oid != _OID_ED25519 or signature_algorithm.parameters_der is not None:
      raise Mode1CmsProfileViolation("EdDSA requires the Ed25519 signatureAlgorithm with parameters absent")
    if not isinstance(signer_public_key, ed25519.Ed25519PublicKey):
      raise Mode1CmsProfileViolation("EdDSA requires an Ed25519 signer key")
    # RFC 8419 s3.2 (no signed attributes): the Ed25519 digestAlgorithm MUST be
    # id-sha512 with parameters absent. Both 1id SDKs emit id-Ed25519 there
    # instead (OWN-022); this non-standard path tolerates that, nothing else.
    eddsa_digest_algorithms = decoded.signed_data_digest_algorithms + [decoded.signer_info_digest_algorithm]
    if not all(algorithm.oid in (_OID_SHA512, _OID_ED25519) and algorithm.parameters_der is None
               for algorithm in eddsa_digest_algorithms):
      raise Mode1CmsProfileViolation("EdDSA requires digestAlgorithm id-sha512 (RFC 8419) with parameters absent")
    return

  all_digest_algorithms = decoded.signed_data_digest_algorithms + [decoded.signer_info_digest_algorithm]
  if not all(_is_sha256_algorithm_identifier(algorithm) for algorithm in all_digest_algorithms):
    raise Mode1CmsProfileViolation("SignedData digestAlgorithms and SignerInfo digestAlgorithm MUST identify SHA-256")

  if header_alg == "RS256":
    # sha256WithRSAEncryption as generated; rsaEncryption also accepted
    # (RFC 5754 adopts RFC 3370 s3.2; email draft RS256 row, OWN-021).
    if signature_algorithm.oid not in (_OID_SHA256_WITH_RSA_ENCRYPTION, _OID_RSA_ENCRYPTION) \
        or signature_algorithm.parameters_der not in (None, _DER_NULL):
      raise Mode1CmsProfileViolation("RS256 requires sha256WithRSAEncryption (or rsaEncryption) with NULL or absent parameters")
    if not isinstance(signer_public_key, rsa.RSAPublicKey):
      raise Mode1CmsProfileViolation("RS256 requires an RSA signer key")
  elif header_alg == "ES256":
    if signature_algorithm.oid != _OID_ECDSA_WITH_SHA256 or signature_algorithm.parameters_der is not None:
      raise Mode1CmsProfileViolation("ES256 requires ecdsa-with-SHA256 with parameters absent")
    if not isinstance(signer_public_key, ec.EllipticCurvePublicKey) or not isinstance(signer_public_key.curve, ec.SECP256R1):
      raise Mode1CmsProfileViolation("ES256 requires a P-256 signer key")
  elif header_alg == "PS256":
    if signature_algorithm.oid != _OID_RSASSA_PSS or not _pss_parameters_are_the_ps256_profile(signature_algorithm.parameters_der):
      raise Mode1CmsProfileViolation("PS256 requires id-RSASSA-PSS with SHA-256, MGF1-SHA-256, salt 32, trailerField 1")
    if not isinstance(signer_public_key, rsa.RSAPublicKey):
      raise Mode1CmsProfileViolation("PS256 requires an RSA signer key")
  else:
    raise Mode1CmsProfileViolation(f"alg {header_alg!r} is not in the Version 1 CMS algorithm table")


# --- signer certificate ------------------------------------------------------

def load_every_certificate_in_signed_data_failing_closed(
  decoded: StrictlyDecodedMode1SignedData,
) -> List[x509.Certificate]:
  """Parse every certificate of the certificates field, in encoded order.

  A certificate that cannot be parsed makes the CMS object unusable (AUD-F78:
  fail closed) instead of being silently skipped as the old helper did.
  """
  certificates = []
  for certificate_index, certificate_der in enumerate(decoded.certificate_der_list):
    try:
      certificates.append(x509.load_der_x509_certificate(certificate_der))
    except ValueError as certificate_parse_error:
      raise Mode1CmsProfileViolation(
        f"certificate #{certificate_index} in SignedData.certificates cannot be parsed: {certificate_parse_error}")
  return certificates


def _extract_raw_issuer_name_element_from_certificate_der(certificate_der: bytes) -> Optional[bytes]:
  """Return the issuer Name exactly as encoded in the TBSCertificate, or None
  when the certificate is not strict DER (callers then rely on re-encoding)."""
  try:
    _, certificate_value_start, certificate_value_end, _ = _read_ber_element(certificate_der, 0, len(certificate_der))
    _, _, tbs_value_start, tbs_value_end, _ = _read_ber_children(certificate_der, certificate_value_start, certificate_value_end)[0]
    tbs_children = _read_ber_children(certificate_der, tbs_value_start, tbs_value_end)
    issuer_field_index = 3 if tbs_children[0][0] == 0xA0 else 2  # after [0] version?, serialNumber, signature
    issuer_tag, issuer_element_start, _, _, issuer_element_end = tbs_children[issuer_field_index]
    return certificate_der[issuer_element_start:issuer_element_end] if issuer_tag == 0x30 else None
  except (Mode1CmsProfileViolation, IndexError):
    return None


def find_signer_certificate_named_by_signer_info(
  decoded: StrictlyDecodedMode1SignedData,
  certificates: List[x509.Certificate],
) -> x509.Certificate:
  """Return the certificate the SignerInfo sid names (RFC 5652 s5.3).

  `certificates` must be load_every_certificate_in_signed_data_failing_closed(decoded)
  (same order as decoded.certificate_der_list). The issuerAndSerialNumber
  issuer is matched against the certificate's raw issuer bytes (what Node and
  OpenSSL copy) or its re-encoding (what the Python SDK emits).
  """
  if len(certificates) != len(decoded.certificate_der_list):
    raise ValueError("certificates must be parsed from decoded.certificate_der_list, in order")
  for certificate, certificate_der in zip(certificates, decoded.certificate_der_list):
    if decoded.signer_subject_key_identifier is not None:
      try:
        try:
          subject_key_identifier = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
          subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(certificate.public_key()).digest
      except (ValueError, UnsupportedAlgorithm):
        continue  # extensions or key unreadable: this certificate cannot be the one the key identifier names
      if subject_key_identifier == decoded.signer_subject_key_identifier:
        return certificate
    elif certificate.serial_number == decoded.signer_serial_number and decoded.signer_issuer_name_der in (
        _extract_raw_issuer_name_element_from_certificate_der(certificate_der), certificate.issuer.public_bytes()):
      return certificate
  raise Mode1CmsProfileViolation("the certificate named by SignerInfo.sid is not in the certificates field")
