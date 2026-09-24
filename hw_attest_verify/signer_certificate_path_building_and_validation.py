"""
Certificate path building and validation for Mode 1, starting from the CMS
signer certificate (AUD-F80, AUD-F82).

Email draft (draft-drake-email-hardware-attestation) "Verification Algorithm"
validates the signer key's certificate evidence under the verifier's
accepted-root policy. The SignedData certificates field is a SET: its encoding
order means nothing (RFC 5652), so the path is BUILT from the signer
certificate by issuer name + signature, never by position (AUD-F80).

Rules (a subset of RFC 5280 s6.1, enough for the Mode 1 evidence we accept):
- every certificate in the path is inside its validity period at the
  validation time;
- every intermediate (issuing) certificate has basicConstraints with cA TRUE
  (s6.1.4 k), keyCertSign when KeyUsage is present (n), and no
  pathLenConstraint is exceeded (l, m; self-issued certificates are not
  counted) (AUD-F82);
- a CRITICAL extension this module does not recognise rejects the path (o);
- the signer certificate, when it carries KeyUsage, asserts digitalSignature.

Trust anchors are identified by public key (SubjectPublicKeyInfo), as the
verifier always did. The final hop is always checked against the TRUST STORE
copy of the anchor, so a bundled look-alike "root" carrying the anchor key
cannot drop the anchor's own constraints. Constraints present in an anchor are
honoured; a missing basicConstraints on an anchor is tolerated (the anchor is
trusted by configuration, which also covers old version 1 roots).

Not processed, so a CRITICAL instance rejects the path: name constraints,
policy constraints, policy mappings, inhibitAnyPolicy. Revocation is not
checked.
"""

from __future__ import annotations

import datetime
import functools
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

MAXIMUM_CERTIFICATES_IN_ONE_PATH_INCLUDING_SIGNER_AND_TRUST_ANCHOR = 8
MAXIMUM_ISSUER_SIGNATURE_CHECKS_PER_PATH_SEARCH = 64

# Extensions whose criticality this module can honour. Mode 1 defines no
# extended key usage and no certificate policy, so those two are recognised
# without imposing a restriction.
_EXTENSION_OIDS_RECOGNISED_BY_THIS_PATH_VALIDATOR = frozenset({
  ExtensionOID.BASIC_CONSTRAINTS,
  ExtensionOID.KEY_USAGE,
  ExtensionOID.EXTENDED_KEY_USAGE,
  ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
  ExtensionOID.ISSUER_ALTERNATIVE_NAME,
  ExtensionOID.SUBJECT_KEY_IDENTIFIER,
  ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
  ExtensionOID.CERTIFICATE_POLICIES,
  ExtensionOID.CRL_DISTRIBUTION_POINTS,
  ExtensionOID.FRESHEST_CRL,
  ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
  ExtensionOID.SUBJECT_INFORMATION_ACCESS,
})


def _subject_public_key_info_der_or_none(certificate: x509.Certificate) -> Optional[bytes]:
  try:
    return certificate.public_key().public_bytes(
      serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
  except (ValueError, UnsupportedAlgorithm):
    return None


def _subject_name_or_none(certificate: x509.Certificate) -> Optional[x509.Name]:
  try:
    return certificate.subject
  except ValueError:
    return None


def _describe_certificate_for_failure_reason(certificate: x509.Certificate) -> str:
  return f"'{certificate.subject.rfc4514_string()}'"


def _extension_value_or_none(certificate: x509.Certificate, extension_class):
  """Return the parsed extension value, None when absent (ValueError when unparseable)."""
  try:
    return certificate.extensions.get_extension_for_class(extension_class).value
  except x509.ExtensionNotFound:
    return None


def _validity_and_critical_extension_problem_or_none(
  certificate: x509.Certificate,
  validation_time_utc: datetime.datetime,
) -> Optional[str]:
  """Checks applied to EVERY certificate of the path, anchor included."""
  described = _describe_certificate_for_failure_reason(certificate)
  if certificate.not_valid_before_utc > validation_time_utc:
    return f"certificate {described} is not yet valid (notBefore={certificate.not_valid_before_utc})"
  if certificate.not_valid_after_utc < validation_time_utc:
    return f"certificate {described} has expired (notAfter={certificate.not_valid_after_utc})"
  try:
    extensions = certificate.extensions
  except ValueError as extension_parse_error:
    return f"certificate {described} has extensions that cannot be parsed: {extension_parse_error}"
  for extension in extensions:
    if extension.critical and extension.oid not in _EXTENSION_OIDS_RECOGNISED_BY_THIS_PATH_VALIDATOR:
      return (f"certificate {described} carries a critical extension {extension.oid.dotted_string} "
              f"that this verifier does not process (RFC 5280 s6.1.4 (o))")
  return None


def _issuing_certificate_problem_or_none(
  issuing_certificate: x509.Certificate,
  count_of_non_self_issued_intermediates_below: int,
  issuing_certificate_is_trust_anchor: bool,
) -> Optional[str]:
  """RFC 5280 s6.1.4 (k) (l)/(m) (n) for a certificate that signed another one."""
  described = _describe_certificate_for_failure_reason(issuing_certificate)
  basic_constraints = _extension_value_or_none(issuing_certificate, x509.BasicConstraints)
  if basic_constraints is None:
    if not issuing_certificate_is_trust_anchor:
      return (f"certificate {described} issued another certificate but has no basicConstraints "
              f"extension, so it is not a CA (RFC 5280 s6.1.4 (k))")
  else:
    if not basic_constraints.ca:
      return f"certificate {described} issued another certificate but its basicConstraints cA is FALSE"
    if (basic_constraints.path_length is not None
        and count_of_non_self_issued_intermediates_below > basic_constraints.path_length):
      return (f"certificate {described} has pathLenConstraint {basic_constraints.path_length} but "
              f"{count_of_non_self_issued_intermediates_below} intermediate certificate(s) follow it")
  key_usage = _extension_value_or_none(issuing_certificate, x509.KeyUsage)
  if key_usage is not None and not key_usage.key_cert_sign:
    return (f"certificate {described} issued another certificate but its KeyUsage lacks "
            f"keyCertSign (RFC 5280 s6.1.4 (n))")
  return None


def _signer_certificate_key_usage_problem_or_none(signer_certificate: x509.Certificate) -> Optional[str]:
  key_usage = _extension_value_or_none(signer_certificate, x509.KeyUsage)
  if key_usage is not None and not key_usage.digital_signature:
    return f"signer certificate {_describe_certificate_for_failure_reason(signer_certificate)} lacks digitalSignature keyUsage"
  return None


def _certificate_is_self_issued(certificate: x509.Certificate) -> bool:
  return certificate.subject == certificate.issuer


@functools.lru_cache(maxsize=8)
def _index_trust_anchors_by_key_and_by_subject_name(
  trusted_root_certificates: Tuple[x509.Certificate, ...],
) -> Tuple[Dict[bytes, List[x509.Certificate]], Dict[x509.Name, List[x509.Certificate]]]:
  """Index a trust store by key and by subject name; cached per distinct store.

  The MailPal trust store holds ~2,000 certificates and is the same on every
  message, while cryptography builds a new Name object on every .subject
  access; indexing per message (or scanning per path step) made verification
  several times slower. Every certificate is kept, since a store may hold two
  certificates for one key (e.g. a re-issued root). The returned dicts are
  shared between calls: read only.
  """
  trust_anchors_by_subject_public_key_info: Dict[bytes, List[x509.Certificate]] = {}
  trust_anchors_by_subject_name: Dict[x509.Name, List[x509.Certificate]] = {}
  for trusted_root_certificate in trusted_root_certificates:
    trusted_root_spki = _subject_public_key_info_der_or_none(trusted_root_certificate)
    trusted_root_subject_name = _subject_name_or_none(trusted_root_certificate)
    if trusted_root_spki is not None and trusted_root_subject_name is not None:
      trust_anchors_by_subject_public_key_info.setdefault(trusted_root_spki, []).append(trusted_root_certificate)
      trust_anchors_by_subject_name.setdefault(trusted_root_subject_name, []).append(trusted_root_certificate)
  return trust_anchors_by_subject_public_key_info, trust_anchors_by_subject_name


def build_and_validate_certificate_path_from_signer_to_trusted_root(
  signer_certificate: x509.Certificate,
  other_certificates_from_signed_data: List[x509.Certificate],
  trusted_root_certificates: List[x509.Certificate],
  validation_time_utc: datetime.datetime,
) -> Optional[str]:
  """Return None if a valid path exists from the signer to a trusted root,
  otherwise the reason from the search branch that got furthest.

  Any error while reading a certificate fails closed (it is a reason, never
  a pass).
  """
  trust_anchors_by_subject_public_key_info, trust_anchors_by_subject_name = (
    _index_trust_anchors_by_key_and_by_subject_name(tuple(trusted_root_certificates)))
  if not trust_anchors_by_subject_public_key_info:
    return "no usable trusted root certificate was supplied"

  # Bundled copies of an anchor are never used: the trust store copy is.
  candidate_intermediate_certificates = [
    certificate for certificate in other_certificates_from_signed_data
    if _subject_public_key_info_der_or_none(certificate) not in trust_anchors_by_subject_public_key_info
  ]
  furthest_problem: List[Tuple[int, str]] = []  # [(path length reached, reason)] -- keeps the first deepest
  issuer_signature_checks_performed = [0]

  def remember_problem(path_length_reached: int, reason: str) -> None:
    if not furthest_problem or path_length_reached > furthest_problem[0][0]:
      furthest_problem[:] = [(path_length_reached, reason)]

  def count_non_self_issued_intermediates(path_below_issuer: List[x509.Certificate]) -> int:
    """Intermediates between an issuer and the signer (path_below_issuer[0] is the signer)."""
    return sum(1 for certificate in path_below_issuer[1:] if not _certificate_is_self_issued(certificate))

  def trust_anchor_completes_path(path_below_trust_anchor: List[x509.Certificate], trust_anchor: x509.Certificate) -> bool:
    """path_below_trust_anchor = [signer, intermediates...] whose top the anchor
    issued; empty when the signer key itself is the anchor (pinned key)."""
    problem = _validity_and_critical_extension_problem_or_none(trust_anchor, validation_time_utc)
    if problem is None and path_below_trust_anchor:
      problem = _issuing_certificate_problem_or_none(
        trust_anchor, count_non_self_issued_intermediates(path_below_trust_anchor),
        issuing_certificate_is_trust_anchor=True)
    if problem is None and not path_below_trust_anchor:
      problem = _signer_certificate_key_usage_problem_or_none(trust_anchor)
    if problem is not None:
      remember_problem(len(path_below_trust_anchor) + 1, problem)
      return False
    return True

  def search_issuers_of_last_certificate(path_from_signer: List[x509.Certificate]) -> bool:
    certificate_needing_issuer = path_from_signer[-1]
    if len(path_from_signer) >= MAXIMUM_CERTIFICATES_IN_ONE_PATH_INCLUDING_SIGNER_AND_TRUST_ANCHOR:
      remember_problem(len(path_from_signer), "certificate path is longer than this verifier accepts")
      return False
    path_certificate_der = {certificate.public_bytes(serialization.Encoding.DER) for certificate in path_from_signer}
    issuer_name_needed = certificate_needing_issuer.issuer
    candidates: List[Tuple[x509.Certificate, bool]] = [
      (trust_anchor, True) for trust_anchor in trust_anchors_by_subject_name.get(issuer_name_needed, [])
    ] + [
      (certificate, False) for certificate in candidate_intermediate_certificates
      if certificate.subject == issuer_name_needed
      and certificate.public_bytes(serialization.Encoding.DER) not in path_certificate_der
    ]
    issuer_found_by_name = bool(candidates)
    for candidate_issuer, candidate_is_trust_anchor in candidates:
      if issuer_signature_checks_performed[0] >= MAXIMUM_ISSUER_SIGNATURE_CHECKS_PER_PATH_SEARCH:
        remember_problem(len(path_from_signer), "certificate path search exceeded its work limit")
        return False
      issuer_signature_checks_performed[0] += 1
      try:
        certificate_needing_issuer.verify_directly_issued_by(candidate_issuer)
      except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as signature_error:
        remember_problem(len(path_from_signer), (
          f"certificate {_describe_certificate_for_failure_reason(certificate_needing_issuer)} does not verify under "
          f"the key of {_describe_certificate_for_failure_reason(candidate_issuer)}: "
          f"{type(signature_error).__name__} {signature_error}".rstrip()))
        continue
      if candidate_is_trust_anchor:
        if trust_anchor_completes_path(path_from_signer, candidate_issuer):
          return True
        continue
      problem = (_validity_and_critical_extension_problem_or_none(candidate_issuer, validation_time_utc)
                 or _issuing_certificate_problem_or_none(
                   candidate_issuer, count_non_self_issued_intermediates(path_from_signer),
                   issuing_certificate_is_trust_anchor=False))
      if problem is not None:
        remember_problem(len(path_from_signer) + 1, problem)
        continue
      if search_issuers_of_last_certificate(path_from_signer + [candidate_issuer]):
        return True
    if not issuer_found_by_name:
      remember_problem(len(path_from_signer), (
        f"no certificate in SignedData or the trust store is named as the issuer "
        f"'{certificate_needing_issuer.issuer.rfc4514_string()}' of "
        f"{_describe_certificate_for_failure_reason(certificate_needing_issuer)}"))
    return False

  try:
    signer_problem = (_validity_and_critical_extension_problem_or_none(signer_certificate, validation_time_utc)
                      or _signer_certificate_key_usage_problem_or_none(signer_certificate))
    if signer_problem is not None:
      return signer_problem
    signer_subject_public_key_info = _subject_public_key_info_der_or_none(signer_certificate)
    if signer_subject_public_key_info in trust_anchors_by_subject_public_key_info:
      # The signer key itself is a trusted root (pinned key): a one-certificate
      # path, judged on the trust store copy.
      for pinned_trust_anchor in trust_anchors_by_subject_public_key_info[signer_subject_public_key_info]:
        if trust_anchor_completes_path([], pinned_trust_anchor):
          return None
    elif search_issuers_of_last_certificate([signer_certificate]):
      return None
  except ValueError as certificate_read_error:
    return f"a certificate in the path cannot be read: {certificate_read_error}"
  return furthest_problem[0][1] if furthest_problem else "no path to a trusted root certificate"
