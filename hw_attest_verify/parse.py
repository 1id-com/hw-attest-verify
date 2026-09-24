"""
Parse Hardware-Attestation and Hardware-Trust-Proof header values.

RFC: draft-drake-email-hardware-attestation-00, Section 5
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Email draft: both modes always cover these nine fields, in this order for
# Mode 2 (a listed field that is absent protects against its later addition).
ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER = [
  "from", "to", "subject", "date", "message-id",
  "reply-to", "mime-version", "content-type", "content-transfer-encoding",
]
# Fields that must occur at most once for verification to be meaningful.
SINGLETON_HEADER_FIELD_NAMES_FOR_VERIFICATION = set(ALWAYS_COVERED_HEADER_FIELD_NAMES_IN_ORDER) | {
  "hardware-attestation", "hardware-trust-proof",
}


def find_duplicate_singleton_header_field_names(ordered_header_pairs):
  """Names of singleton fields occurring more than once (permerror)."""
  counts = {}
  for name, _value in ordered_header_pairs or []:
    lowered = name.strip().lower()
    counts[lowered] = counts.get(lowered, 0) + 1
  return sorted(n for n, c in counts.items() if c > 1 and n in SINGLETON_HEADER_FIELD_NAMES_FOR_VERIFICATION)


_RFC_TYP_TO_TRUST_TIER = {
  "TPM": "sovereign",
  "PIV": "portable",
  "ENC": "enclave",
  "VRT": "virtual",
  "SFT": "declared",
}


@dataclass
class ParsedHardwareAttestationHeader:
  """Parsed parameters from a Hardware-Attestation header value."""
  version: int = 0
  typ: str = ""
  trust_tier: str = ""
  alg: str = ""
  signed_header_names: List[str] = field(default_factory=list)
  bh: str = ""
  ts: int = 0
  chain_base64: str = ""
  aid: Optional[str] = None
  bind: Optional[str] = None
  raw_parameters: Dict[str, str] = field(default_factory=dict)
  raw_header_value_with_original_tag_order: str = ""
  parse_errors: List[str] = field(default_factory=list)


_HEADER_FIELD_NAME_PATTERN = re.compile(r"^[!-9;-~]+$")
_EXTENSION_TAG_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
# Email draft header-format ABNF: the only tags, in the only legal order
# (aid/bind optional). This version defines no extension tags (AUD-F25/F74).
_MODE1_TAG_NAMES_IN_ABNF_ORDER = ["v", "typ", "alg", "h", "bh", "ts", "chain", "aid", "bind"]
_AID_URN_CHARACTERS_AFTER_FWS_REMOVAL_PATTERN = re.compile(r"^[A-Za-z0-9:-]+$")
_BASE64URL_WITHOUT_PADDING_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_COMPACT_JWS_WITHOUT_TRANSPORT_FWS_PATTERN = re.compile(
  r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
)


def _unfold_mime_header_value(raw_value: str) -> str:
  """Remove RFC 5322 header folding from a structured header value.

  RFC 5322 unfolding removes only the folding line break. The continuation
  WSP is deliberately preserved so each AIRS tag grammar, rather than the
  parser as a whole, decides where FWS is legal.
  """
  return re.sub(r"\r?\n(?=[ \t])", "", raw_value)


def _remove_transport_fws_from_encoded_value(encoded_value_with_optional_fws: str) -> str:
  """Remove FWS only for AIRS values whose ABNF explicitly permits it."""
  return re.sub(r"[ \t]+", "", encoded_value_with_optional_fws.strip(" \t"))


def _base64_encoding_is_strictly_valid(base64_value_without_fws: str) -> bool:
  """Require RFC 4648 alphabet, padding, and zero-bit validity for chain=."""
  try:
    base64.b64decode(base64_value_without_fws, validate=True)
    return True
  except (binascii.Error, ValueError):
    return False


def replace_single_chain_tag_value_with_empty_value_preserving_other_text(
  raw_hardware_attestation_header_value: str,
) -> str:
  """Empty chain= while retaining the received tag order and extension text.

  The caller subsequently applies DKIM2 Section 9.6 canonicalization, so
  folding WSP is preserved here and removed only by that cryptographic step.
  """
  parameter_segments = raw_hardware_attestation_header_value.split(";")
  matching_chain_segment_indices: List[int] = []
  replacement_segments = list(parameter_segments)

  for parameter_segment_index, parameter_segment in enumerate(parameter_segments):
    equals_position = parameter_segment.find("=")
    if equals_position < 0:
      continue
    parameter_name = parameter_segment[:equals_position].strip(" \t\r\n").lower()
    if parameter_name == "chain":
      matching_chain_segment_indices.append(parameter_segment_index)
      replacement_segments[parameter_segment_index] = parameter_segment[:equals_position + 1]

  if len(matching_chain_segment_indices) != 1:
    raise ValueError("Hardware-Attestation must contain exactly one chain tag")
  return ";".join(replacement_segments)


def parse_hardware_attestation_header(header_value: str) -> ParsedHardwareAttestationHeader:
  """Parse a Hardware-Attestation header value into structured data.

  The header format is semicolon-separated key=value pairs:
    v=1; typ=TPM; alg=RS256; h=from:to:subject:date:message-id; bh=...; ts=...; chain=...; aid=...

  The chain parameter contains a base64-encoded CMS SignedData (RFC 5652)
  with the hardware signature and certificate chain.
  """
  result = ParsedHardwareAttestationHeader()
  raw_parameters: Dict[str, str] = {}
  parse_errors: List[str] = []

  header_value = _unfold_mime_header_value(header_value)
  result.raw_header_value_with_original_tag_order = header_value

  parameter_pairs = header_value.split(";")
  for parameter_pair_index, parameter_pair in enumerate(parameter_pairs):
    parameter_pair = parameter_pair.strip(" \t")
    if not parameter_pair:
      if parameter_pair_index != len(parameter_pairs) - 1:
        parse_errors.append("Empty parameter between semicolon separators")
      continue
    equals_position = parameter_pair.find("=")
    if equals_position == -1:
      parse_errors.append(f"Parameter lacks equals sign: {parameter_pair!r}")
      continue
    parameter_name = parameter_pair[:equals_position].strip(" \t").lower()
    parameter_value = parameter_pair[equals_position + 1:].strip(" \t")
    if not _EXTENSION_TAG_NAME_PATTERN.fullmatch(parameter_name):
      parse_errors.append(f"Invalid parameter name: {parameter_name!r}")
      continue
    if parameter_name not in _MODE1_TAG_NAMES_IN_ABNF_ORDER:
      # AUD-F25: an unrecognized tag makes the field malformed (not ignored).
      parse_errors.append(f"Unrecognized tag {parameter_name!r}: this version defines no extension tags")
      continue
    if parameter_name in raw_parameters:
      parse_errors.append(f"Duplicate parameter: {parameter_name}")
      continue
    raw_parameters[parameter_name] = parameter_value

  result.raw_parameters = raw_parameters

  # AUD-F74: tags must appear in the ABNF order (dicts keep insertion order).
  received_tag_positions_in_abnf_order = [
    _MODE1_TAG_NAMES_IN_ABNF_ORDER.index(tag_name) for tag_name in raw_parameters
  ]
  if received_tag_positions_in_abnf_order != sorted(received_tag_positions_in_abnf_order):
    parse_errors.append(
      "Tags are not in the required order v; typ; alg; h; bh; ts; chain; [aid; bind]"
    )

  if "v" in raw_parameters:
    if not re.fullmatch(r"[0-9]+", raw_parameters["v"]):
      parse_errors.append("v parameter must contain decimal digits without embedded WSP")
    else:
      result.version = int(raw_parameters["v"])

  result.typ = raw_parameters.get("typ", "")
  if result.typ and not re.fullmatch(r"TPM|PIV|ENC|VRT|SFT", result.typ):
    parse_errors.append("typ parameter is not a supported AIRS type token")
  result.trust_tier = _RFC_TYP_TO_TRUST_TIER.get(result.typ, "unknown")
  result.alg = raw_parameters.get("alg", "")
  if result.alg and not re.fullmatch(r"RS256|ES256|PS256|EdDSA", result.alg):
    parse_errors.append("alg parameter is not a supported AIRS algorithm token")

  # AUD-F26: WSP/FWS anywhere inside h, bh, ts, chain, aid and bind values is
  # not part of the value and is removed before validation (email draft).
  header_names_string = _remove_transport_fws_from_encoded_value(raw_parameters.get("h", ""))
  if header_names_string:
    signed_header_name_parts = header_names_string.split(":")
    if any(
      not signed_header_name_part
      or not _HEADER_FIELD_NAME_PATTERN.fullmatch(signed_header_name_part)
      for signed_header_name_part in signed_header_name_parts
    ):
      parse_errors.append(
        "h parameter must contain complete RFC 5322 field names separated by colons"
      )
    else:
      result.signed_header_names = [
        signed_header_name_part.lower()
        for signed_header_name_part in signed_header_name_parts
      ]

  bh_raw = raw_parameters.get("bh", "")
  result.bh = _remove_transport_fws_from_encoded_value(bh_raw)
  if result.bh and not _BASE64URL_WITHOUT_PADDING_PATTERN.fullmatch(result.bh):
    parse_errors.append("bh parameter must be unpadded base64url after FWS removal")

  if "ts" in raw_parameters:
    ts_without_fws = _remove_transport_fws_from_encoded_value(raw_parameters["ts"])
    if not re.fullmatch(r"[0-9]+", ts_without_fws):
      parse_errors.append("ts parameter must contain decimal digits after FWS removal")
    else:
      result.ts = int(ts_without_fws)

  chain_raw = raw_parameters.get("chain", "")
  result.chain_base64 = _remove_transport_fws_from_encoded_value(chain_raw)
  if result.chain_base64 and not _base64_encoding_is_strictly_valid(result.chain_base64):
    parse_errors.append("chain parameter is not strict RFC 4648 base64")

  aid_raw = raw_parameters.get("aid")
  result.aid = _remove_transport_fws_from_encoded_value(aid_raw) if aid_raw is not None else None
  if result.aid is not None and not _AID_URN_CHARACTERS_AFTER_FWS_REMOVAL_PATTERN.fullmatch(result.aid):
    parse_errors.append("aid parameter must be a non-empty URN (ALPHA / DIGIT / - / :) after FWS removal")

  bind_raw = raw_parameters.get("bind")
  if bind_raw is not None:
    result.bind = _remove_transport_fws_from_encoded_value(bind_raw)
    if not _COMPACT_JWS_WITHOUT_TRANSPORT_FWS_PATTERN.fullmatch(result.bind):
      parse_errors.append("bind parameter is not a compact JWS after permitted FWS removal")

  result.parse_errors = parse_errors
  return result
