"""
Parse Hardware-Attestation and Hardware-Trust-Proof header values.

RFC: draft-drake-email-hardware-attestation-00, Section 5
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


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


def _unfold_mime_header_value(raw_value: str) -> str:
  """Remove RFC 5322 header folding from a structured header value.

  Per RFC 5322 Section 2.2.3: unfolding is performed by removing any
  CRLF that is immediately followed by at least one WSP character.
  After unfolding, leading/trailing whitespace and any WSP around
  semicolons is stripped since our headers are semicolon-delimited
  structured fields where inter-token whitespace is insignificant.
  """
  unfolded = re.sub(r"\r\n([ \t]+)", r"\1", raw_value)
  unfolded = re.sub(r"\n([ \t]+)", r"\1", unfolded)
  unfolded = re.sub(r"[ \t]+", " ", unfolded)
  unfolded = re.sub(r"\s*;\s*", ";", unfolded)
  return unfolded.strip()


def parse_hardware_attestation_header(header_value: str) -> ParsedHardwareAttestationHeader:
  """Parse a Hardware-Attestation header value into structured data.

  The header format is semicolon-separated key=value pairs:
    v=1; typ=TPM; alg=RS256; h=from:to:subject:date:message-id; bh=...; ts=...; chain=...; aid=...

  The chain parameter contains a base64-encoded CMS SignedData (RFC 5652)
  with the hardware signature and certificate chain.
  """
  result = ParsedHardwareAttestationHeader()
  raw_parameters: Dict[str, str] = {}

  header_value = _unfold_mime_header_value(header_value)

  for parameter_pair in header_value.split(";"):
    parameter_pair = parameter_pair.strip()
    if not parameter_pair:
      continue
    equals_position = parameter_pair.find("=")
    if equals_position == -1:
      continue
    parameter_name = parameter_pair[:equals_position].strip().lower()
    parameter_value = parameter_pair[equals_position + 1:].strip()
    raw_parameters[parameter_name] = parameter_value

  result.raw_parameters = raw_parameters

  if "v" in raw_parameters:
    try:
      result.version = int(raw_parameters["v"])
    except ValueError:
      pass

  result.typ = raw_parameters.get("typ", "")
  result.trust_tier = _RFC_TYP_TO_TRUST_TIER.get(result.typ, "unknown")
  result.alg = raw_parameters.get("alg", "")

  header_names_string = re.sub(r"[ \t\r\n]+", "", raw_parameters.get("h", ""))
  if header_names_string:
    result.signed_header_names = [
      name.lower() for name in header_names_string.split(":")
      if name
    ]

  bh_raw = raw_parameters.get("bh", "")
  result.bh = re.sub(r"[ \t\r\n]+", "", bh_raw)

  if "ts" in raw_parameters:
    try:
      result.ts = int(re.sub(r"[ \t\r\n]+", "", raw_parameters["ts"]))
    except ValueError:
      pass

  chain_raw = raw_parameters.get("chain", "")
  result.chain_base64 = re.sub(r"[ \t\r\n]+", "", chain_raw)

  aid_raw = raw_parameters.get("aid")
  result.aid = re.sub(r"[ \t\r\n]+", "", aid_raw) if aid_raw is not None else None

  bind_raw = raw_parameters.get("bind")
  if bind_raw is not None:
    result.bind = re.sub(r"[ \t\r\n]+", "", bind_raw)

  return result

