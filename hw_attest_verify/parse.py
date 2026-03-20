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
  raw_parameters: Dict[str, str] = field(default_factory=dict)


def parse_hardware_attestation_header(header_value: str) -> ParsedHardwareAttestationHeader:
  """Parse a Hardware-Attestation header value into structured data.

  The header format is semicolon-separated key=value pairs:
    v=1; typ=TPM; alg=RS256; h=from:to:subject:date:message-id; bh=...; ts=...; chain=...; aid=...

  The chain parameter contains a base64-encoded CMS SignedData (RFC 5652)
  with the hardware signature and certificate chain.
  """
  result = ParsedHardwareAttestationHeader()
  raw_parameters: Dict[str, str] = {}

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

  header_names_string = raw_parameters.get("h", "")
  if header_names_string:
    result.signed_header_names = [
      name.strip().lower() for name in header_names_string.split(":")
      if name.strip()
    ]

  result.bh = raw_parameters.get("bh", "")

  if "ts" in raw_parameters:
    try:
      result.ts = int(raw_parameters["ts"])
    except ValueError:
      pass

  result.chain_base64 = raw_parameters.get("chain", "")
  result.aid = raw_parameters.get("aid")

  return result

