"""
Combined mode: a message carrying both Hardware-Attestation and
Hardware-Trust-Proof (draft-drake-email-hardware-attestation-03, "Combined Mode").

Combined mode is meaningful only when the two artifacts concern the same
message and the same Mode-1 signing key, so the Mode 2 presentation passes only
if (AUD-F19):
  - Mode 1 verified, and its h= covers Hardware-Trust-Proof;
  - the SD-JWT carries a non-selective cnf.jwk equal to the CMS signer key;
  - when Mode 1 carries a verified aid, Mode 2 discloses sub and it is equal;
  - the two trust tiers agree.
Mode 1 stands on its own; a broken Combined relationship fails the Mode 2 result.
"""

from __future__ import annotations

from typing import List

from .mode1 import VerificationResult
from .mode2 import Mode2VerificationResult


def apply_combined_mode_requirements_to_mode2_result(
  mode1_result: VerificationResult,
  mode2_result: Mode2VerificationResult,
) -> List[str]:
  """Check the Combined-mode rules for a message that carries both fields.

  Only a Mode 2 result that passed on its own is changed: when a rule is broken
  it becomes fail (or temperror / policy when that is the Mode 1 outcome it
  depends on) with the reasons first. Returns the reasons (empty = consistent).
  """
  if mode2_result.authentication_results_result != "pass":
    return []

  combined_mode_problems: List[str] = []
  dependent_result = "fail"
  if mode1_result.authentication_results_result != "pass":
    if mode1_result.authentication_results_result in ("temperror", "policy"):
      dependent_result = mode1_result.authentication_results_result
    combined_mode_problems.append(
      "Combined mode: the Hardware-Attestation proof this presentation depends on is "
      f"{mode1_result.authentication_results_result} ({mode1_result.failure_reason})"
    )
  else:
    mode1_signed_header_names = {name.strip().lower() for name in mode1_result.signed_header_names}
    if "hardware-trust-proof" not in mode1_signed_header_names:
      combined_mode_problems.append("Combined mode: Mode 1 h= does not cover Hardware-Trust-Proof")
    if not mode2_result.cnf_jwk_thumbprint:
      combined_mode_problems.append("Combined mode: the SD-JWT has no non-selective cnf.jwk")
    elif mode2_result.cnf_jwk_thumbprint != mode1_result.signer_public_key_jwk_thumbprint:
      combined_mode_problems.append("Combined mode: SD-JWT cnf.jwk is not the CMS signer public key")
    if mode1_result.agent_identity_urn:
      if not mode2_result.is_identified_mode:
        combined_mode_problems.append("Combined mode: Mode 1 carries aid but Mode 2 does not disclose sub")
      elif mode2_result.agent_identity_urn != mode1_result.agent_identity_urn:
        combined_mode_problems.append(
          f"Combined mode: Mode 1 aid {mode1_result.agent_identity_urn!r} differs from "
          f"Mode 2 sub {mode2_result.agent_identity_urn!r}"
        )
    if mode1_result.trust_tier and mode2_result.trust_tier and mode1_result.trust_tier != mode2_result.trust_tier:
      combined_mode_problems.append(
        f"Combined mode: Mode 1 trust tier {mode1_result.trust_tier!r} differs from "
        f"Mode 2 trust tier {mode2_result.trust_tier!r}"
      )

  if combined_mode_problems:
    mode2_result.authentication_results_result = dependent_result
    mode2_result.is_valid = False
    mode2_result.failure_reasons = combined_mode_problems + list(mode2_result.failure_reasons)
    mode2_result.failure_reason = combined_mode_problems[0]
  return combined_mode_problems
