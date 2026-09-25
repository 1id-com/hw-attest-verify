"""
hw-attest-verify: Verification library for RFC Hardware-Attestation headers.

Implements verification for:
  Mode 1: Hardware-Attestation (CMS SignedData with hardware cert chain)
  Mode 2: Hardware-Trust-Proof (SD-JWT with selective disclosure)

RFC: draft-drake-email-hardware-attestation

Usage:
    # Mode 1 (Direct Hardware Attestation)
    from hw_attest_verify import verify_hardware_attestation
    result = verify_hardware_attestation(header_value=..., email_headers=..., body=...)

    # Mode 2 (SD-JWT Trust Proof)
    from hw_attest_verify import verify_hardware_trust_proof
    result = verify_hardware_trust_proof(header_value=..., email_headers=..., body=...,
                                         trusted_hidden_mode_issuers=[...])

    # Both fields present (Combined mode): apply the cross-checks to Mode 2
    from hw_attest_verify import apply_combined_mode_requirements_to_mode2_result
    apply_combined_mode_requirements_to_mode2_result(mode1_result, mode2_result)

    # result.authentication_results_result is the A-R result name:
    # pass / fail / policy / temperror / permerror
"""

from .combined import apply_combined_mode_requirements_to_mode2_result
from .issuer_key_discovery import AirsIdentityResolutionRejected, TransientExternalLookupFailure
from .mode1 import verify_hardware_attestation, VerificationResult
from .mode2 import verify_hardware_trust_proof, Mode2VerificationResult
from .parse import parse_hardware_attestation_header

__version__ = "2.0.2"

__all__ = [
  "verify_hardware_attestation",
  "verify_hardware_trust_proof",
  "apply_combined_mode_requirements_to_mode2_result",
  "TransientExternalLookupFailure",
  "AirsIdentityResolutionRejected",
  "parse_hardware_attestation_header",
  "VerificationResult",
  "Mode2VerificationResult",
]

