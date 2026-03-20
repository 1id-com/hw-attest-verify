"""
hw-attest-verify: Verification library for RFC Hardware-Attestation headers.

Implements verification for:
  Mode 1: Hardware-Attestation (CMS SignedData with hardware cert chain)
  Mode 2: Hardware-Trust-Proof (SD-JWT with selective disclosure)

RFC: draft-drake-email-hardware-attestation-00

Usage:
    # Mode 1 (Direct Hardware Attestation)
    from hw_attest_verify import verify_hardware_attestation
    result = verify_hardware_attestation(header_value=..., email_headers=..., body=...)

    # Mode 2 (SD-JWT Trust Proof)
    from hw_attest_verify import verify_hardware_trust_proof
    result = verify_hardware_trust_proof(header_value=..., email_headers=..., body=...)
"""

from .mode1 import verify_hardware_attestation, VerificationResult
from .mode2 import verify_hardware_trust_proof, Mode2VerificationResult
from .parse import parse_hardware_attestation_header

__version__ = "0.1.0"

__all__ = [
  "verify_hardware_attestation",
  "verify_hardware_trust_proof",
  "parse_hardware_attestation_header",
  "VerificationResult",
  "Mode2VerificationResult",
]

