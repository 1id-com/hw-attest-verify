"""
Issuer public key discovery for Hardware-Trust-Proof (Mode 2) verification.

RFC: draft-drake-email-hardware-attestation-00, Section 6.1

Two discovery mechanisms, tried in order:
  1. DNS TXT record at _hwattest.{domain} (preferred, no HTTPS fetch needed)
  2. HTTPS JWKS at {issuer}/.well-known/jwks.json (fallback)

The DNS record format:
  _hwattest.1id.com.  IN TXT "v=hwattest1; alg=ES256; p=MFkwEwYH..."

The p= tag contains the base64-encoded SubjectPublicKeyInfo DER encoding
of the issuer's EC P-256 public key.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

logger = logging.getLogger("hw_attest_verify.issuer_key_discovery")

_JWKS_FETCH_TIMEOUT_SECONDS = 10


def discover_issuer_public_key(
  issuer_domain: str,
  kid: Optional[str] = None,
) -> Optional[ec.EllipticCurvePublicKey]:
  """Discover the issuer's public key via DNS or JWKS.

  Tries DNS _hwattest.{domain} first, then falls back to HTTPS JWKS.

  Args:
    issuer_domain: The issuer's domain name (e.g. "1id.com").
    kid: Optional key ID to match in JWKS (from the SD-JWT header).

  Returns:
    The issuer's EC P-256 public key, or None if discovery fails.
  """
  dns_key = _discover_key_via_dns_txt_record(issuer_domain, kid=kid)
  if dns_key is not None:
    return dns_key

  jwks_key = _discover_key_via_https_jwks(issuer_domain, kid=kid)
  if jwks_key is not None:
    return jwks_key

  return None


def _discover_key_via_dns_txt_record(
  issuer_domain: str,
  kid: Optional[str] = None,
) -> Optional[ec.EllipticCurvePublicKey]:
  """Look up _hwattest.{domain} DNS TXT record for the issuer's public key.

  Record format: "v=hwattest1; alg=ES256; p=<base64 SPKI DER>; kid=<optional>"
  """
  dns_name = f"_hwattest.{issuer_domain}"
  try:
    import dns.resolver
    answers = dns.resolver.resolve(dns_name, "TXT")
    for rdata in answers:
      txt_value = b"".join(rdata.strings).decode("utf-8")
      key = _parse_hwattest_dns_record(txt_value, kid=kid)
      if key is not None:
        return key
  except ImportError:
    logger.debug("dnspython not installed; skipping DNS key discovery for %s", dns_name)
  except Exception as dns_error:
    logger.debug("DNS lookup for %s failed: %s", dns_name, dns_error)

  return None


def _parse_hwattest_dns_record(
  txt_value: str,
  kid: Optional[str] = None,
) -> Optional[ec.EllipticCurvePublicKey]:
  """Parse a _hwattest DNS TXT record value into an EC public key.

  Expected format: "v=hwattest1; alg=ES256; p=<base64 SPKI DER>"
  """
  params = {}
  for part in txt_value.split(";"):
    part = part.strip()
    equals_pos = part.find("=")
    if equals_pos == -1:
      continue
    tag = part[:equals_pos].strip().lower()
    value = part[equals_pos + 1:].strip()
    params[tag] = value

  if params.get("v") != "hwattest1":
    return None

  if kid is not None and "kid" in params and params["kid"] != kid:
    return None

  p_b64 = params.get("p", "")
  if not p_b64:
    return None

  return _load_ec_public_key_from_base64_spki(p_b64)


def _discover_key_via_https_jwks(
  issuer_domain: str,
  kid: Optional[str] = None,
) -> Optional[ec.EllipticCurvePublicKey]:
  """Fetch the issuer's JWKS from https://{domain}/.well-known/jwks.json."""
  jwks_url = f"https://{issuer_domain}/.well-known/jwks.json"

  try:
    request = Request(jwks_url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as response:
      jwks_data = json.loads(response.read().decode("utf-8"))
  except (URLError, json.JSONDecodeError, OSError) as fetch_error:
    logger.debug("JWKS fetch from %s failed: %s", jwks_url, fetch_error)
    return None

  keys = jwks_data.get("keys", [])
  for jwk in keys:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
      continue
    if jwk.get("use", "sig") != "sig":
      continue
    if kid is not None and jwk.get("kid") != kid:
      continue

    try:
      return _load_ec_public_key_from_jwk(jwk)
    except Exception as key_parse_error:
      logger.debug("Failed to parse JWK: %s", key_parse_error)
      continue

  if kid is not None:
    for jwk in keys:
      if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        continue
      try:
        return _load_ec_public_key_from_jwk(jwk)
      except Exception:
        continue

  return None


def _load_ec_public_key_from_base64_spki(b64_spki: str) -> Optional[ec.EllipticCurvePublicKey]:
  """Load an EC public key from base64-encoded SubjectPublicKeyInfo DER."""
  try:
    padded = b64_spki + "=" * (4 - len(b64_spki) % 4)
    der_bytes = base64.b64decode(padded)
    key = load_der_public_key(der_bytes)
    if isinstance(key, ec.EllipticCurvePublicKey):
      return key
  except Exception as decode_error:
    logger.debug("Failed to decode SPKI from base64: %s", decode_error)
  return None


def _load_ec_public_key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
  """Load an EC P-256 public key from a JWK dict (x, y coordinates)."""
  x_b64 = jwk["x"]
  y_b64 = jwk["y"]

  x_bytes = base64.urlsafe_b64decode(x_b64 + "=" * (4 - len(x_b64) % 4))
  y_bytes = base64.urlsafe_b64decode(y_b64 + "=" * (4 - len(y_b64) % 4))

  public_numbers = ec.EllipticCurvePublicNumbers(
    x=int.from_bytes(x_bytes, "big"),
    y=int.from_bytes(y_bytes, "big"),
    curve=ec.SECP256R1(),
  )
  return public_numbers.public_key()

