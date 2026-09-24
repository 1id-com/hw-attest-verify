"""
Issuer public key discovery for Hardware-Trust-Proof (Mode 2) verification.

RFC: draft-drake-email-hardware-attestation-03, Section 4

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
from urllib.error import HTTPError, URLError

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
    logger.debug("No JWK matched kid=%s in JWKS from %s", kid, jwks_url)

  return None


def _load_ec_public_key_from_base64_spki(b64_spki: str) -> Optional[ec.EllipticCurvePublicKey]:
  """Load an EC public key from base64-encoded SubjectPublicKeyInfo DER."""
  try:
    padded = b64_spki + "=" * ((4 - len(b64_spki) % 4) % 4)
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

  x_bytes = base64.urlsafe_b64decode(x_b64 + "=" * ((4 - len(x_b64) % 4) % 4))
  y_bytes = base64.urlsafe_b64decode(y_b64 + "=" * ((4 - len(y_b64) % 4) % 4))

  public_numbers = ec.EllipticCurvePublicNumbers(
    x=int.from_bytes(x_bytes, "big"),
    y=int.from_bytes(y_bytes, "big"),
    curve=ec.SECP256R1(),
  )
  return public_numbers.public_key()



# --- Email draft "Authoritative Registrar Key Discovery" (hw-attest-verify 2.0.1) ---
#
# Verifiers resolve the aid at the AIRS Registry, take its currentIssuer, fetch
# RFC 8414 Authorization Server Metadata for EXACTLY that issuer, require
# metadata.issuer == currentIssuer, and obtain Registrar signing keys ONLY from
# that metadata's jwks_uri. (The DNS TXT / {domain}/.well-known/jwks.json
# lookups above are kept only for API compatibility; the verification paths no
# longer use them -- AUD-F04: a token must not bootstrap its own authority.)

_RFC8414_CACHE_SECONDS = 300
_registrar_jwk_set_cache: dict = {}


class TransientExternalLookupFailure(Exception):
  """AIRS currentIssuer resolution or issuer metadata/JWK Set retrieval could
  not complete (network error, timeout, HTTP 429/5xx). Verifiers report the
  email draft's temperror for this, never pass and never a permanent fail."""


def build_rfc8414_metadata_url_for_issuer(issuer_uri: str) -> Optional[str]:
  """RFC 8414 s3.1: insert /.well-known/oauth-authorization-server between the
  host and the path of the issuer identifier (https, no query/fragment)."""
  from urllib.parse import urlparse
  parsed_issuer = urlparse(issuer_uri)
  if parsed_issuer.scheme != "https" or not parsed_issuer.netloc or parsed_issuer.query or parsed_issuer.fragment:
    return None
  return f"https://{parsed_issuer.netloc}/.well-known/oauth-authorization-server{parsed_issuer.path.rstrip('/')}"


def _fetch_json_document(url: str) -> dict:
  """GET a JSON document. HTTP 4xx (except 429) and bad JSON raise ordinary
  exceptions (permanent); network errors and 429/5xx raise
  TransientExternalLookupFailure."""
  request = Request(url, headers={"Accept": "application/json"})
  try:
    with urlopen(request, timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as response:
      response_bytes = response.read()
  except HTTPError as http_error:
    if http_error.code == 429 or http_error.code >= 500:
      raise TransientExternalLookupFailure(f"{url}: HTTP {http_error.code}") from http_error
    raise
  except (URLError, TimeoutError, OSError) as network_error:
    raise TransientExternalLookupFailure(f"{url}: {network_error}") from network_error
  return json.loads(response_bytes.decode("utf-8"))


def fetch_registrar_jwk_set_via_rfc8414_metadata(issuer_uri: str):
  """Return (list_of_jwks, None) or (None, failure_reason). Cached per issuer.
  Raises TransientExternalLookupFailure when the lookup could not complete."""
  import time
  cached_entry = _registrar_jwk_set_cache.get(issuer_uri)
  if cached_entry and time.time() - cached_entry[0] < _RFC8414_CACHE_SECONDS:
    return cached_entry[1], None
  metadata_url = build_rfc8414_metadata_url_for_issuer(issuer_uri)
  if metadata_url is None:
    return None, f"issuer {issuer_uri!r} is not an https issuer identifier (RFC 8414)"
  try:
    metadata = _fetch_json_document(metadata_url)
  except TransientExternalLookupFailure:
    raise
  except Exception as metadata_error:
    return None, f"RFC 8414 metadata for {issuer_uri!r} unavailable ({metadata_url}): {metadata_error}"
  if metadata.get("issuer") != issuer_uri:
    return None, f"RFC 8414 metadata issuer {metadata.get('issuer')!r} does not equal {issuer_uri!r}"
  jwks_uri = metadata.get("jwks_uri")
  if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
    return None, f"RFC 8414 metadata for {issuer_uri!r} has no https jwks_uri (permanent error)"
  try:
    jwk_set = _fetch_json_document(jwks_uri)
  except TransientExternalLookupFailure:
    raise
  except Exception as jwks_error:
    return None, f"JWK Set {jwks_uri} unavailable: {jwks_error}"
  keys = jwk_set.get("keys") if isinstance(jwk_set, dict) else None
  if not isinstance(keys, list):
    return None, f"JWK Set {jwks_uri} has no keys array"
  _registrar_jwk_set_cache[issuer_uri] = (time.time(), keys)
  return keys, None


def load_public_key_from_jwk(jwk: dict):
  """EC (P-256/P-384) or RSA public key from a JWK; private members are refused."""
  if any(private_member in jwk for private_member in ("d", "p", "q", "dp", "dq", "qi", "k")):
    raise ValueError("JWK contains private key members")

  def b64url_int(value: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")

  if jwk.get("kty") == "EC":
    curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}.get(jwk.get("crv"))
    if curve is None:
      raise ValueError(f"unsupported EC curve {jwk.get('crv')!r}")
    return ec.EllipticCurvePublicNumbers(x=b64url_int(jwk["x"]), y=b64url_int(jwk["y"]), curve=curve).public_key()
  if jwk.get("kty") == "RSA":
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.RSAPublicNumbers(e=b64url_int(jwk["e"]), n=b64url_int(jwk["n"])).public_key()
  raise ValueError(f"unsupported JWK kty {jwk.get('kty')!r}")


def discover_registrar_signing_key(issuer_uri: str, kid: Optional[str]):
  """Return (public_key, None) for the signing-capable key `kid` in the
  issuer's authenticated JWK Set, or (None, failure_reason). Raises
  TransientExternalLookupFailure when the lookup could not complete."""
  if not kid:
    return None, "JWS protected header has no kid (required)"
  keys, failure_reason = fetch_registrar_jwk_set_via_rfc8414_metadata(issuer_uri)
  if keys is None:
    return None, failure_reason
  for jwk in keys:
    if jwk.get("kid") != kid:
      continue
    if jwk.get("use", "sig") != "sig":
      return None, f"key {kid!r} is not a signing key (use={jwk.get('use')!r})"
    try:
      return load_public_key_from_jwk(jwk), None
    except Exception as key_error:
      return None, f"key {kid!r} in the JWK Set is unusable: {key_error}"
  return None, f"kid {kid!r} not found in the JWK Set of {issuer_uri!r}"


def verify_compact_jws_signature(public_key, alg: str, signing_input: bytes, signature: bytes) -> Optional[str]:
  """Verify a JWS signature (RFC 7518) with the discovered key; None = valid.
  ES256 (raw R||S), RS256, PS256; any other alg (incl. none / HS*) is refused."""
  from cryptography.exceptions import InvalidSignature
  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding, rsa
  from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
  try:
    if alg == "ES256":
      if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        return "ES256 requires a P-256 key"
      if len(signature) != 64:
        return "ES256 JWS signature must be 64 octets (R||S)"
      der_signature = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
      public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    elif alg == "RS256":
      if not isinstance(public_key, rsa.RSAPublicKey):
        return "RS256 requires an RSA key"
      public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256":
      if not isinstance(public_key, rsa.RSAPublicKey):
        return "PS256 requires an RSA key"
      public_key.verify(signature, signing_input, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    else:
      return f"JWS alg {alg!r} is not accepted"
  except InvalidSignature:
    return "JWS signature verification failed"
  return None
