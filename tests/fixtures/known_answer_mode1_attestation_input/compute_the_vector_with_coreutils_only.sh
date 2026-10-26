#!/bin/bash
# Computes the 92-octet Mode 1 attestation-input of draft -03 for a small fixed message using ONLY coreutils
# (printf, sha256sum, xxd, base64), so that it shares no code with any implementation.
#   attestation-input = label || h-hash || bh-raw || ts-bytes
#   label = "AIRS-Email-Mode1-v1" || 0x00 (20 octets)
set -e
TS=1792000000

# body: simple canonicalization of "Known answer body.<CRLF>" is itself
BH_RAW_HEX=$(printf 'Known answer body.\r\n' | sha256sum | cut -d' ' -f1)
BH_B64URL=$(printf '%s' "$BH_RAW_HEX" | xxd -r -p | base64 -w0 | tr '+/' '-_' | tr -d '=')

H_TAG='from:to:cc:subject:date:message-id:sender:reply-to:in-reply-to:references:mime-version:content-type:content-transfer-encoding'
# the Hardware-Attestation tags with chain= emptied and every WSP removed (no trailing semicolon in this message)
SELF_REFERENCE="v=1;typ=SFT;alg=ES256;h=${H_TAG};bh=${BH_B64URL};ts=${TS};chain="

# canonicalized headers in h order (absent fields: cc, sender, reply-to, in-reply-to, references contribute nothing),
# then the Hardware-Attestation self reference; relaxed canonicalization: lowercase name, single spaces, no edge WSP
H_HASH_HEX=$( {
  printf 'from:alice@example.com\r\n'
  printf 'to:bob@example.org\r\n'
  printf 'subject:Known answer\r\n'
  printf 'date:Mon, 26 Oct 2026 10:00:00 +0000\r\n'
  printf 'message-id:<known-answer-1@example.com>\r\n'
  printf 'mime-version:1.0\r\n'
  printf 'content-type:text/plain; charset=utf-8\r\n'
  printf 'content-transfer-encoding:7bit\r\n'
  printf 'hardware-attestation:%s\r\n' "$SELF_REFERENCE"
} | sha256sum | cut -d' ' -f1)

LABEL_HEX=$(printf 'AIRS-Email-Mode1-v1\0' | xxd -p -c 256)
TS_HEX=$(printf '%016x' "$TS")

echo "bh_b64url=${BH_B64URL}"
echo "bh_raw_hex=${BH_RAW_HEX}"
echo "h_hash_hex=${H_HASH_HEX}"
echo "label_hex=${LABEL_HEX}"
echo "ts_hex=${TS_HEX}"
INPUT_HEX="${LABEL_HEX}${H_HASH_HEX}${BH_RAW_HEX}${TS_HEX}"
echo "attestation_input_hex=${INPUT_HEX}"
echo "octets=$(( ${#INPUT_HEX} / 2 ))"
