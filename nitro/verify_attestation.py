#!/usr/bin/env python3
"""Challenge an enclave and independently verify AWS Nitro attestation.

No endpoint-supplied key or CA becomes a trust anchor. Expected measurements and
application keys must come from the reviewed release and controlled Config.
"""

import argparse
import base64
import binascii
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT_DER_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
PROTOCOL = "SCB_VERDICT_V5"
MAX_DOCUMENT = 16384
MAX_RESPONSE = 32768
MAX_AGE_SECONDS = 300
FUTURE_SKEW_SECONDS = 30
RESPONSE_FIELDS = {
    "document_b64", "nonce_b64", "enclave_enc_pubkey_hex", "verdict_pubkey_hex",
    "build_commit", "protocol", "attestation_version",
}
DOCUMENT_FIELDS = {
    "module_id", "timestamp", "digest", "pcrs", "certificate", "cabundle",
    "public_key", "user_data", "nonce",
}


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def decode_cbor(data):
    stream = io.BytesIO(data)
    try:
        value = cbor2.CBORDecoder(
            stream, max_depth=8, allow_indefinite=False,
            allow_duplicate_keys=False, read_size=1,
        ).decode()
    except (ValueError, TypeError, cbor2.CBORDecodeError) as exc:
        raise VerificationError("invalid or ambiguous CBOR") from exc
    require(stream.tell() == len(data), "trailing CBOR bytes")
    return value


def decode_base64(value, maximum):
    require(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3),
            "oversized or invalid base64 field")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VerificationError("invalid base64 field") from exc
    require(len(raw) <= maximum and base64.b64encode(raw).decode("ascii") == value,
            "oversized or noncanonical base64 field")
    return raw


def json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_json_constant(_):
    raise VerificationError("nonfinite JSON number")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise VerificationError("attestation endpoint redirected the request")


def fetch(url, nonce, allow_loopback_http):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.hostname is not None and parsed.username is None
            and parsed.password is None and not parsed.query and not parsed.fragment,
            "URL must have a host and no credentials, query, or fragment")
    require(parsed.path.endswith("/internal/attestation"),
            "URL must name the /internal/attestation endpoint")
    if parsed.scheme != "https":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        require(parsed.scheme == "http" and allow_loopback_http and loopback,
                "HTTPS required; HTTP is allowed only for an explicit loopback IP tunnel")
    encoded = json.dumps({"nonce_b64": base64.b64encode(nonce).decode("ascii")}).encode()
    request = urllib.request.Request(url, data=encoded, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Accept-Encoding": "identity",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    deadline = time.monotonic() + 20
    with opener.open(request, timeout=20) as response:
        require(response.status == 200, "attestation endpoint returned a non-200 status")
        require(response.headers.get_content_type() == "application/json",
                "attestation endpoint did not return JSON")
        require(response.headers.get("Content-Encoding", "identity") == "identity",
                "compressed responses are not accepted")
        chunks = []
        size = 0
        while size <= MAX_RESPONSE:
            require(time.monotonic() <= deadline, "attestation HTTP response exceeded 20 seconds")
            chunk = response.read1(min(4096, MAX_RESPONSE + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
    require(len(raw) <= MAX_RESPONSE, "attestation response too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=json_object,
                           parse_constant=reject_json_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VerificationError("invalid JSON response") from exc
    require(type(value) is dict and set(value) == RESPONSE_FIELDS,
            "unexpected attestation response fields")
    return value


def cert_from_der(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 1024, "invalid certificate length")
    try:
        cert = x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise VerificationError("invalid DER certificate") from exc
    require(cert.public_bytes(serialization.Encoding.DER) == raw,
            "noncanonical DER certificate")
    return cert


def verify_chain(payload, now):
    root_path = Path(__file__).with_name("aws_nitro_root_g1.pem")
    root = x509.load_pem_x509_certificate(root_path.read_bytes())
    require(root.fingerprint(hashes.SHA256()).hex() == ROOT_DER_SHA256,
            "local AWS trust root fingerprint mismatch")
    leaf = cert_from_der(payload["certificate"])
    bundle = payload["cabundle"]
    require(type(bundle) is list and 1 <= len(bundle) <= 16, "invalid CA bundle")
    chain = [cert_from_der(raw) for raw in bundle]
    require(chain[0].fingerprint(hashes.SHA256()).hex() == ROOT_DER_SHA256,
            "attestation CA bundle is not rooted at the pinned AWS CA")
    seen = set()
    for cert in [leaf, *chain]:
        fingerprint = cert.fingerprint(hashes.SHA256())
        require(fingerprint not in seen, "duplicate attestation certificate")
        seen.add(fingerprint)
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise VerificationError("certificate lacks basic constraints or key usage") from exc
        if cert is leaf:
            require(not constraints.value.ca and constraints.value.path_length is None
                    and usage.digital_signature, "invalid attestation signing certificate usage")
        else:
            require(constraints.critical and constraints.value.ca and usage.key_cert_sign,
                    "invalid attestation CA constraints")
        before = cert.not_valid_before_utc.timestamp()
        after = cert.not_valid_after_utc.timestamp()
        require(before <= now <= after, "attestation certificate is outside its validity period")
    key = leaf.public_key()
    require(isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP384R1), "attestation signing key is not P-384")
    # OpenSSL performs full RFC 5280 path/constraint/critical-extension checks.
    # All default CA stores are disabled; the bundled root is the sole anchor.
    with tempfile.TemporaryDirectory(prefix="scb-attestation-") as directory:
        directory = Path(directory)
        trusted = directory / "root.pem"
        target = directory / "leaf.pem"
        untrusted = directory / "intermediates.pem"
        trusted.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        target.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        untrusted.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in chain[1:]))
        command = [
            "/usr/bin/openssl", "verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
            "-trusted", str(trusted), "-x509_strict", "-check_ss_sig", "-auth_level", "2",
            "-purpose", "any", "-attime", str(int(now)),
        ]
        if len(chain) > 1:
            command.extend(["-untrusted", str(untrusted)])
        command.append(str(target))
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        require(result.returncode == 0, "AWS certificate path validation failed")
    return key


def verify_response(response, nonce, pcr0, enc_key, verdict_key, build_commit):
    require(type(response) is dict and set(response) == RESPONSE_FIELDS,
            "unexpected attestation response fields")
    require(type(response["attestation_version"]) is int
            and response["attestation_version"] == 1, "unsupported attestation binding version")
    require(response["protocol"] == PROTOCOL and response["build_commit"] == build_commit,
            "response protocol or source commit does not match the expected release")
    require(response["enclave_enc_pubkey_hex"] == enc_key.hex()
            and response["verdict_pubkey_hex"] == verdict_key.hex(),
            "response application keys differ from the independently pinned keys")
    require(decode_base64(response["nonce_b64"], 64) == nonce, "response nonce mismatch")
    document = decode_base64(response["document_b64"], MAX_DOCUMENT)
    require(document, "empty attestation document")
    # Nitro accepts both the untagged and the COSE_Sign1 tag-18 encoding.
    cose = decode_cbor(document)
    if isinstance(cose, cbor2.CBORTag):
        require(cose.tag == 18, "unexpected COSE tag")
        cose = cose.value
    require(type(cose) is list and len(cose) == 4, "invalid COSE_Sign1 structure")
    protected, unprotected, payload_raw, signature = cose
    require(type(protected) is bytes and 1 <= len(protected) <= 128,
            "invalid COSE protected header")
    algorithm = decode_cbor(protected)
    require(type(algorithm) is dict and len(algorithm) == 1
            and all(type(k) is int for k in algorithm)
            and type(algorithm.get(1)) is int and algorithm[1] == -35,
            "COSE algorithm must be protected ES384")
    require(type(unprotected) is dict and not unprotected, "unexpected unprotected COSE headers")
    require(type(payload_raw) is bytes and 1 <= len(payload_raw) <= MAX_DOCUMENT,
            "invalid COSE payload")
    require(type(signature) is bytes and len(signature) == 96, "invalid ES384 signature length")
    payload = decode_cbor(payload_raw)
    require(type(payload) is dict and set(payload) == DOCUMENT_FIELDS,
            "unexpected or missing attestation document fields")
    require(type(payload["module_id"]) is str and 1 <= len(payload["module_id"]) <= 1024,
            "invalid module ID")
    require(payload["digest"] == "SHA384", "unexpected PCR digest algorithm")
    require(type(payload["timestamp"]) is int and 0 < payload["timestamp"] < 2**64,
            "invalid attestation timestamp")
    pcrs = payload["pcrs"]
    require(type(pcrs) is dict and 1 <= len(pcrs) <= 32, "invalid PCR map")
    for index, digest in pcrs.items():
        require(type(index) is int and 0 <= index < 32
                and type(digest) is bytes and len(digest) == 48, "invalid SHA384 PCR")
    require(pcrs.get(0) == pcr0 and any(pcr0), "PCR0 does not match the reviewed non-debug image")
    require(type(payload["nonce"]) is bytes and payload["nonce"] == nonce,
            "signed nonce does not match the fresh challenge")
    require(type(payload["public_key"]) is bytes and payload["public_key"] == enc_key,
            "signed encryption key does not match the pinned key")
    binding = (b"SCB_ATTESTATION_V1\0" + verdict_key + build_commit.encode("ascii")
               + b"\0" + PROTOCOL.encode("ascii"))
    require(type(payload["user_data"]) is bytes and payload["user_data"] == binding,
            "signed verdict key, source commit, or protocol binding mismatch")
    now = time.time()
    timestamp = payload["timestamp"] / 1000
    require(-FUTURE_SKEW_SECONDS <= now - timestamp <= MAX_AGE_SECONDS,
            "attestation document is stale or from the future")
    key = verify_chain(payload, now)
    signed = cbor2.dumps(["Signature1", protected, b"", payload_raw])
    der_signature = utils.encode_dss_signature(
        int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big"))
    try:
        key.verify(der_signature, signed, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise VerificationError("attestation COSE signature is invalid") from exc
    return {
        "verified": True, "protocol": PROTOCOL, "attestation_version": 1,
        "pcr0": pcr0.hex(), "enclave_enc_pubkey_hex": enc_key.hex(),
        "verdict_pubkey_hex": verdict_key.hex(), "build_commit": build_commit,
        "module_id": payload["module_id"], "timestamp_ms": payload["timestamp"],
        "document_sha384": hashlib.sha384(document).hexdigest(),
        "trust_root_der_sha256": ROOT_DER_SHA256,
    }


def hex_bytes(value, size, label):
    require(re.fullmatch(r"[0-9a-fA-F]{" + str(2 * size) + r"}", value) is not None,
            f"{label} must be {2 * size} hexadecimal characters")
    return bytes.fromhex(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="full HTTPS /internal/attestation URL")
    parser.add_argument("--pcr0", required=True, help="reviewed release PCR0, 96 hex characters")
    parser.add_argument("--encryption-key", required=True, help="pinned Config encryption key, 64 hex")
    parser.add_argument("--verdict-key", required=True, help="pinned Config verdict key, 64 hex")
    parser.add_argument("--build-commit", required=True, help="reviewed Git commit, 40 lowercase hex")
    parser.add_argument("--allow-development-build", action="store_true",
                        help="explicitly allow a dirty commit or 'development'; never a release approval")
    parser.add_argument("--allow-loopback-http", action="store_true",
                        help="allow HTTP through an SSH tunnel at a literal loopback IP")
    args = parser.parse_args()
    try:
        pcr0 = hex_bytes(args.pcr0, 48, "PCR0")
        require(pcr0 != bytes(48) and pcr0 != b"\xff" * 48, "placeholder/debug PCR0 is forbidden")
        enc_key = hex_bytes(args.encryption_key, 32, "encryption key")
        verdict_key = hex_bytes(args.verdict_key, 32, "verdict key")
        require(any(enc_key) and any(verdict_key), "placeholder application keys are forbidden")
        release = re.fullmatch(r"[0-9a-f]{40}", args.build_commit) is not None
        development = (args.build_commit == "development"
                       or re.fullmatch(r"[0-9a-f]{40}-dirty", args.build_commit) is not None)
        require(release or (args.allow_development_build and development),
                "a clean release commit is required; development requires an explicit flag")
        nonce = secrets.token_bytes(32)
        started = time.monotonic()
        response = fetch(args.url, nonce, args.allow_loopback_http)
        require(time.monotonic() - started <= 30, "attestation challenge round trip exceeded 30 seconds")
        report = verify_response(response, nonce, pcr0, enc_key, verdict_key, args.build_commit)
        report["development_build"] = not release
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (VerificationError, OSError, ValueError, urllib.error.URLError,
            subprocess.TimeoutExpired, x509.DuplicateExtension) as exc:
        print(f"Attestation verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
