"""Cryptographic webhook signature verifier supporting Stripe, GitHub, Shopify, and generic HMAC."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Optional, Tuple


class SignatureVerificationResult:
    def __init__(self, is_valid: bool, reason: str, details: Optional[dict] = None):
        self.is_valid = is_valid
        self.reason = reason
        self.details = details or {}

    def __bool__(self) -> bool:
        return self.is_valid

    def __repr__(self) -> str:
        status = "VALID" if self.is_valid else "INVALID"
        return f"<SignatureVerificationResult [{status}]: {self.reason}>"


class WebhookVerifier:
    @staticmethod
    def verify_generic_hmac(
        raw_body: bytes,
        secret: str,
        received_signature: str,
        algorithm: str = "sha256",
        encoding: str = "hex",
    ) -> SignatureVerificationResult:
        """Verify standard HMAC signature."""
        if not secret:
            return SignatureVerificationResult(False, "Webhook secret is empty or missing.")

        hash_func = getattr(hashlib, algorithm.lower(), None)
        if not hash_func:
            return SignatureVerificationResult(False, f"Unsupported hash algorithm: {algorithm}")

        mac = hmac.new(secret.encode("utf-8"), raw_body, hash_func)

        if encoding == "base64":
            expected = base64.b64encode(mac.digest()).decode("utf-8")
        else:
            expected = mac.hexdigest()

        # Clean prefix like 'sha256=' if passed
        clean_received = received_signature.strip()
        if "=" in clean_received:
            clean_received = clean_received.split("=", 1)[1]

        if hmac.compare_digest(expected, clean_received):
            return SignatureVerificationResult(True, "HMAC signature verified successfully.")

        return SignatureVerificationResult(
            False,
            "Signature mismatch. Verify your webhook signing secret and ensure raw unparsed body is used.",
            {"expected_prefix": expected[:8] + "...", "received_prefix": clean_received[:8] + "..."},
        )

    @staticmethod
    def verify_stripe(
        raw_body: bytes,
        secret: str,
        stripe_signature_header: str,
        tolerance_seconds: int = 300,
    ) -> SignatureVerificationResult:
        """Verify Stripe webhook signature (Stripe-Signature: t=...,v1=...).

        Implements Stripe's canonical verification scheme:
        1. Extract timestamp t and signature v1
        2. Prevent replay attacks via tolerance window
        3. Compute HMAC-SHA256 of '{timestamp}.{raw_body}'
        """
        if not stripe_signature_header:
            return SignatureVerificationResult(False, "Missing Stripe-Signature header.")

        elements = stripe_signature_header.split(",")
        timestamp: Optional[int] = None
        signatures: list[str] = []

        for item in elements:
            parts = item.strip().split("=", 1)
            if len(parts) == 2:
                key, val = parts[0].strip(), parts[1].strip()
                if key == "t":
                    try:
                        timestamp = int(val)
                    except ValueError:
                        return SignatureVerificationResult(False, f"Malformed timestamp in header: {val}")
                elif key == "v1":
                    signatures.append(val)

        if timestamp is None:
            return SignatureVerificationResult(False, "Missing timestamp 't' in Stripe-Signature header.")

        if not signatures:
            return SignatureVerificationResult(False, "Missing v1 signature in Stripe-Signature header.")

        # Timestamp tolerance verification (prevents replay attacks)
        current_time = int(time.time())
        age = current_time - timestamp
        if tolerance_seconds > 0 and abs(age) > tolerance_seconds:
            return SignatureVerificationResult(
                False,
                f"Timestamp outside tolerance window. Event age is {age}s (tolerance: {tolerance_seconds}s). Possible replay attack.",
                {"event_timestamp": timestamp, "current_time": current_time, "age_seconds": age},
            )

        # Compute expected signature: HMAC_SHA256(secret, "{timestamp}.{raw_body}")
        signed_payload = f"{timestamp}.".encode("utf-8") + raw_body
        expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

        for sig in signatures:
            if hmac.compare_digest(expected, sig):
                return SignatureVerificationResult(
                    True,
                    "Stripe signature verified successfully.",
                    {"timestamp": timestamp, "verified_v1": sig[:8] + "..."},
                )

        return SignatureVerificationResult(
            False,
            "Stripe v1 signature mismatch. Verify secret and raw body encoding.",
            {"expected": expected[:8] + "...", "received_candidates": [s[:8] + "..." for s in signatures]},
        )

    @staticmethod
    def verify_github(
        raw_body: bytes,
        secret: str,
        github_signature_header: str,
    ) -> SignatureVerificationResult:
        """Verify GitHub webhook (X-Hub-Signature-256: sha256=...)."""
        if not github_signature_header:
            return SignatureVerificationResult(False, "Missing X-Hub-Signature-256 header.")

        if not github_signature_header.startswith("sha256="):
            return SignatureVerificationResult(False, "GitHub signature header must begin with 'sha256=' prefix.")

        received_hash = github_signature_header[len("sha256="):].strip()
        expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()

        if hmac.compare_digest(expected, received_hash):
            return SignatureVerificationResult(True, "GitHub webhook signature verified successfully.")

        return SignatureVerificationResult(
            False,
            "GitHub signature mismatch. Ensure raw body bytes were not transformed.",
            {"expected": expected[:8] + "...", "received": received_hash[:8] + "..."},
        )

    @staticmethod
    def verify_shopify(
        raw_body: bytes,
        secret: str,
        shopify_hmac_header: str,
    ) -> SignatureVerificationResult:
        """Verify Shopify webhook (X-Shopify-Hmac-Sha256: base64(hmac_sha256))."""
        if not shopify_hmac_header:
            return SignatureVerificationResult(False, "Missing X-Shopify-Hmac-Sha256 header.")

        mac = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256)
        expected = base64.b64encode(mac.digest()).decode("utf-8")

        received = shopify_hmac_header.strip()
        if hmac.compare_digest(expected, received):
            return SignatureVerificationResult(True, "Shopify webhook HMAC verified successfully.")

        return SignatureVerificationResult(
            False,
            "Shopify HMAC signature mismatch.",
            {"expected": expected[:8] + "...", "received": received[:8] + "..."},
        )
