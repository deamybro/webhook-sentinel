"""Cryptographic webhook signer for generating authentic test payloads and headers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Optional


class WebhookSigner:
    @staticmethod
    def sign_stripe(
        raw_body: bytes,
        secret: str,
        timestamp: Optional[int] = None,
    ) -> str:
        """Generate a valid Stripe-Signature header (t=...,v1=...)."""
        ts = int(time.time()) if timestamp is None else timestamp
        signed_payload = f"{ts}.".encode("utf-8") + raw_body
        signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
        return f"t={ts},v1={signature}"

    @staticmethod
    def sign_github(
        raw_body: bytes,
        secret: str,
    ) -> str:
        """Generate a valid GitHub X-Hub-Signature-256 header (sha256=...)."""
        signature = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        return f"sha256={signature}"

    @staticmethod
    def sign_shopify(
        raw_body: bytes,
        secret: str,
    ) -> str:
        """Generate a valid Shopify X-Shopify-Hmac-Sha256 header (base64 string)."""
        mac = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256)
        return base64.b64encode(mac.digest()).decode("utf-8")

    @staticmethod
    def sign_generic(
        raw_body: bytes,
        secret: str,
        algorithm: str = "sha256",
        encoding: str = "hex",
    ) -> str:
        """Generate a generic HMAC signature."""
        hash_func = getattr(hashlib, algorithm.lower(), hashlib.sha256)
        mac = hmac.new(secret.encode("utf-8"), raw_body, hash_func)
        if encoding == "base64":
            return base64.b64encode(mac.digest()).decode("utf-8")
        return mac.hexdigest()
