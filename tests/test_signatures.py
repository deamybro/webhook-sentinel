"""Unit tests for cryptographic signature verification and generation."""

import time
from src.signatures.signer import WebhookSigner
from src.signatures.verifier import WebhookVerifier


def test_stripe_signature_flow():
    secret = "whsec_test_secret_key_12345"
    payload = b'{"id":"evt_123","type":"payment_intent.succeeded"}'

    # 1. Sign
    sig_header = WebhookSigner.sign_stripe(payload, secret)
    assert sig_header.startswith("t=")
    assert ",v1=" in sig_header

    # 2. Verify (Valid)
    res = WebhookVerifier.verify_stripe(payload, secret, sig_header, tolerance_seconds=300)
    assert res.is_valid is True

    # 3. Verify with wrong secret (Must fail)
    res_wrong_secret = WebhookVerifier.verify_stripe(payload, "whsec_wrong_key", sig_header)
    assert res_wrong_secret.is_valid is False
    assert "mismatch" in res_wrong_secret.reason.lower()

    # 4. Verify with tampered body (Must fail)
    tampered_payload = b'{"id":"evt_123","type":"payment_intent.failed"}'
    res_tampered = WebhookVerifier.verify_stripe(tampered_payload, secret, sig_header)
    assert res_tampered.is_valid is False


def test_stripe_replay_attack_prevention():
    secret = "whsec_replay_test"
    payload = b'{"event":"charge.refunded"}'

    # Sign with a timestamp 10 minutes (600s) in the past
    past_timestamp = int(time.time()) - 600
    old_sig = WebhookSigner.sign_stripe(payload, secret, timestamp=past_timestamp)

    # Verification with 300s tolerance window must be rejected
    res = WebhookVerifier.verify_stripe(payload, secret, old_sig, tolerance_seconds=300)
    assert res.is_valid is False
    assert "tolerance" in res.reason.lower()


def test_github_signature_flow():
    secret = "gh_webhook_secret_999"
    payload = b'{"action":"opened","issue":{"number":42}}'

    sig = WebhookSigner.sign_github(payload, secret)
    assert sig.startswith("sha256=")

    # Valid check
    res = WebhookVerifier.verify_github(payload, secret, sig)
    assert res.is_valid is True

    # Tampered check
    res_tampered = WebhookVerifier.verify_github(payload + b" ", secret, sig)
    assert res_tampered.is_valid is False


def test_shopify_signature_flow():
    secret = "shpss_secret_12345"
    payload = b'{"order_id":987654,"total_price":"250.00"}'

    sig = WebhookSigner.sign_shopify(payload, secret)

    # Valid check
    res = WebhookVerifier.verify_shopify(payload, secret, sig)
    assert res.is_valid is True

    # Bad signature
    res_bad = WebhookVerifier.verify_shopify(payload, secret, "invalid_base64_sig")
    assert res_bad.is_valid is False


def test_generic_hmac():
    secret = "custom_auth_token"
    payload = b'{"user_id":"usr_abc"}'

    sig = WebhookSigner.sign_generic(payload, secret, algorithm="sha256")
    res = WebhookVerifier.verify_generic_hmac(payload, secret, sig)
    assert res.is_valid is True
