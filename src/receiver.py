"""Local webhook receiver server for capturing, inspecting, and verifying events in real time."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from src.signatures.verifier import SignatureVerificationResult, WebhookVerifier
from src.storage import EventStore


class WebhookReceiverHandler(BaseHTTPRequestHandler):
    store: EventStore
    secret: Optional[str] = None
    provider: Optional[str] = None

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)

        headers_dict = {k: v for k, v in self.headers.items()}
        prov = (self.provider or self._sniff_provider(headers_dict)).lower()

        verification: Optional[SignatureVerificationResult] = None

        if self.secret:
            if prov == "stripe":
                sig = headers_dict.get("Stripe-Signature", "")
                verification = WebhookVerifier.verify_stripe(raw_body, self.secret, sig)
            elif prov == "github":
                sig = headers_dict.get("X-Hub-Signature-256", "")
                verification = WebhookVerifier.verify_github(raw_body, self.secret, sig)
            elif prov == "shopify":
                sig = headers_dict.get("X-Shopify-Hmac-Sha256", "")
                verification = WebhookVerifier.verify_shopify(raw_body, self.secret, sig)
            else:
                sig = headers_dict.get("X-Webhook-Signature", "")
                verification = WebhookVerifier.verify_generic_hmac(raw_body, self.secret, sig)

        verified_flag = verification.is_valid if verification else True

        # Store in event database
        body_text = raw_body.decode("utf-8", errors="replace")
        event_id = self.store.save_event(
            provider=prov,
            headers=headers_dict,
            payload=body_text,
            verified=verified_flag,
        )

        status_text = "VERIFIED" if verified_flag else "REJECTED"
        print(f"[{status_text}] {prov.upper()} Webhook captured -> Event ID: {event_id}")

        if verification and not verification.is_valid:
            print(f"       Warning: {verification.reason}")
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = json.dumps({"status": "rejected", "reason": verification.reason, "event_id": event_id})
            self.wfile.write(resp.encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = json.dumps({"status": "received", "event_id": event_id})
        self.wfile.write(resp.encode("utf-8"))

    def _sniff_provider(self, headers: dict[str, str]) -> str:
        """Autodetect provider based on distinct signature headers."""
        if "Stripe-Signature" in headers:
            return "stripe"
        if "X-Hub-Signature-256" in headers or "X-GitHub-Event" in headers:
            return "github"
        if "X-Shopify-Hmac-Sha256" in headers or "X-Shopify-Topic" in headers:
            return "shopify"
        return "generic"

    def log_message(self, format: str, *args) -> None:
        # Suppress default noisy access logs to keep CLI clean
        pass


def run_receiver(
    port: int = 9000,
    secret: Optional[str] = None,
    provider: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    """Start local webhook receiver daemon."""
    store = EventStore(db_path=db_path)
    WebhookReceiverHandler.store = store
    WebhookReceiverHandler.secret = secret
    WebhookReceiverHandler.provider = provider

    server = HTTPServer(("0.0.0.0", port), WebhookReceiverHandler)
    print(f"🛡️  WebhookSentinel listening on http://localhost:{port}")
    if provider:
        print(f"   Provider: {provider.upper()}")
    if secret:
        print(f"   Signature Verification: ENABLED (Secret: {'*' * 6})")
    else:
        print("   Signature Verification: DISABLED (Recording all payloads)")
    print("   Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping receiver...")
        server.server_close()
