"""Webhook dispatcher for firing mock events and replaying recorded webhooks."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from src.signatures.signer import WebhookSigner
from src.storage import EventStore


class DispatchResult:
    def __init__(
        self,
        success: bool,
        status_code: int,
        response_body: str,
        sent_headers: Dict[str, str],
        error_message: Optional[str] = None,
    ):
        self.success = success
        self.status_code = status_code
        self.response_body = response_body
        self.sent_headers = sent_headers
        self.error_message = error_message

    def __repr__(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return f"<DispatchResult [{status} HTTP {self.status_code}]: {self.response_body[:40]}>"


class WebhookDispatcher:
    def __init__(self, store: Optional[EventStore] = None):
        self.store = store or EventStore()

    def dispatch(
        self,
        target_url: str,
        payload: str | bytes,
        headers: Dict[str, str],
        timeout: int = 10,
    ) -> DispatchResult:
        """Send a webhook POST request to the target URL."""
        body_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

        req = urllib.request.Request(
            target_url,
            data=body_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.getcode()
                resp_text = resp.read().decode("utf-8", errors="replace")
                return DispatchResult(
                    success=(200 <= status < 300),
                    status_code=status,
                    response_body=resp_text,
                    sent_headers=headers,
                )
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            return DispatchResult(
                success=False,
                status_code=e.code,
                response_body=err_body,
                sent_headers=headers,
                error_message=f"HTTP Error {e.code}: {e.reason}",
            )
        except Exception as e:
            return DispatchResult(
                success=False,
                status_code=0,
                response_body="",
                sent_headers=headers,
                error_message=str(e),
            )

    def send_mock(
        self,
        target_url: str,
        provider: str,
        secret: str,
        event_type: str,
        payload_data: Optional[Dict[str, Any]] = None,
    ) -> DispatchResult:
        """Construct a cryptographically signed mock webhook and dispatch it."""
        prov = provider.lower()

        if payload_data is None:
            payload_data = self._get_default_mock_payload(prov, event_type)

        raw_payload = json.dumps(payload_data, separators=(",", ":"))
        payload_bytes = raw_payload.encode("utf-8")

        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "WebhookSentinel/1.0",
        }

        if prov == "stripe":
            headers["Stripe-Signature"] = WebhookSigner.sign_stripe(payload_bytes, secret)
        elif prov == "github":
            headers["X-Hub-Signature-256"] = WebhookSigner.sign_github(payload_bytes, secret)
            headers["X-GitHub-Event"] = event_type
        elif prov == "shopify":
            headers["X-Shopify-Hmac-Sha256"] = WebhookSigner.sign_shopify(payload_bytes, secret)
            headers["X-Shopify-Topic"] = event_type
        else:
            headers["X-Webhook-Signature"] = WebhookSigner.sign_generic(payload_bytes, secret)

        # Dispatch and optionally record event
        result = self.dispatch(target_url, payload_bytes, headers)
        self.store.save_event(prov, headers, raw_payload, verified=True, event_type=event_type)
        return result

    def replay_event(
        self,
        event_id: str,
        target_url: str,
        re_sign_secret: Optional[str] = None,
    ) -> DispatchResult:
        """Replay an already recorded event to a target destination."""
        evt = self.store.get_event(event_id)
        if not evt:
            raise ValueError(f"Event ID '{event_id}' not found in store.")

        headers = dict(evt["headers"])
        payload = evt["payload"]
        prov = evt["provider"]

        # If re_sign_secret is provided, refresh the timestamp & signature
        if re_sign_secret:
            payload_bytes = payload.encode("utf-8")
            if prov == "stripe":
                headers["Stripe-Signature"] = WebhookSigner.sign_stripe(payload_bytes, re_sign_secret)
            elif prov == "github":
                headers["X-Hub-Signature-256"] = WebhookSigner.sign_github(payload_bytes, re_sign_secret)
            elif prov == "shopify":
                headers["X-Shopify-Hmac-Sha256"] = WebhookSigner.sign_shopify(payload_bytes, re_sign_secret)
            else:
                headers["X-Webhook-Signature"] = WebhookSigner.sign_generic(payload_bytes, re_sign_secret)

        return self.dispatch(target_url, payload, headers)

    def _get_default_mock_payload(self, provider: str, event_type: str) -> Dict[str, Any]:
        """Generate realistic mock payload structures."""
        if provider == "stripe":
            return {
                "id": f"evt_mock_{event_type.replace('.', '_')}",
                "object": "event",
                "api_version": "2024-04-10",
                "type": event_type,
                "data": {
                    "object": {
                        "id": "pi_1234567890",
                        "object": "payment_intent",
                        "amount": 2500,
                        "currency": "usd",
                        "status": "succeeded",
                    }
                },
            }
        elif provider == "github":
            return {
                "action": event_type,
                "repository": {
                    "full_name": "example/project",
                    "html_url": "https://github.com/example/project",
                },
                "sender": {"login": "octocat", "id": 1},
            }
        elif provider == "shopify":
            return {
                "id": 820982911946154508,
                "email": "customer@example.com",
                "total_price": "149.99",
                "currency": "USD",
                "financial_status": "paid",
            }
        return {"event": event_type, "timestamp": 1700000000, "status": "active"}
