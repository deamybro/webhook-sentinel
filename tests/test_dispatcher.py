"""Integration tests for WebhookDispatcher against a mock HTTP server."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from src.dispatcher import WebhookDispatcher
from src.signatures.verifier import WebhookVerifier
from src.storage import EventStore


class MockReceiver(BaseHTTPRequestHandler):
    received_requests = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        MockReceiver.received_requests.append({
            "headers": dict(self.headers),
            "body": body,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"received":true}')

    def log_message(self, format, *args):
        pass


def test_mock_dispatch_flow(tmp_path: Path):
    MockReceiver.received_requests.clear()
    server = HTTPServer(("127.0.0.1", 0), MockReceiver)
    port = server.server_address[1]

    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()

    try:
        db_file = tmp_path / "dispatch_test.db"
        store = EventStore(db_path=db_file)
        dispatcher = WebhookDispatcher(store=store)

        secret = "whsec_mock_test_key"
        target_url = f"http://127.0.0.1:{port}/webhook"

        # Send mock Stripe event
        res = dispatcher.send_mock(
            target_url=target_url,
            provider="stripe",
            secret=secret,
            event_type="payment_intent.succeeded",
        )

        assert res.success is True
        assert res.status_code == 200
        assert len(MockReceiver.received_requests) == 1

        req = MockReceiver.received_requests[0]
        sig_header = req["headers"].get("Stripe-Signature")
        assert sig_header is not None

        # Verify signature on the receiver side
        verify_result = WebhookVerifier.verify_stripe(req["body"], secret, sig_header)
        assert verify_result.is_valid is True

    finally:
        server.shutdown()
        server.server_close()
