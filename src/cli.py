"""Command Line Interface for WebhookSentinel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.dispatcher import WebhookDispatcher
from src.receiver import run_receiver
from src.signatures.verifier import WebhookVerifier
from src.storage import EventStore


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="webhook-sentinel",
        description="Production-grade Webhook Inspector, HMAC Validator, and Mock Dispatcher.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: verify
    verify_p = subparsers.add_parser("verify", help="Verify signature of a raw webhook payload")
    verify_p.add_argument("--provider", choices=["stripe", "github", "shopify", "generic"], default="stripe")
    verify_p.add_argument("--secret", required=True, help="Webhook signing secret")
    verify_p.add_argument("--signature", required=True, help="Header signature string to verify")
    verify_p.add_argument("--body", required=True, help="Path to raw payload file or inline string")

    # Subcommand: mock
    mock_p = subparsers.add_parser("mock", help="Send a cryptographically signed mock webhook to a target URL")
    mock_p.add_argument("--target", required=True, help="Target URL (e.g. http://localhost:8000/webhook)")
    mock_p.add_argument("--provider", choices=["stripe", "github", "shopify", "generic"], default="stripe")
    mock_p.add_argument("--secret", required=True, help="Signing secret")
    mock_p.add_argument("--event", default="payment_intent.succeeded", help="Event name (e.g. invoice.paid, push)")
    mock_p.add_argument("--payload", default=None, help="Optional custom JSON file or inline string")

    # Subcommand: listen
    listen_p = subparsers.add_parser("listen", help="Start local webhook receiver daemon")
    listen_p.add_argument("-p", "--port", type=int, default=9000, help="Local port to bind")
    listen_p.add_argument("--provider", choices=["stripe", "github", "shopify", "generic"], default=None)
    listen_p.add_argument("--secret", default=None, help="Secret to verify incoming signatures")

    # Subcommand: list
    list_p = subparsers.add_parser("list", help="List captured webhook events")
    list_p.add_argument("-n", "--limit", type=int, default=20, help="Max events to display")

    # Subcommand: inspect
    inspect_p = subparsers.add_parser("inspect", help="Display full headers and payload of an event")
    inspect_p.add_argument("event_id", help="Event ID to inspect")

    # Subcommand: replay
    replay_p = subparsers.add_parser("replay", help="Replay a captured event to a destination target")
    replay_p.add_argument("event_id", help="Event ID to replay")
    replay_p.add_argument("--target", required=True, help="Destination target URL")
    replay_p.add_argument("--re-sign-secret", default=None, help="Optional new secret to re-sign timestamp and HMAC")

    args = parser.parse_args()
    store = EventStore()
    dispatcher = WebhookDispatcher(store=store)

    if args.command == "verify":
        # Load body bytes
        if Path(args.body).exists():
            body_bytes = Path(args.body).read_bytes()
        else:
            body_bytes = args.body.encode("utf-8")

        if args.provider == "stripe":
            res = WebhookVerifier.verify_stripe(body_bytes, args.secret, args.signature)
        elif args.provider == "github":
            res = WebhookVerifier.verify_github(body_bytes, args.secret, args.signature)
        elif args.provider == "shopify":
            res = WebhookVerifier.verify_shopify(body_bytes, args.secret, args.signature)
        else:
            res = WebhookVerifier.verify_generic_hmac(body_bytes, args.secret, args.signature)

        print(f"Status: {'[VALID]' if res.is_valid else '[INVALID]'}")
        print(f"Reason: {res.reason}")
        if res.details:
            print(f"Details: {json.dumps(res.details, indent=2)}")
        sys.exit(0 if res.is_valid else 1)

    elif args.command == "mock":
        custom_data = None
        if args.payload:
            if Path(args.payload).exists():
                custom_data = json.loads(Path(args.payload).read_text(encoding="utf-8"))
            else:
                custom_data = json.loads(args.payload)

        print(f"Dispatching mock {args.provider.upper()} webhook to: {args.target}")
        result = dispatcher.send_mock(
            target_url=args.target,
            provider=args.provider,
            secret=args.secret,
            event_type=args.event,
            payload_data=custom_data,
        )

        if result.success:
            print(f"Success! Response HTTP {result.status_code}")
            print(f"Body: {result.response_body[:200]}")
        else:
            print(f"Failed! HTTP {result.status_code} - {result.error_message}")
            if result.response_body:
                print(f"Response: {result.response_body[:200]}")
            sys.exit(1)

    elif args.command == "listen":
        run_receiver(port=args.port, secret=args.secret, provider=args.provider)

    elif args.command == "list":
        events = store.list_events(limit=args.limit)
        if not events:
            print("No recorded webhook events found.")
            return

        print(f"{'EVENT ID':<18} {'PROVIDER':<10} {'EVENT TYPE':<24} {'VERIFIED':<10} {'RECEIVED AT'}")
        print("-" * 80)
        for e in events:
            v_str = "YES" if e["verified"] else "NO"
            print(f"{e['id']:<18} {e['provider']:<10} {e['event_type'][:22]:<24} {v_str:<10} {e['received_at'][:19]}")

    elif args.command == "inspect":
        evt = store.get_event(args.event_id)
        if not evt:
            print(f"Error: Event '{args.event_id}' not found.")
            sys.exit(1)

        print(f"Event ID: {evt['id']}")
        print(f"Provider: {evt['provider']}")
        print(f"Type: {evt['event_type']}")
        print(f"Verified: {evt['verified']}")
        print(f"Received At: {evt['received_at']}\n")
        print("Headers:")
        print(json.dumps(evt["headers"], indent=2))
        print("\nPayload:")
        print(evt["payload"])

    elif args.command == "replay":
        try:
            print(f"Replaying event '{args.event_id}' to: {args.target}")
            res = dispatcher.replay_event(
                event_id=args.event_id,
                target_url=args.target,
                re_sign_secret=args.re_sign_secret,
            )
            print(f"Result: HTTP {res.status_code} ({'SUCCESS' if res.success else 'FAILED'})")
            if res.response_body:
                print(f"Body: {res.response_body[:200]}")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
