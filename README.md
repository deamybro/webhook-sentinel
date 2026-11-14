# WebhookSentinel 🛡️
> Production-grade Webhook Inspector, HMAC Cryptographic Signature Validator, and Mock Replay Engine.

Zero external runtime dependencies. Built in pure, high-performance Python 3.10+.

---

## 🌟 Why WebhookSentinel?

Webhooks are the backbone of modern payment and event-driven architectures (**Stripe, GitHub, Shopify, LemonSqueezy, Paddle**). Yet developing and debugging them is notoriously painful:

- **Cryptographic Signature Errors**: One misplaced character or parsing the raw JSON before checking the signature causes immediate HMAC validation failure.
- **Replay Attacks**: Forgetting timestamp tolerance windows exposes endpoints to replay vulnerabilities.
- **Testing Without Live Payments**: Triggering actual test cards in Stripe to test webhook handlers is slow and brittle.
- **Lost Webhooks**: When local servers crash, replaying the exact failed event is near impossible without paid services like Hookdeck or Svix.

**WebhookSentinel** solves all of this locally with zero monthly fees.

---

## 🚀 Key Features

| Capability | Description |
| :--- | :--- |
| **Multi-Provider Verification** | Native HMAC SHA-256 validation for **Stripe** (`Stripe-Signature`), **GitHub** (`X-Hub-Signature-256`), **Shopify** (`X-Shopify-Hmac-Sha256`), and generic HMAC. |
| **Replay Attack Defense** | Strict timestamp tolerance enforcement (configurable tolerance window) using constant-time digest comparisons (`hmac.compare_digest`). |
| **Signed Mock Dispatcher** | Synthesizes realistic, cryptographically signed webhook payloads to test your local API (`http://localhost:8000/webhook`) in unit tests or CI/CD pipelines. |
| **Event Persistence & Replay** | Automatically logs all received webhooks to local SQLite, enabling instant one-click event replaying against any target URL. |
| **Local Receiver Daemon** | In-process HTTP daemon to catch, inspect, and verify incoming webhooks on any local port. |

---

## 📦 Quickstart

### Installation
No external libraries needed! Just clone and run:

```bash
git clone https://github.com/deamybro/webhook-sentinel.git
cd webhook-sentinel
pip install -r requirements.txt
```

---

## 💻 CLI Commands

### 1. Verify a Webhook Payload Offline
Diagnose exactly why a webhook signature failed:
```bash
python -m src.cli verify \
  --provider stripe \
  --secret whsec_your_signing_secret \
  --signature "t=1700000000,v1=52571868e30f9a..." \
  --body payload.json
```

### 2. Send a Signed Mock Webhook to Local API
Simulate authentic Stripe or GitHub events during development:
```bash
# Fire a signed Stripe payment_intent.succeeded event
python -m src.cli mock \
  --target http://localhost:8000/api/stripe/webhook \
  --provider stripe \
  --secret whsec_test_secret \
  --event payment_intent.succeeded

# Fire a signed GitHub push event
python -m src.cli mock \
  --target http://localhost:8000/api/github/webhook \
  --provider github \
  --secret my_gh_secret \
  --event push
```

### 3. Start Local Receiver Server
Listen for incoming webhooks and verify them in real time:
```bash
python -m src.cli listen --port 9000 --provider stripe --secret whsec_test_key
```

### 4. Inspect & Replay Webhooks
```bash
# List captured webhooks
python -m src.cli list

# Inspect payload and headers
python -m src.cli inspect evt_4a1b2c3d4e5f

# Replay an event to your backend
python -m src.cli replay evt_4a1b2c3d4e5f --target http://localhost:8000/webhook
```

---

## 🐍 Python Library Usage

Integrate HMAC verification directly into your **FastAPI, Flask, or Django** backend:

```python
from src.signatures.verifier import WebhookVerifier

# In your FastAPI route handler:
# Note: Always pass raw request body bytes, NOT parsed JSON!
raw_body: bytes = await request.body()
signature_header = request.headers.get("Stripe-Signature")

result = WebhookVerifier.verify_stripe(
    raw_body=raw_body,
    secret="whsec_12345",
    stripe_signature_header=signature_header,
    tolerance_seconds=300
)

if not result.is_valid:
    print(f"Rejected: {result.reason}")
    return {"error": result.reason}, 400

print("Signature verified successfully!")
```

---

## 🧪 Automated Testing

```bash
pytest -v
```
All unit tests for Stripe, GitHub, Shopify, SQLite persistence, and mock dispatching pass cleanly.
