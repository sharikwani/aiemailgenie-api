import os
import json
from typing import Optional, Tuple, Dict, Any

import requests
import stripe
from fastapi import APIRouter, Request, HTTPException


router = APIRouter()

# -----------------------------
# Stripe config
# -----------------------------
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "").strip()
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

# -----------------------------
# Worker DB API config
# -----------------------------
DB_API_URL = os.getenv("DB_API_URL", "").strip().rstrip("/")
DB_API_KEY = os.getenv("DB_API_KEY", "").strip()

# -----------------------------
# Email config (Resend)
# -----------------------------
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
FROM_EMAIL = os.getenv("FROM_EMAIL", "license@aiemailgenie.com").strip()


def _require_env_or_500():
    if not stripe.api_key:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY not set")
    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not set")
    if not DB_API_URL or not DB_API_KEY:
        raise HTTPException(status_code=500, detail="DB_API_URL / DB_API_KEY not set")


def _worker_post(path: str, payload: Dict[str, Any], timeout: int = 15) -> Dict[str, Any]:
    url = f"{DB_API_URL}{path}"
    try:
        r = requests.post(
            url,
            json=payload,
            headers={"X-DB-KEY": DB_API_KEY, "Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Worker DB API unreachable: {str(e)}")

    if r.status_code >= 400:
        # expose minimal debug info
        try:
            raise HTTPException(status_code=r.status_code, detail=r.json())
        except Exception:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    return r.json()


def _send_license_email_resend(to_email: str, license_key: str, plan_name: str) -> None:
    """
    Best-effort email: never raises to break Stripe fulfillment.
    """
    if not RESEND_API_KEY:
        return
    if not to_email:
        return

    subject = "Your AI Mail Genie Pro License Key"
    html = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.4;">
      <h2>Welcome to AI Mail Genie {plan_name.upper()}</h2>
      <p>Here is your license key:</p>
      <div style="padding:12px;border:1px solid #ddd;border-radius:8px;display:inline-block;">
        <code style="font-size:16px;font-weight:bold;">{license_key}</code>
      </div>

      <h3 style="margin-top:18px;">How to activate</h3>
      <ol>
        <li>Open Gmail</li>
        <li>Click <strong>AI Mail Genie</strong> → <strong>Settings</strong></li>
        <li>Paste the license key above</li>
      </ol>

      <p>If you need help, reply to this email.</p>
    </div>
    """

    try:
        requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "html": html,
            },
            timeout=10,
        )
    except Exception:
        return


def _resolve_plan_from_price_id(price_id: Optional[str]) -> Tuple[str, Optional[int]]:
    """
    Map Stripe price IDs to (plan_name, duration_days).

    For your stated goal (one-time Pro purchase), this can be very simple:
      - price_id == STRIPE_PRICE_ID_PRO -> ("pro", None)  # lifetime
    Or set STRIPE_PRO_DURATION_DAYS for time-limited Pro.

    You can expand later for multiple products.
    """
    pro_price = os.getenv("STRIPE_PRICE_ID_PRO", "").strip()
    pro_days_raw = os.getenv("STRIPE_PRO_DURATION_DAYS", "").strip()  # e.g. "365" or ""

    if pro_price and price_id == pro_price:
        if pro_days_raw:
            try:
                days = int(pro_days_raw)
                if days > 0:
                    return "pro", days
            except Exception:
                pass
        return "pro", None  # lifetime by default

    # Fallback: if you only sell one product, still treat as Pro
    return "pro", None


def _get_customer_email(session_obj: Dict[str, Any]) -> str:
    # Stripe can provide email in a few places
    cd = session_obj.get("customer_details") or {}
    email = cd.get("email") or session_obj.get("customer_email") or ""
    return (email or "").strip().lower()


def _get_first_price_id(session_obj: Dict[str, Any]) -> Optional[str]:
    """
    Requires session with line_items expanded.
    """
    line_items = session_obj.get("line_items") or {}
    data = line_items.get("data") or []
    if not data:
        return None

    first = data[0] or {}
    price = first.get("price") or {}
    return price.get("id")


@router.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    """
    Stripe webhook handler:
      - verify signature
      - handle checkout.session.completed
      - create license in Worker
      - email license to customer
    """
    _require_env_or_500()

    payload_bytes = await request.body()
    sig = request.headers.get("stripe-signature")

    if not sig:
        raise HTTPException(status_code=400, detail="Missing Stripe signature header")

    # Verify and parse event
    try:
        event = stripe.Webhook.construct_event(payload_bytes, sig, WEBHOOK_SECRET)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Only handle Checkout completion
    if event.get("type") != "checkout.session.completed":
        return {"ok": True, "ignored": True, "type": event.get("type")}

    session = event.get("data", {}).get("object", {}) or {}
    session_id = session.get("id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session id")

    # Retrieve full session with line_items expanded (reliable price_id source)
    try:
        full_session = stripe.checkout.Session.retrieve(
            session_id,
            expand=["line_items.data.price"],
        )
        # stripe returns a StripeObject; convert to plain dict safely
        full_session_dict = json.loads(str(full_session))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to retrieve session: {str(e)}")

    customer_email = _get_customer_email(full_session_dict)
    price_id = _get_first_price_id(full_session_dict)
    plan_name, duration_days = _resolve_plan_from_price_id(price_id)

    # Create license in Worker
    worker_payload = {
        "email": customer_email,
        "plan": plan_name,
        "duration_days": duration_days,     # None => lifetime
        "max_devices": None,                # your Worker ignores per-license; plan defines it
        "daily_limit": None,                # your Worker ignores per-license; plan defines it
        "stripe_session_id": session_id,    # currently ignored by Worker (safe to send)
        "stripe_price_id": price_id,        # currently ignored by Worker (safe to send)
    }

    lic = _worker_post("/admin/license/create", worker_payload, timeout=15)
    license_key = (lic.get("license_key") or "").strip()
    if not license_key:
        raise HTTPException(status_code=502, detail="Worker did not return a license_key")

    # Send license email (best-effort; does not block Stripe 200)
    _send_license_email_resend(customer_email, license_key, plan_name)

    return {
        "ok": True,
        "event": "checkout.session.completed",
        "plan": plan_name,
        "license_key_created": True,
    }
