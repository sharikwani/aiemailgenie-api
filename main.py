import os
import re
from typing import List, Optional, Dict, Any, Literal, Tuple
from urllib.parse import quote

import requests
import stripe
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from openai import OpenAI


# =============================================================================
# AI Mail Genie Server (FastAPI)
# =============================================================================

Verdict = Literal["SAFE", "CAUTION", "HIGH RISK"]
PlanMode = Literal["free", "pro"]


# -----------------------------
# OpenAI / App init
# -----------------------------
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

app = FastAPI(title="AI Mail Genie AI API", version="3.3.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DEV ONLY (lock down later)
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


# -----------------------------
# Cloudflare Worker DB API (D1 Gateway)
# -----------------------------
DB_API_URL = os.environ.get("DB_API_URL", "").strip().rstrip("/")
DB_API_KEY = os.environ.get("DB_API_KEY", "").strip()


# -----------------------------
# Stripe config
# -----------------------------
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()

# Price IDs (NOT product IDs). Add all 3 in Render env vars.
STRIPE_PRICE_PRO_MONTHLY = os.environ.get("STRIPE_PRICE_PRO_MONTHLY", "").strip()
STRIPE_PRICE_PRO_YEARLY = os.environ.get("STRIPE_PRICE_PRO_YEARLY", "").strip()
STRIPE_PRICE_PRO_LIFETIME = os.environ.get("STRIPE_PRICE_PRO_LIFETIME", "").strip()

# Stripe Billing Portal return URL (where user goes back after managing billing)
BILLING_PORTAL_RETURN_URL = os.environ.get("BILLING_PORTAL_RETURN_URL", "https://aiemailgenie.com/manage.html").strip()

# -----------------------------
# CRON secret (Option A: Render Cron hits Render endpoint)
# -----------------------------
CRON_SECRET = (os.environ.get("CRON_SECRET", "") or "").strip()


# -----------------------------
# Email delivery (Resend) - best effort
# -----------------------------
def send_license_email(
    to_email: str,
    license_key: str,
    plan_name: str = "Pro",
    session_id: str = "",
) -> None:
    """
    Sends a premium, branded license email via Resend.
    Best-effort only — never raises.

    NOTE:
      - We link user to manage.html (no long query string).
      - We also link to success.html with session_id (so it can store into localStorage).
    """
    to_email = (to_email or "").strip().lower()
    license_key = (license_key or "").strip()
    session_id = (session_id or "").strip()

    api_key = (os.environ.get("RESEND_API_KEY", "") or "").strip()
    from_email = (os.environ.get("FROM_EMAIL", "AI Mail Genie <license@aiemailgenie.com>")).strip()

    if not api_key or not to_email or "@" not in to_email or not license_key:
        return

    subject = f"Welcome to AI Mail Genie {plan_name} — Your License Is Ready"

    manage_url = "https://aiemailgenie.com/manage.html"
    success_url = "https://aiemailgenie.com/success.html"
    if session_id:
        success_url = f"https://aiemailgenie.com/success.html?session_id={quote(session_id)}"

    html = f"""
    <html>
      <body style="margin:0;padding:0;background:#0b0f14;font-family:Inter,Segoe UI,Arial,sans-serif;color:#ffffff;">
        <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
          <tr>
            <td align="center">
              <table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:16px;overflow:hidden;box-shadow:0 0 40px rgba(0,255,200,0.08);">

                <!-- HEADER -->
                <tr>
                  <td style="padding:32px;text-align:center;background:linear-gradient(135deg,#0ea5e9,#22c55e);">
                    <img src="https://aiemailgenie.com/logo.png" alt="AI Mail Genie" width="64" style="margin-bottom:12px;" />
                    <h1 style="margin:0;font-size:26px;font-weight:800;color:#041014;">
                      Welcome to AI Mail Genie {plan_name}
                    </h1>
                  </td>
                </tr>

                <!-- BODY -->
                <tr>
                  <td style="padding:32px;">
                    <p style="font-size:16px;line-height:1.6;margin-top:0;">
                      Thank you for choosing <strong>AI Mail Genie</strong>. Your purchase was successful and your license is active.
                    </p>

                    <p style="font-size:15px;color:#cbd5e1;">
                      <strong>Account email:</strong> {to_email}<br/>
                      <strong>Plan:</strong> {plan_name}
                    </p>

                    <!-- LICENSE BOX -->
                    <div style="margin:28px 0;padding:20px;border-radius:12px;background:#020617;border:1px solid #1f2937;">
                      <p style="margin:0 0 8px 0;color:#94a3b8;font-size:14px;">Your license key</p>
                      <div style="font-size:18px;font-weight:900;letter-spacing:1px;color:#22c55e;">
                        {license_key}
                      </div>
                    </div>

                    <!-- ACTION BUTTONS -->
                    <div style="margin: 18px 0 8px 0;">
                      <a href="{success_url}"
                         style="display:inline-block;padding:12px 16px;border-radius:12px;
                                background:linear-gradient(135deg,#0ea5e9,#22c55e);
                                color:#041014;font-weight:900;text-decoration:none;margin-right:10px;">
                        Open Success Page
                      </a>

                      <a href="{manage_url}"
                         style="display:inline-block;padding:12px 16px;border-radius:12px;
                                border:1px solid #1f2937;background:#0b1220;color:#e5e7eb;
                                font-weight:800;text-decoration:none;">
                        Manage License
                      </a>
                    </div>

                    <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.5;">
                      Tip: Open the Success Page once after checkout. It securely stores your purchase in your browser so Manage License works without long links.
                    </p>

                    <!-- HOW TO ACTIVATE -->
                    <h3 style="margin:22px 0 10px 0;">How to activate</h3>
                    <ol style="padding-left:20px;color:#e5e7eb;font-size:15px;line-height:1.6;margin-top:0;">
                      <li>Open Gmail</li>
                      <li>Click <strong>AI Mail Genie → Settings</strong></li>
                      <li>Paste your license key</li>
                    </ol>

                    <p style="margin-top:24px;font-size:14px;color:#9ca3af;">
                      If you need help, reply to this email.
                    </p>
                  </td>
                </tr>

                <!-- FOOTER -->
                <tr>
                  <td style="padding:20px;text-align:center;font-size:12px;color:#64748b;background:#020617;">
                    © 2026 AI Mail Genie · Security-first email intelligence
                  </td>
                </tr>

              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
    """

    try:
        requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_email,
                "to": [to_email],
                "subject": subject,
                "html": html,
            },
            timeout=12,
        )
    except Exception:
        return


# -----------------------------
# Basic config guards
# -----------------------------
def require_openai_api_key():
    k = os.environ.get("OPENAI_API_KEY", "")
    if not k or not k.startswith("sk-"):
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not set or invalid")


def require_db_api_config():
    if not DB_API_URL or not DB_API_KEY:
        raise HTTPException(status_code=500, detail="DB_API_URL / DB_API_KEY not configured")


def require_stripe_config():
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET not configured")


def require_cron_secret(request: Request):
    expected = CRON_SECRET
    got = (request.headers.get("X-CRON-SECRET", "") or "").strip()
    if not expected or got != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


# -----------------------------
# Worker DB gateway helpers
# -----------------------------
def db_get(path: str, timeout: int = 15) -> Dict[str, Any]:
    require_db_api_config()
    url = f"{DB_API_URL}{path}"
    try:
        r = requests.get(url, headers={"X-DB-KEY": DB_API_KEY}, timeout=timeout)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"DB API unreachable: {str(e)}")

    if r.status_code >= 400:
        try:
            raise HTTPException(status_code=r.status_code, detail=r.json())
        except Exception:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    return r.json()


def db_post(path: str, payload: Dict[str, Any], timeout: int = 15) -> Dict[str, Any]:
    require_db_api_config()
    url = f"{DB_API_URL}{path}"
    try:
        r = requests.post(
            url,
            json=payload,
            headers={"X-DB-KEY": DB_API_KEY},
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"DB API unreachable: {str(e)}")

    if r.status_code >= 400:
        try:
            raise HTTPException(status_code=r.status_code, detail=r.json())
        except Exception:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    return r.json()


# -----------------------------
# Stripe helpers
# -----------------------------
def resolve_plan_from_price_id(price_id: str) -> Dict[str, Any]:
    """
    Map Stripe Price ID -> license creation parameters.
    """
    pid = (price_id or "").strip()

    if STRIPE_PRICE_PRO_MONTHLY and pid == STRIPE_PRICE_PRO_MONTHLY:
        return {"plan": "pro", "duration_days": 30, "label": "AI Mail Genie Pro (Monthly)"}

    if STRIPE_PRICE_PRO_YEARLY and pid == STRIPE_PRICE_PRO_YEARLY:
        return {"plan": "pro", "duration_days": 365, "label": "AI Mail Genie Pro (Yearly)"}

    if STRIPE_PRICE_PRO_LIFETIME and pid == STRIPE_PRICE_PRO_LIFETIME:
        return {"plan": "pro", "duration_days": None, "label": "AI Mail Genie Pro (Lifetime)"}

    # Fallback: lifetime pro
    return {"plan": "pro", "duration_days": None, "label": "AI Mail Genie Pro"}


# -----------------------------
# Health endpoints
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/health/db")
def health_db():
    if not DB_API_URL or not DB_API_KEY:
        return {"ok": True, "db": "not_configured"}
    try:
        data = db_get("/health/db", timeout=15)
        return {"ok": True, "db": data}
    except HTTPException as e:
        return {"ok": True, "db": "error", "detail": str(e.detail)[:300]}


# -----------------------------
# Manage License lookup (Render -> Worker)
# GET /api/manage/lookup?session_id=cs_...
# -----------------------------
@app.get("/api/manage/lookup")
def manage_license_lookup(session_id: str):
    """
    Browser calls this endpoint (Render).
    Backend calls Worker admin endpoint /admin/license/by-session (Cloudflare).
    Returns SAFE fields only (masked license key).
    """
    session_id = (session_id or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="missing_session_id")

    require_db_api_config()

    data = db_get(f"/admin/license/by-session?session_id={quote(session_id)}", timeout=20)

    license_key = (data.get("license_key") or "").strip()
    plan = data.get("plan")
    expires_at = data.get("expires_at")

    masked = "—"
    if len(license_key) > 8:
        masked = f"{license_key[:4]}…{license_key[-4:]}"

    status = "active"
    try:
        if expires_at:
            from datetime import datetime, timezone
            exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if exp < datetime.now(timezone.utc):
                status = "expired"
    except Exception:
        status = "active"

    return {
        "plan": plan,
        "status": status,
        "expires_at": expires_at,
        "license_key_masked": masked,
    }


# -----------------------------
# Stripe: Billing Portal (Customer Portal)
# POST /api/billing/portal
# Body: { session_id: "cs_..." }
# Returns: { url: "https://billing.stripe.com/..." }
# -----------------------------
class BillingPortalRequest(BaseModel):
    session_id: str = Field(default="", max_length=200)


@app.post("/api/billing/portal")
def create_billing_portal(req: BillingPortalRequest):
    """
    Creates a Stripe Billing Portal session from a Checkout session_id.
    Used by manage.html 'Manage Billing' button.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY not configured")

    stripe.api_key = STRIPE_SECRET_KEY

    session_id = (req.session_id or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="missing_session_id")

    try:
        checkout = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"stripe_retrieve_failed: {str(e)}")

    customer = getattr(checkout, "customer", None)
    if not customer:
        raise HTTPException(status_code=400, detail="no_customer_on_session")

    try:
        portal = stripe.billing_portal.Session.create(
            customer=customer,
            return_url=BILLING_PORTAL_RETURN_URL,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"stripe_portal_failed: {str(e)}")

    return {"url": getattr(portal, "url", "")}


# -----------------------------
# CRON: License reminders (Option A)
# POST /cron/license-reminders/run
# Header: X-CRON-SECRET: <CRON_SECRET>
# -----------------------------
def send_resend_email(to_email: str, subject: str, html: str) -> None:
    api_key = (os.environ.get("RESEND_API_KEY", "") or "").strip()
    from_email = (os.environ.get("FROM_EMAIL", "AI Mail Genie <license@aiemailgenie.com>") or "").strip()

    to_email = (to_email or "").strip().lower()
    if not api_key or not to_email or "@" not in to_email:
        return

    try:
        requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"from": from_email, "to": [to_email], "subject": subject, "html": html},
            timeout=12,
        )
    except Exception:
        return


def reminder_email_html(kind: str, plan_name: str, expires_at: str) -> str:
    title = "Your AI Mail Genie license is expiring soon"
    pre = "Your subscription is ending soon."
    if kind == "1d":
        title = "Your AI Mail Genie license expires tomorrow"
        pre = "Your subscription expires tomorrow."
    if kind == "expired":
        title = "Your AI Mail Genie license has expired"
        pre = "Your subscription has expired."

    exp_line = ""
    if expires_at:
        exp_line = f"<p style='margin:0 0 12px 0;color:#cbd5e1;'><strong>Expiry:</strong> {expires_at}</p>"

    manage_url = "https://aiemailgenie.com/manage.html"

    return f"""
    <html>
      <body style="margin:0;padding:0;background:#0b0f14;font-family:Inter,Segoe UI,Arial,sans-serif;color:#ffffff;">
        <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
          <tr>
            <td align="center">
              <table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:16px;overflow:hidden;box-shadow:0 0 40px rgba(0,255,200,0.08);">
                <tr>
                  <td style="padding:28px;text-align:center;background:linear-gradient(135deg,#0ea5e9,#22c55e);">
                    <img src="https://aiemailgenie.com/logo.png" alt="AI Mail Genie" width="56" style="margin-bottom:10px;" />
                    <h1 style="margin:0;font-size:22px;font-weight:900;color:#041014;">{title}</h1>
                  </td>
                </tr>

                <tr>
                  <td style="padding:28px;">
                    <p style="margin:0 0 12px 0;line-height:1.6;color:#e5e7eb;">
                      {pre} Manage billing to keep your <strong>{plan_name or "Pro"}</strong> plan active.
                    </p>
                    {exp_line}

                    <div style="margin:18px 0 8px 0;">
                      <a href="{manage_url}"
                         style="display:inline-block;padding:12px 16px;border-radius:12px;
                                background:linear-gradient(135deg,#0ea5e9,#22c55e);
                                color:#041014;font-weight:900;text-decoration:none;">
                        Manage Billing
                      </a>
                    </div>

                    <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.5;">
                      If the button does not work, open Manage License and click “Manage Billing”.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td style="padding:18px;text-align:center;font-size:12px;color:#64748b;background:#020617;">
                    © 2026 AI Mail Genie
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
    """


@app.post("/cron/license-reminders/run")
def cron_license_reminders_run(request: Request):
    """
    Render Cron calls this endpoint daily.
    - Pull lists from Worker:
        GET /admin/licenses/expiring?days=7
        GET /admin/licenses/expiring?days=1
        GET /admin/licenses/expiring?days=0   (expired)
    - Send emails via Resend (Render env)
    - Mark as sent:
        POST /admin/licenses/mark-reminded  { kind, license_ids }
    """
    require_cron_secret(request)
    require_db_api_config()

    batches = [
        {"days": 7, "kind": "7d"},
        {"days": 1, "kind": "1d"},
        {"days": 0, "kind": "expired"},
    ]

    out = {
        "ok": True,
        "sent": {"7d": 0, "1d": 0, "expired": 0},
        "skipped_missing_email": 0,
    }

    for b in batches:
        days = b["days"]
        kind = b["kind"]

        data = db_get(f"/admin/licenses/expiring?days={days}", timeout=30)
        licenses = (data.get("licenses") or []) if isinstance(data, dict) else []

        sent_ids: List[int] = []

        for row in licenses[:500]:
            lic_id = row.get("id")
            email = (row.get("email") or "").strip().lower()
            plan = row.get("plan_name") or row.get("plan") or "Pro"
            expires_at = row.get("expires_at") or ""

            if not email or "@" not in email:
                out["skipped_missing_email"] += 1
                continue

            subject = "AI Mail Genie — renewal reminder"
            if kind == "1d":
                subject = "AI Mail Genie — expires tomorrow"
            if kind == "expired":
                subject = "AI Mail Genie — expired"

            html = reminder_email_html(kind=kind, plan_name=str(plan), expires_at=str(expires_at))
            send_resend_email(email, subject, html)

            try:
                sent_ids.append(int(lic_id))
            except Exception:
                continue

        if sent_ids:
            db_post("/admin/licenses/mark-reminded", {"kind": kind, "license_ids": sent_ids}, timeout=30)
            out["sent"][kind] += len(sent_ids)

    return out


# -----------------------------
# Stripe Webhook (Checkout fulfillment)
# -----------------------------
@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    """
    Receives Stripe events.
    Primary event: checkout.session.completed

    Responsibilities:
      - Verify Stripe signature
      - Retrieve session with expand=['line_items.data.price'] (reliable price IDs)
      - Extract customer email
      - Resolve plan from price_id
      - Call Worker admin endpoint to create license: POST /admin/license/create
      - Send license email (best-effort)
    """
    require_stripe_config()
    require_db_api_config()

    stripe.api_key = STRIPE_SECRET_KEY

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing Stripe signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")

    event_type = event.get("type", "")
    if event_type != "checkout.session.completed":
        return {"ok": True, "ignored": True, "type": event_type}

    session = (event.get("data") or {}).get("object") or {}
    session_id = (session.get("id") or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session id")

    # Retrieve full session with line items expanded to obtain price_id reliably
    try:
        full_session = stripe.checkout.Session.retrieve(
            session_id,
            expand=["line_items.data.price"],
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe retrieve failed: {str(e)}")

    # Email extraction
    email = ""
    try:
        cd = getattr(full_session, "customer_details", None) or {}
        if isinstance(cd, dict):
            email = cd.get("email") or ""
    except Exception:
        email = ""

    if not email:
        try:
            email = getattr(full_session, "customer_email", "") or ""
        except Exception:
            email = ""

    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Missing customer email")

    # Price ID extraction (StripeObject-safe)
    price_id = ""
    try:
        li = getattr(full_session, "line_items", None)
        data = getattr(li, "data", None) if li is not None else None
        if data and len(data) > 0:
            item0 = data[0]
            p = getattr(item0, "price", None)
            pid = getattr(p, "id", None) if p is not None else None
            price_id = (pid or "").strip()
    except Exception:
        price_id = ""

    plan_payload = resolve_plan_from_price_id(price_id)

    # Create license in Worker (Worker dedupes by stripe_session_id)
    try:
        created = db_post(
            "/admin/license/create",
            {
                "email": email,
                "plan": plan_payload["plan"],
                "duration_days": plan_payload["duration_days"],
                "stripe_session_id": session_id,
                "stripe_price_id": price_id,
            },
            timeout=25,
        )
    except HTTPException as e:
        raise HTTPException(status_code=500, detail={"license_create_failed": True, "db_error": e.detail})

    # Send license email (best-effort)
    license_key = (created.get("license_key") or "").strip()
    if license_key:
        send_license_email(
            to_email=email,
            license_key=license_key,
            plan_name=plan_payload.get("label") or "AI Mail Genie Pro",
            session_id=session_id,
        )

    return {"ok": True, "fulfilled": True, "license": created}


# -----------------------------
# Helpers (privacy, parsing)
# -----------------------------
def safe_clean_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = re.sub(r"[^a-z0-9.\-]", "", d)
    return d[:200]


def redact_text(t: str) -> str:
    if not t:
        return ""
    s = t
    s = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[EMAIL]", s, flags=re.I)
    s = re.sub(r"\b\d{5,}\b", "[NUMBER]", s)
    s = re.sub(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", "[IBAN]", s, flags=re.I)
    s = re.sub(r"https?://\S+", "[URL]", s, flags=re.I)
    s = s.strip()
    if len(s) > 1600:
        s = s[:1600] + "…"
    return s


def classify_noise(subject: str, snippet: str) -> Dict[str, Any]:
    subj = (subject or "").lower()
    snip = (snippet or "").lower()
    text2 = f"{subj}\n{snip}"

    if any(x in text2 for x in ["unsubscribe", "view in browser", "newsletter", "marketing", "preferences", "promotions"]):
        return {"category": "newsletter", "confidence": 0.78}

    if any(x in text2 for x in ["receipt", "order", "invoice", "payment", "subscription", "delivery", "shipped", "tracking", "statement"]):
        return {"category": "transactional", "confidence": 0.70}

    if any(x in text2 for x in ["quick call", "book a meeting", "calendar", "demo", "pricing", "proposal", "partnership", "reach out"]):
        return {"category": "sales", "confidence": 0.68}

    return {"category": "unknown", "confidence": 0.55}


# -----------------------------
# Link / domain helpers
# -----------------------------
def domain_from_url(url: str) -> str:
    try:
        m = re.match(r"^https?://([^/]+)", (url or "").strip(), flags=re.I)
        if not m:
            return ""
        host = m.group(1).split("@")[-1]
        host = host.split(":")[0]
        return safe_clean_domain(host)
    except Exception:
        return ""


def looks_like_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


def looks_like_punycode(host: str) -> bool:
    return (host or "").startswith("xn--")


SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"
}

INFRA_DOMAINS = [
    "google.com", "googleusercontent.com", "gstatic.com",
    "microsoft.com", "office.com", "office365.com", "live.com",
    "icloud.com", "apple.com",
    "amazonaws.com", "cloudfront.net",
    "sendgrid.net", "mailchimp.com", "mandrillapp.com"
]


def is_infra_domain(d: str) -> bool:
    d = safe_clean_domain(d)
    return any(d == x or d.endswith("." + x) for x in INFRA_DOMAINS)


def normalize_for_lookalike(s: str) -> str:
    s = (s or "").lower()
    s = s.replace("0", "o").replace("1", "l")
    s = s.replace("rn", "m").replace("vv", "w")
    s = re.sub(r"[^a-z0-9]", "", s)
    return s


def lookalike_score(a: str, b: str) -> int:
    a = safe_clean_domain(a)
    b = safe_clean_domain(b)
    if not a or not b or a == b:
        return 0

    na = normalize_for_lookalike(a)
    nb = normalize_for_lookalike(b)
    if na == nb:
        return 3
    if na in nb or nb in na:
        return 2
    if len(na) > 6 and len(nb) > 6:
        common = sum(1 for ch in set(na) if ch in set(nb))
        if common >= 5:
            return 1
    return 0


def compute_link_signals(sender_domain: str, link_urls: List[str], link_domains: List[str]) -> Dict[str, Any]:
    sender_domain = safe_clean_domain(sender_domain)
    domains = [safe_clean_domain(d) for d in (link_domains or []) if d]

    for u in (link_urls or [])[:20]:
        d = domain_from_url(u)
        if d:
            domains.append(d)

    domains = list(dict.fromkeys([d for d in domains if d]))

    signals = {
        "unique_link_domains": domains[:20],
        "has_ip_link": False,
        "has_punycode_link": False,
        "has_shortener": False,
        "has_sender_mismatch_domains": False,
        "lookalike_domains": [],
        "mismatch_domains": [],
    }

    for d in domains:
        if looks_like_ip(d):
            signals["has_ip_link"] = True
        if looks_like_punycode(d):
            signals["has_punycode_link"] = True
        if d in SHORTENERS:
            signals["has_shortener"] = True

        if sender_domain and d != sender_domain and not is_infra_domain(d):
            signals["has_sender_mismatch_domains"] = True
            signals["mismatch_domains"].append({"domain": d})
            lk = lookalike_score(d, sender_domain)
            if lk > 0:
                signals["lookalike_domains"].append({"domain": d, "score": lk})

    signals["lookalike_domains"] = signals["lookalike_domains"][:10]
    signals["mismatch_domains"] = signals["mismatch_domains"][:20]
    return signals


# -----------------------------
# Deterministic Verdict Layer
# -----------------------------
def decide_verdict(
    sender_domain: str,
    mailed_by: str,
    signed_by: str,
    payment_changed: bool,
    payment_intent: bool,
    link_signals: Dict[str, Any],
    strictness: str = "normal",
) -> Tuple[Verdict, float, List[str]]:
    sender_domain = safe_clean_domain(sender_domain)
    mailed_by = safe_clean_domain(mailed_by)
    signed_by = safe_clean_domain(signed_by)

    reasons: List[str] = []

    strong_flags = 0
    if payment_changed:
        strong_flags += 1
        reasons.append("Payment details changed (strong indicator).")

    if link_signals.get("has_ip_link"):
        strong_flags += 1
        reasons.append("A link points directly to an IP address (strong indicator).")

    if link_signals.get("has_punycode_link"):
        strong_flags += 1
        reasons.append("A link uses punycode (possible impersonation).")

    lookalikes = link_signals.get("lookalike_domains") or []
    if any(x.get("score", 0) >= 2 for x in lookalikes):
        strong_flags += 1
        reasons.append("A link domain looks similar to the sender domain (possible lookalike).")

    moderate_flags = 0
    if link_signals.get("has_shortener"):
        moderate_flags += 1
        reasons.append("A URL shortener is used (moderate risk).")

    if link_signals.get("has_sender_mismatch_domains"):
        moderate_flags += 1
        reasons.append("Link domains differ from the sender domain (moderate risk).")

    legitimacy = 0
    if sender_domain:
        legitimacy += 1

    if mailed_by and sender_domain and (mailed_by == sender_domain or mailed_by.endswith("." + sender_domain)):
        legitimacy += 1
        reasons.append("Mailed-by matches sender domain (supporting signal).")
    if signed_by and sender_domain and (signed_by == sender_domain or signed_by.endswith("." + sender_domain)):
        legitimacy += 1
        reasons.append("Signed-by matches sender domain (supporting signal).")

    strict_finance = (strictness or "").lower() == "strict_finance"
    low_noise = (strictness or "").lower() == "low_noise"

    if low_noise and moderate_flags > 0 and not payment_changed:
        moderate_flags = max(0, moderate_flags - 1)

    if strong_flags >= 2 or (strong_flags >= 1 and moderate_flags >= 2):
        confidence = 0.85 if strong_flags >= 2 else 0.75
        return "HIGH RISK", confidence, reasons

    if strong_flags == 0:
        if moderate_flags == 0:
            return "SAFE", 0.82, reasons
        if legitimacy >= 2 and not payment_changed:
            return "SAFE", 0.72, reasons

    base_conf = 0.62
    if payment_intent and moderate_flags > 0:
        base_conf = 0.60
    if strict_finance and payment_intent and strong_flags == 0:
        base_conf = min(base_conf, 0.58)
    return "CAUTION", base_conf, reasons


# -----------------------------
# License gate (uses Worker) - UPDATED
# -----------------------------
def license_validate_or_free_fallback(license_key: str, device_id: str) -> Dict[str, Any]:
    license_key = (license_key or "").strip()
    device_id = (device_id or "").strip()

    if not license_key or not device_id:
        return {"ok": True, "mode": "free"}

    if not DB_API_URL or not DB_API_KEY:
        return {"ok": True, "mode": "free"}

    try:
        data = db_post("/license/validate", {"license_key": license_key, "device_id": device_id}, timeout=12)

        if isinstance(data, dict) and "valid" in data:
            if data.get("valid") is True:
                plan = data.get("plan") or {}
                return {
                    "ok": True,
                    "mode": "pro",
                    "license_id": data.get("license_id"),
                    "plan": plan,
                }
            return {"ok": True, "mode": "free", "reason": data.get("reason", "invalid")}

        if isinstance(data, dict) and data.get("ok") is True:
            mode = (data.get("mode") or "free").lower().strip()
            return {"ok": True, "mode": "pro" if mode == "pro" else "free"}

        return {"ok": True, "mode": "free"}

    except Exception:
        return {"ok": True, "mode": "free"}


def usage_increment_best_effort(license_key: str, device_id: str, amount: int = 1) -> None:
    license_key = (license_key or "").strip()
    device_id = (device_id or "").strip()

    if not license_key or not device_id or not DB_API_URL or not DB_API_KEY:
        return

    try:
        db_post(
            "/usage/increment",
            {"license_key": license_key, "device_id": device_id, "amount": int(amount)},
            timeout=12,
        )
    except Exception:
        return


# -----------------------------
# API models
# -----------------------------
class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(default="", max_length=2000)


class ChatRequest(BaseModel):
    provider: str = Field(default="gmail", max_length=30)
    threadKey: str = Field(default="", max_length=260)

    senderEmail: str = Field(default="", max_length=260)
    senderDomain: str = Field(default="", max_length=200)
    mailedBy: str = Field(default="", max_length=200)
    signedBy: str = Field(default="", max_length=200)

    subject: str = Field(default="", max_length=240)
    linkDomains: List[str] = Field(default_factory=list)
    linkUrls: List[str] = Field(default_factory=list)

    paymentIntent: bool = False
    paymentChanged: bool = False

    redactedSnippet: str = Field(default="", max_length=1600)

    userMessage: Optional[str] = Field(default=None, max_length=2000)
    history: List[ChatMessage] = Field(default_factory=list)

    mode: PlanMode = "free"
    strictness: Literal["normal", "strict_finance", "low_noise"] = "normal"

    followupCount: Optional[int] = None
    maxFollowups: int = 5

    licenseKey: str = Field(default="", max_length=80)
    deviceId: str = Field(default="", max_length=120)


class ChatResponse(BaseModel):
    reply: str


def upgrade_required_reply() -> str:
    return (
        "VERDICT: CAUTION\n"
        "CONFIDENCE: 0.50\n\n"
        "WHY (SHORT)\n"
        "Follow-up questions are available in AI Mail Genie Pro.\n\n"
        "WHAT I CHECKED\n"
        "- Sender address & domain\n"
        "- Mailed-by / Signed-by (if available)\n"
        "- Links and link domains\n"
        "- Payment-change indicator (if provided)\n"
        "- Noise category (newsletter / sales / transactional / unknown)\n\n"
        "KEY FINDINGS\n"
        "- This is a Pro-only feature: asking questions and getting deeper explanations.\n"
        "- Upgrade to Pro to ask follow-ups, get ranked risk drivers, and safe action templates.\n\n"
        "RECOMMENDED NEXT STEP\n"
        "- Upgrade to AI Mail Genie Pro to continue.\n"
    )


# -----------------------------
# System prompts
# -----------------------------
SYSTEM_CHAT_FREE_INITIAL = """
You are AI Mail Genie, a client-facing email security assistant.

You will be given a JSON payload containing:
- server_decision (VERDICT + CONFIDENCE + deterministic reasons)
- computed_link_signals
- limited email context (sender, subject, redacted snippet)
- noise classification

CRITICAL RULES:
- You MUST follow server_decision.verdict exactly. No hedging on the verdict.
- Do not claim you verified SPF/DKIM/DMARC, DNS ownership, SSL validity, or bank ownership unless explicitly provided.
- Use only facts present in the JSON payload.

FREE MODE OUTPUT (must follow exactly; no extra sections):

VERDICT: <SAFE|CAUTION|HIGH RISK>
CONFIDENCE: <0.00-1.00>

WHY (SHORT)
<1-2 sentences, plain language>

WHAT I CHECKED
- Sender address & domain
- Mailed-by / Signed-by (if available)
- Links and link domains
- Payment-change indicator (if provided)
- Noise category (newsletter / sales / transactional / unknown)

KEY FINDINGS
- <3-6 bullets; factual; derived from input only>

RECOMMENDED NEXT STEP
- <one concrete action only>
"""


SYSTEM_CHAT_PRO_INITIAL = """
You are AI Mail Genie PRO, a client-facing email security assistant.

You will be given a JSON payload containing:
- server_decision (VERDICT + CONFIDENCE + deterministic reasons)
- computed_link_signals
- limited email context (sender, subject, redacted snippet)
- noise classification
- strictness mode hint (normal / strict_finance / low_noise)

CRITICAL RULES:
- You MUST follow server_decision.verdict exactly. No hedging.
- Do not claim you verified SPF/DKIM/DMARC, DNS ownership, SSL validity, or bank ownership unless explicitly provided.
- Use only facts present in the JSON payload.

PRO MODE OUTPUT (must follow exactly):

VERDICT: <SAFE|CAUTION|HIGH RISK>
CONFIDENCE: <0.00-1.00>

WHY (SHORT)
<1-2 sentences, plain language>

WHAT I CHECKED
- Sender address & domain
- Mailed-by / Signed-by (if available)
- Links and link domains
- Payment-change indicator (if provided)
- Noise category (newsletter / sales / transactional / unknown)

KEY FINDINGS
- <4-8 bullets; factual; derived from input only>

RECOMMENDED NEXT STEP
- <one concrete action only>

RISK DRIVERS (RANKED)
1) <Most important signal> — <why it matters>
2) <Second signal> — <why it matters>
3) <Third signal> — <why it matters>

WHAT WOULD MAKE THIS SAFE?
- <2-5 specific verification conditions; concrete and realistic>

ACTION TEMPLATES
- Vendor verification email: <short, ready-to-send template>
- Internal note (optional): <1-3 sentence justification suitable for accounting/ops>
"""


SYSTEM_CHAT_PRO_FOLLOWUP = """
You are AI Mail Genie PRO. You must answer the user's follow-up question.

You will be given JSON payload containing:
- server_decision (VERDICT + CONFIDENCE)
- computed_link_signals
- limited email context (sender, subject, redacted snippet)
- strictness mode hint

CRITICAL RULES:
- You MUST keep the verdict consistent with server_decision.verdict.
- Do not reprint the full initial report.
- Answer in 3-8 bullets, direct and specific.
- If the user asks "what should I do" or "reply", include a short action template.
- Do not claim SPF/DKIM/DMARC/bank ownership unless explicitly provided.
"""


def sanitize_history_for_followups(history: List["ChatMessage"]) -> List["ChatMessage"]:
    if not history:
        return []

    trimmed: List[ChatMessage] = []
    for h in history[-10:]:
        c = (h.content or "").strip()
        if not c:
            continue

        if h.role == "assistant" and "VERDICT:" in c and "WHAT I CHECKED" in c and len(c) > 900:
            continue

        if h.role == "assistant" and len(c) > 700:
            c = c[:700] + "…"

        trimmed.append(ChatMessage(role=h.role, content=c[:2000]))

    return trimmed


def build_context(req: "ChatRequest") -> Dict[str, Any]:
    sender_domain = safe_clean_domain(req.senderDomain)
    mailed_by = safe_clean_domain(req.mailedBy)
    signed_by = safe_clean_domain(req.signedBy)

    link_signals = compute_link_signals(
        sender_domain=sender_domain,
        link_urls=req.linkUrls or [],
        link_domains=req.linkDomains or []
    )

    noise = classify_noise(req.subject, req.redactedSnippet)

    verdict, conf, verdict_reasons = decide_verdict(
        sender_domain=sender_domain,
        mailed_by=mailed_by,
        signed_by=signed_by,
        payment_changed=bool(req.paymentChanged),
        payment_intent=bool(req.paymentIntent),
        link_signals=link_signals,
        strictness=req.strictness,
    )

    ctx = {
        "provider": (req.provider or "")[:30],
        "thread_key": (req.threadKey or "")[:260],

        "sender_email": (req.senderEmail or "")[:260],
        "sender_domain": sender_domain,
        "mailed_by": mailed_by,
        "signed_by": signed_by,

        "subject": (req.subject or "")[:240],
        "link_domains": [safe_clean_domain(d) for d in (req.linkDomains or [])[:20]],
        "link_urls": (req.linkUrls or [])[:12],

        "payment_intent": bool(req.paymentIntent),
        "payment_changed": bool(req.paymentChanged),

        "redacted_snippet": redact_text(req.redactedSnippet),

        "noise": noise,

        "plan": {
            "mode": req.mode,
            "strictness": req.strictness,
        },

        "computed_link_signals": link_signals,

        "server_decision": {
            "verdict": verdict,
            "confidence": float(conf),
            "reasons": verdict_reasons[:8],
        }
    }
    return ctx


def count_followups(history: List[ChatMessage]) -> int:
    return sum(1 for h in (history or []) if h.role
