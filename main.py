import os
import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Literal, Tuple

import json

import requests
import stripe
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

import tldextract
from pybloom_live import BloomFilter

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

# 🔴 REQUIRED FOR RENDER HEALTH CHECK 🔴
@app.get("/")
def root():
    return {"ok": True}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # DEV ONLY (lock down later)
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


# =============================================================================
# Tranco Top 1M Bloom filter (legitimacy signal ONLY; never a trust override)
# - Private repo safe: bloom is loaded from local artifacts/ at startup.
# - Subdomain-safe: comparisons use eTLD+1 (organizational domain).
#
# UPDATE (domain_overrides integration):
# - If Worker domain_overrides says "deny" => treat as NOT legitimate.
# - If "allow" => treat as legitimate.
# - Else fallback to Bloom filter.
# - Best-effort; never crashes the app if Worker is unreachable.
# =============================================================================
TRANCO_BLOOM_PATH = os.path.join("artifacts", "tranco.bloom")
_tranco_extractor = tldextract.TLDExtract(cache_dir=False)

# Domain override cache (best-effort, low-risk performance optimization)
DOMAIN_OVERRIDE_CACHE_TTL_SECONDS = int((os.environ.get("DOMAIN_OVERRIDE_CACHE_TTL_SECONDS", "600") or "600").strip())


def etld1(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    r = _tranco_extractor(host)
    if not r.domain or not r.suffix:
        return ""
    return f"{r.domain}.{r.suffix}"


def safe_clean_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = re.sub(r"[^a-z0-9.\-]", "", d)
    return d[:200]

def normalize_email(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    m = re.search(r"<([^>]+)>", v)
    if m:
        v = (m.group(1) or "").strip().lower()
    v = re.sub(r"[^a-z0-9@._+\-]", "", v)
    return v[:260]


def _kb_cache_get() -> Optional[Dict[str, Any]]:
    try:
        cache = getattr(app.state, "known_bad_cache", None)
        if not isinstance(cache, dict):
            return None
        exp = cache.get("exp", 0)
        if exp and exp > int(datetime.now(timezone.utc).timestamp()):
            return cache.get("data")
        return None
    except Exception:
        return None


def _kb_cache_set(data: Dict[str, Any]) -> None:
    try:
        ttl = max(30, int(KNOWN_BAD_CACHE_TTL_SECONDS))
        app.state.known_bad_cache = {
            "data": data,
            "exp": int(datetime.now(timezone.utc).timestamp()) + ttl,
            "last_fetch_utc": datetime.now(timezone.utc).isoformat(),
        }
    except Exception:
        return


def load_known_bad_best_effort() -> Dict[str, Any]:
    cached = _kb_cache_get()
    if cached is not None:
        return cached

    empty = {"version": 0, "updated_at": "", "emails": [], "domains": []}

    if not KNOWN_BAD_URL:
        _kb_cache_set(empty)
        return empty

    try:
        r = requests.get(KNOWN_BAD_URL, timeout=12)
        r.raise_for_status()
        data = r.json() if r.content else {}

        emails_raw = data.get("emails") or []
        domains_raw = data.get("domains") or []

        emails = sorted({normalize_email(x) for x in emails_raw if isinstance(x, str) and x.strip()})
        domains = sorted({safe_clean_domain(x) for x in domains_raw if isinstance(x, str) and x.strip()})

        out = {
            "version": int(data.get("version") or 1),
            "updated_at": str(data.get("updated_at") or ""),
            "emails": emails,
            "domains": domains,
        }
        _kb_cache_set(out)
        return out
    except Exception:
        _kb_cache_set(empty)
        return empty


def known_bad_lookup(sender_email: str, sender_domain: str) -> Dict[str, Any]:
    kb = load_known_bad_best_effort()
    emails = set(kb.get("emails") or [])
    domains = set(kb.get("domains") or [])

    se = normalize_email(sender_email)
    sd = safe_clean_domain(sender_domain)
    base = etld1(sd) if sd else ""

    if se and se in emails:
        return {"hit": True, "type": "email", "value": se, "reason": "Sender email is in known-bad list.", "meta": kb}

    if sd and (sd in domains or (base and base in domains)):
        return {"hit": True, "type": "domain", "value": sd if sd in domains else base, "reason": "Sender domain is in known-bad list.", "meta": kb}

    return {"hit": False, "type": "", "value": "", "reason": "", "meta": kb}



def same_etld1(a: str, b: str) -> bool:
    a = safe_clean_domain(a)
    b = safe_clean_domain(b)
    if not a or not b:
        return False
    return etld1(a) == etld1(b)


def _load_tranco_bloom_best_effort():
    try:
        if not os.path.exists(TRANCO_BLOOM_PATH):
            return None
        with open(TRANCO_BLOOM_PATH, "rb") as f:
            return BloomFilter.fromfile(f)
    except Exception:
        return None


@app.on_event("startup")
def _startup_load_tranco_bloom():
    # Best-effort: never crash the app if the file is missing.
    app.state.tranco_bloom = _load_tranco_bloom_best_effort()
    # Best-effort cache for Worker domain_overrides
    app.state.domain_override_cache = {}
    app.state.known_bad_cache = {}


def _cache_get_domain_override(etld1_value: str) -> Optional[str]:
    """
    Returns "allow" / "deny" / None.
    """
    try:
        cache = getattr(app.state, "domain_override_cache", None)
        if not isinstance(cache, dict):
            return None
        item = cache.get(etld1_value)
        if not item:
            return None
        action, expires_at = item
        if not action:
            return None
        if isinstance(expires_at, (int, float)) and expires_at < int(datetime.now(timezone.utc).timestamp()):
            cache.pop(etld1_value, None)
            return None
        if action in ("allow", "deny"):
            return action
        return None
    except Exception:
        return None


def _cache_set_domain_override(etld1_value: str, action: Optional[str]) -> None:
    try:
        cache = getattr(app.state, "domain_override_cache", None)
        if not isinstance(cache, dict):
            return
        exp = int(datetime.now(timezone.utc).timestamp()) + max(30, int(DOMAIN_OVERRIDE_CACHE_TTL_SECONDS))
        stored_action = action if action in ("allow", "deny") else ""
        cache[etld1_value] = (stored_action, exp)
    except Exception:
        return


def _worker_domain_override_best_effort(etld1_value: str) -> Optional[str]:
    """
    Best-effort lookup:
      GET /admin/domain-override?etld1=...

    Expected outcomes:
      - If exists: returns dict containing an action ("allow"/"deny") (field name may vary)
      - If not exists: may return ok:false or empty; treat as None

    Never raises; returns "allow", "deny", or None.
    """
    etld1_value = (etld1_value or "").strip().lower()
    if not etld1_value:
        return None

    cached = _cache_get_domain_override(etld1_value)
    if cached in ("allow", "deny"):
        return cached

    # If DB is not configured, skip overrides entirely
    if not DB_API_URL or not DB_API_KEY:
        return None

    url = f"{DB_API_URL}/admin/domain-override?etld1={requests.utils.quote(etld1_value)}"
    try:
        r = requests.get(url, headers={"X-DB-KEY": DB_API_KEY}, timeout=10)
        if r.status_code >= 400:
            _cache_set_domain_override(etld1_value, None)
            return None

        data = r.json() if r.content else {}
        if not isinstance(data, dict):
            _cache_set_domain_override(etld1_value, None)
            return None

        action = None
        if isinstance(data.get("action"), str):
            action = data.get("action")
        elif isinstance(data.get("override_action"), str):
            action = data.get("override_action")
        else:
            ov = data.get("override")
            if isinstance(ov, dict) and isinstance(ov.get("action"), str):
                action = ov.get("action")

        action = (action or "").strip().lower()
        if action in ("allow", "deny"):
            _cache_set_domain_override(etld1_value, action)
            return action

        _cache_set_domain_override(etld1_value, None)
        return None

    except Exception:
        return None


def tranco_legitimacy_signal(domain: str) -> Dict[str, Any]:
    """
    Returns:
      - tranco_present: effective legitimacy boolean or None
      - tranco_base: eTLD+1
      - reason: "override_allow" | "override_deny" | "ok" | "bloom_unavailable" | "bloom_error" | "invalid_domain"
      - override_action: "allow" | "deny" | None
      - tranco_present_raw: raw bloom presence boolean or None (when available)
    """
    base = etld1(domain)
    bloom = getattr(app.state, "tranco_bloom", None)

    if not base:
        return {
            "tranco_present": None,
            "tranco_base": None,
            "reason": "invalid_domain",
            "override_action": None,
            "tranco_present_raw": None,
        }

    override_action = _worker_domain_override_best_effort(base)
    if override_action == "allow":
        return {
            "tranco_present": True,
            "tranco_base": base,
            "reason": "override_allow",
            "override_action": "allow",
            "tranco_present_raw": (base in bloom) if bloom is not None else None,
        }
    if override_action == "deny":
        return {
            "tranco_present": False,
            "tranco_base": base,
            "reason": "override_deny",
            "override_action": "deny",
            "tranco_present_raw": (base in bloom) if bloom is not None else None,
        }

    if bloom is None:
        return {
            "tranco_present": None,
            "tranco_base": base,
            "reason": "bloom_unavailable",
            "override_action": None,
            "tranco_present_raw": None,
        }

    try:
        raw = (base in bloom)
        return {
            "tranco_present": raw,
            "tranco_base": base,
            "reason": "ok",
            "override_action": None,
            "tranco_present_raw": raw,
        }
    except Exception:
        return {
            "tranco_present": None,
            "tranco_base": base,
            "reason": "bloom_error",
            "override_action": None,
            "tranco_present_raw": None,
        }


def apply_tranco_confidence_dampener(verdict: str, confidence: float, tranco_present: Optional[bool]) -> Tuple[float, bool]:
    """If Tranco indicates a widely-used domain, slightly dampen confidence for risky verdicts.
    Verdict is not changed; this is only calibration.
    """
    if tranco_present is True and verdict in ("CAUTION", "HIGH RISK") and isinstance(confidence, (int, float)):
        new_conf = max(0.55, float(confidence) - 0.08)
        return new_conf, (new_conf != float(confidence))
    return float(confidence), False


# -----------------------------
# Cloudflare Worker DB API (D1 Gateway)
# -----------------------------
DB_API_URL = os.environ.get("DB_API_URL", "").strip().rstrip("/")
DB_API_KEY = os.environ.get("DB_API_KEY", "").strip()

# -----------------------------
# Known-bad threatlist (email + domain) from GitHub RAW
# -----------------------------
KNOWN_BAD_URL = (os.environ.get("KNOWN_BAD_URL", "") or "").strip()
KNOWN_BAD_CACHE_TTL_SECONDS = int((os.environ.get("KNOWN_BAD_CACHE_TTL_SECONDS", "30") or "300").strip())


# -----------------------------
# Render-side Admin Proxy (Security Hardening)
# -----------------------------
ADMIN_TOKEN = (os.environ.get("ADMIN_TOKEN", "") or "").strip()


# -----------------------------
# Admin UI Basic Auth (recommended)
# -----------------------------
ADMIN_USER = (os.environ.get("ADMIN_USER", "") or "").strip()
ADMIN_PASS = (os.environ.get("ADMIN_PASS", "") or "").strip()
_admin_basic = HTTPBasic()

def require_admin_basic(credentials: HTTPBasicCredentials) -> None:
    # If not configured, fail closed
    if not ADMIN_USER or not ADMIN_PASS:
        raise HTTPException(status_code=500, detail="admin_basic_not_configured")
    u_ok = secrets.compare_digest((credentials.username or ""), ADMIN_USER)
    p_ok = secrets.compare_digest((credentials.password or ""), ADMIN_PASS)
    if not (u_ok and p_ok):
        # Browser will show credential prompt
        raise HTTPException(status_code=401, detail="unauthorized", headers={"WWW-Authenticate": "Basic"})

def require_admin_token(request: Request) -> None:
    """
    Protects Render-side admin proxy endpoints.
    Clients (your laptop/admin UI) must send X-Admin-Token.
    """
    expected = ADMIN_TOKEN
    got = (request.headers.get("X-Admin-Token", "") or "").strip()
    if not expected or got != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


# -----------------------------
# Security for cron endpoint
# -----------------------------
CRON_SECRET = (os.environ.get("CRON_SECRET", "") or "").strip()


def require_cron_secret(request: Request) -> None:
    expected = CRON_SECRET
    got = (request.headers.get("X-CRON-SECRET", "") or "").strip()
    if not expected or got != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


# -----------------------------
# Email delivery (Resend) - best effort
# -----------------------------
def send_resend_email(to_email: str, subject: str, html: str) -> None:
    """
    Best-effort only — never raises.
    """
    api_key = (os.environ.get("RESEND_API_KEY", "") or "").strip()
    from_email = (os.environ.get("FROM_EMAIL", "AI Mail Genie <license@aiemailgenie.com>")).strip()

    to_email = (to_email or "").strip().lower()
    if not api_key or not to_email or "@" not in to_email:
        return

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


def send_license_email(to_email: str, license_key: str, plan_name: str = "Pro", session_id: str = "") -> None:
    """
    Sends a premium, branded license email via Resend.
    Best-effort only — never raises.
    Includes a Manage License link (no long query string required; success.html stores session_id in localStorage).
    """
    to_email = (to_email or "").strip().lower()
    license_key = (license_key or "").strip()

    api_key = (os.environ.get("RESEND_API_KEY", "") or "").strip()
    if not api_key or not to_email or "@" not in to_email or not license_key:
        return

    manage_url = "https://aiemailgenie.com/manage.html"
    subject = f"Welcome to AI Mail Genie {plan_name} — Your License Is Ready"

    html = f"""
    <html>
      <body style="margin:0;padding:0;background:#0b0f14;font-family:Inter,Segoe UI,Arial,sans-serif;color:#ffffff;">
        <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 0;">
          <tr>
            <td align="center">
              <table width="600" cellpadding="0" cellspacing="0" style="background:#111827;border-radius:16px;overflow:hidden;box-shadow:0 0 40px rgba(0,255,200,0.08);">

                <tr>
                  <td style="padding:32px;text-align:center;background:linear-gradient(135deg,#0ea5e9,#22c55e);">
                    <img src="https://aiemailgenie.com/logo.png" alt="AI Mail Genie" width="64" style="margin-bottom:12px;" />
                    <h1 style="margin:0;font-size:26px;font-weight:800;color:#041014;">
                      Welcome to AI Mail Genie {plan_name}
                    </h1>
                  </td>
                </tr>

                <tr>
                  <td style="padding:32px;">
                    <p style="font-size:16px;line-height:1.6;margin-top:0;">
                      Thank you for choosing <strong>AI Mail Genie</strong>.
                      Your purchase was successful, and your license is now active.
                    </p>

                    <p style="font-size:15px;color:#cbd5e1;">
                      <strong>Account email:</strong> {to_email}<br/>
                      <strong>Plan:</strong> {plan_name}
                    </p>

                    <div style="margin:28px 0;padding:20px;border-radius:12px;background:#020617;border:1px solid #1f2937;">
                      <p style="margin:0 0 8px 0;color:#94a3b8;font-size:14px;">
                        Your license key
                      </p>
                      <div style="font-size:18px;font-weight:800;letter-spacing:1px;color:#22c55e;">
                        {license_key}
                      </div>
                    </div>

                    <div style="margin: 18px 0 8px 0;">
                      <a href="{manage_url}"
                         style="display:inline-block;padding:12px 16px;border-radius:12px;
                                background:linear-gradient(135deg,#0ea5e9,#22c55e);
                                color:#041014;font-weight:900;text-decoration:none;">
                        Manage License
                      </a>
                    </div>
                    <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.5;">
                      Use this to view your plan, expiry, and manage billing anytime.
                    </p>

                    <h3 style="margin:22px 0 10px 0;">How to activate</h3>
                    <ol style="padding-left:20px;color:#e5e7eb;font-size:15px;line-height:1.6;margin:0;">
                      <li>Open Gmail</li>
                      <li>Click <strong>AI Mail Genie → Settings</strong></li>
                      <li>Paste your license key</li>
                    </ol>

                    <p style="margin-top:22px;font-size:14px;color:#9ca3af;">
                      If you need help, reply to this email.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td style="padding:20px;text-align:center;font-size:12px;color:#64748b;background:#020617;">
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

    send_resend_email(to_email, subject, html)


# -----------------------------
# Guards / helpers
# -----------------------------
def require_openai_api_key():
    k = os.environ.get("OPENAI_API_KEY", "")
    if not k or not k.startswith("sk-"):
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not set or invalid")


def require_db_api_config():
    if not DB_API_URL or not DB_API_KEY:
        raise HTTPException(status_code=500, detail="DB_API_URL / DB_API_KEY not configured")


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
# Admin proxy endpoints (Render -> Worker)
# -----------------------------
@app.get("/admin/domain-override")
def admin_proxy_get_domain_override(request: Request, etld1: str):
    """
    Laptop/Admin UI -> Render (X-Admin-Token)
    Render -> Worker (X-DB-KEY)
    """
    require_admin_token(request)
    require_db_api_config()

    etld1_val = safe_clean_domain(etld1)
    if not etld1_val:
        raise HTTPException(status_code=400, detail="invalid_etld1")

    return db_get(f"/admin/domain-override?etld1={requests.utils.quote(etld1_val)}", timeout=15)


class DomainOverrideUpsertRequest(BaseModel):
    etld1: str = Field(default="", max_length=200)
    action: Literal["allow", "deny"]


@app.post("/admin/domain-overrides/upsert")
def admin_proxy_upsert_domain_override(request: Request, body: DomainOverrideUpsertRequest):
    """
    Laptop/Admin UI -> Render (X-Admin-Token)
    Render -> Worker (X-DB-KEY)
    """
    require_admin_token(request)
    require_db_api_config()

    etld1_val = safe_clean_domain(body.etld1)
    if not etld1_val:
        raise HTTPException(status_code=400, detail="invalid_etld1")

    if body.action not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="invalid_action")

    return db_post(
        "/admin/domain-overrides/upsert",
        {"etld1": etld1_val, "action": body.action},
        timeout=15,
    )



# ✅ Admin-only debug: verify Tranco + domain_overrides behavior (Render-protected)
@app.get("/admin/tranco-signal")
def admin_tranco_signal(request: Request, domain: str):
    require_admin_token(request)
    d = safe_clean_domain(domain)
    if not d:
        raise HTTPException(status_code=400, detail="invalid_domain")
    return tranco_legitimacy_signal(d)



# -----------------------------
# Admin UI (served by Render; Worker stays behind DB key)
# - Protected by HTTP Basic Auth (ADMIN_USER / ADMIN_PASS)
# - Browser calls same-origin /admin/api/* so credentials are reused automatically
# -----------------------------
ADMIN_UI_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>AI Mail Genie - Admin</title>
  <style>
    :root { --bg:#0b0f14; --panel:#111827; --panel2:#0f172a; --text:#e5e7eb; --muted:#94a3b8; --border:#1f2937; }
    body { margin:0; font-family: Inter, system-ui, -apple-system, Segoe UI, Arial, sans-serif; background:var(--bg); color:var(--text); }
    header { padding:18px 22px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; background:rgba(17,24,39,0.6); backdrop-filter: blur(8px); }
    h1 { margin:0; font-size:16px; letter-spacing:0.2px; }
    main { padding:18px 22px; max-width:1200px; margin:0 auto; }
    .row { display:flex; gap:12px; flex-wrap:wrap; }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:14px; }
    .card h2 { margin:0 0 10px 0; font-size:14px; color:#cbd5e1; }
    .grow { flex:1; min-width:320px; }
    label { display:block; font-size:12px; color:var(--muted); margin:10px 0 6px; }
    input { width:100%; padding:10px 10px; border-radius:10px; border:1px solid var(--border); background:var(--panel2); color:var(--text); outline:none; }
    button { padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:#0f172a; color:var(--text); cursor:pointer; font-weight:700; }
    button:hover { filter:brightness(1.1); }
    .btn-danger { background:#3b0a0a; }
    .btn-ok { background:#064e3b; }
    .btn-small { padding:6px 10px; font-size:12px; border-radius:9px; }
    .muted { color:var(--muted); font-size:12px; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:10px 8px; border-bottom:1px solid var(--border); font-size:12px; vertical-align:top; }
    th { text-align:left; color:#cbd5e1; font-weight:800; }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid var(--border); font-size:11px; color:#cbd5e1; }
    .pill.ok { background:#052e16; }
    .pill.bad { background:#3b0a0a; }
    .pill.warn { background:#2b1b05; }
    pre { background:var(--panel2); border:1px solid var(--border); border-radius:12px; padding:10px; overflow:auto; max-height:260px; }
    .tabs { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }
    .tab { padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:var(--panel2); cursor:pointer; font-weight:800; font-size:12px; }
    .tab.active { background:#0b1222; }
    .right { display:flex; gap:10px; align-items:center; }
    .statusdot { width:10px; height:10px; border-radius:50%; background:#64748b; display:inline-block; }
    .statusdot.ok { background:#22c55e; }
    .statusdot.bad { background:#ef4444; }
  </style>
</head>
<body>
<header>
  <div>
    <h1>AI Mail Genie - Admin</h1>
    <div class="muted">Protected by Basic Auth. All admin actions are proxied via Render.</div>
  </div>
  <div class="right">
    <span id="apiDot" class="statusdot"></span>
    <span id="apiText" class="muted">checking...</span>
    <button onclick="refreshAll()">Refresh</button>
  </div>
</header>

<main>
  <div class="tabs">
    <div class="tab active" data-tab="licenses" onclick="switchTab('licenses')">Licenses</div>
    <div class="tab" data-tab="overrides" onclick="switchTab('overrides')">Domain Overrides</div>
    <div class="tab" data-tab="raw" onclick="switchTab('raw')">Raw JSON</div>
  </div>

  <div id="tab-licenses">
    <div class="row">
      <div class="card grow">
        <h2>Search & Actions</h2>

        <div class="row">
          <div class="grow">
            <label>Filter (email, license key, plan, status)</label>
            <input id="licFilter" placeholder="e.g. john@company.com or pro or blocked" oninput="renderLicenses()" />
          </div>
          <div style="min-width:240px">
            <label>Selected license key</label>
            <input id="selectedLicenseKey" placeholder="Click a license row" readonly />
          </div>
        </div>

        <div class="row" style="margin-top:10px;">
          <button class="btn-ok" onclick="blockOrUnblock('unblock')">Unblock</button>
          <button class="btn-danger" onclick="blockOrUnblock('block')">Block</button>
          <button onclick="loadDevices()">View Devices</button>
        </div>

        <div class="muted" style="margin-top:10px;">Tip: click a license row to select it.</div>
      </div>

      <div class="card grow">
        <h2>Devices</h2>
        <div class="muted">Shows activations for the selected license key.</div>
        <div style="margin-top:10px;">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="devicesBody">
              <tr><td colspan="3" class="muted">Select a license and click "View Devices".</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:14px;">
      <h2>Licenses</h2>
      <div class="muted">Rendered from <code>/admin/api/licenses</code>.</div>
      <div style="margin-top:10px; overflow:auto;">
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Plan</th>
              <th>Status</th>
              <th>Expires</th>
              <th>License Key</th>
            </tr>
          </thead>
          <tbody id="licensesBody">
            <tr><td colspan="5" class="muted">Loading...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="tab-overrides" style="display:none;">
    <div class="row">
      <div class="card grow">
        <h2>Lookup Override</h2>
        <label>eTLD+1</label>
        <input id="ovEtld" placeholder="paypal.com" />
        <div class="row" style="margin-top:10px;">
          <button onclick="lookupOverride()">Lookup</button>
          <button class="btn-ok" onclick="upsertOverride('allow')">Allow</button>
          <button class="btn-danger" onclick="upsertOverride('deny')">Deny</button>
        </div>
        <div class="muted" style="margin-top:10px;">Writes to <code>domain_overrides</code> via Render proxy.</div>
      </div>

      <div class="card grow">
        <h2>Override Result</h2>
        <pre id="ovResult">{}</pre>
      </div>
    </div>
  </div>

  <div id="tab-raw" style="display:none;">
    <div class="row">
      <div class="card grow">
        <h2>Last API Response</h2>
        <pre id="rawJson">{}</pre>
      </div>
    </div>
  </div>

</main>

<script>
  let licenses = [];
  let lastJson = {};
  function setApiStatus(ok, msg) {
    const dot = document.getElementById("apiDot");
    const text = document.getElementById("apiText");
    dot.className = "statusdot " + (ok ? "ok" : "bad");
    text.textContent = msg;
  }

  function switchTab(name) {
    for (const t of ["licenses","overrides","raw"]) {
      document.getElementById("tab-"+t).style.display = (t===name) ? "" : "none";
      document.querySelector(`.tab[data-tab="${t}"]`).classList.toggle("active", t===name);
    }
  }

  async function apiGet(path) {
    const r = await fetch("/admin/api" + path, { method:"GET" });
    if (!r.ok) throw new Error(await r.text());
    return await r.json();
  }

  async function apiPost(path, body) {
    const r = await fetch("/admin/api" + path, {
      method:"POST",
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify(body || {})
    });
    if (!r.ok) throw new Error(await r.text());
    return await r.json();
  }

  function pill(status) {
    const s = (status || "").toLowerCase();
    if (s.includes("block")) return '<span class="pill bad">blocked</span>';
    if (s.includes("expir")) return '<span class="pill warn">expired</span>';
    return '<span class="pill ok">active</span>';
  }

  function renderLicenses() {
    const filter = (document.getElementById("licFilter").value || "").toLowerCase().trim();
    const body = document.getElementById("licensesBody");
    const rows = (licenses || []).filter(x => {
      if (!filter) return true;
      const hay = [
        x.email, x.license_key, x.plan, x.plan_name, x.status, x.expires_at
      ].map(v => (v || "").toString().toLowerCase()).join(" ");
      return hay.includes(filter);
    });

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="5" class="muted">No results.</td></tr>';
      return;
    }

    body.innerHTML = rows.map(x => {
      const key = (x.license_key || x.licenseKey || "");
      const status = x.status || (x.is_blocked ? "blocked" : "active");
      return `
        <tr style="cursor:pointer" onclick="selectLicense('${key.replace(/'/g,"&#39;")}')">
          <td>${(x.email||"")}</td>
          <td>${(x.plan_name||x.plan||"")}</td>
          <td>${pill(status)}</td>
          <td>${(x.expires_at||"")}</td>
          <td><code>${key}</code></td>
        </tr>
      `;
    }).join("");
  }

  function selectLicense(key) {
    document.getElementById("selectedLicenseKey").value = key || "";
    document.getElementById("devicesBody").innerHTML = '<tr><td colspan="3" class="muted">Click "View Devices".</td></tr>';
  }

  async function refreshLicenses() {
    const data = await apiGet("/licenses");
    lastJson = data;
    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);
    const list = data.licenses || data.items || data.data || data || [];
    licenses = Array.isArray(list) ? list : [];
    renderLicenses();
    setApiStatus(true, "API OK");
  }

  async function blockOrUnblock(action) {
    const key = (document.getElementById("selectedLicenseKey").value || "").trim();
    if (!key) { alert("Select a license first."); return; }
    const endpoint = action === "block" ? "/license/block" : "/license/unblock";
    const data = await apiPost(endpoint, { license_key: key });
    lastJson = data;
    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);
    await refreshLicenses();
    alert(action === "block" ? "Blocked." : "Unblocked.");
  }

  async function loadDevices() {
    const key = (document.getElementById("selectedLicenseKey").value || "").trim();
    if (!key) { alert("Select a license first."); return; }
    const data = await apiGet("/license/devices?license_key=" + encodeURIComponent(key));
    lastJson = data;
    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);

    const body = document.getElementById("devicesBody");
    const list = data.devices || data.activations || data.items || [];
    if (!Array.isArray(list) || !list.length) {
      body.innerHTML = '<tr><td colspan="3" class="muted">No devices.</td></tr>';
      return;
    }

    body.innerHTML = list.map(d => {
      const dev = d.device_id || d.deviceId || d.id || "";
      const created = d.created_at || d.createdAt || "";
      const did = (d.device_id || d.deviceId || "");
      return `
        <tr>
          <td><code>${dev}</code></td>
          <td>${created}</td>
          <td><button class="btn-small btn-danger" onclick="revokeDevice('${key.replace(/'/g,"&#39;")}','${did.replace(/'/g,"&#39;")}')">Revoke</button></td>
        </tr>
      `;
    }).join("");
  }

  async function revokeDevice(licenseKey, deviceId) {
    if (!licenseKey || !deviceId) { alert("Missing license/device id."); return; }
    const data = await apiPost("/license/device/revoke", { license_key: licenseKey, device_id: deviceId });
    lastJson = data;
    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);
    await loadDevices();
    alert("Device revoked.");
  }

  async function lookupOverride() {
    const etld1 = (document.getElementById("ovEtld").value || "").trim().toLowerCase();
    if (!etld1) { alert("Enter etld1 (e.g. paypal.com)"); return; }
    const data = await apiGet("/domain-override?etld1=" + encodeURIComponent(etld1));
    document.getElementById("ovResult").textContent = JSON.stringify(data, null, 2);
    lastJson = data;
    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);
  }

  async function upsertOverride(action) {
    const etld1 = (document.getElementById("ovEtld").value || "").trim().toLowerCase();
    if (!etld1) { alert("Enter etld1 (e.g. paypal.com)"); return; }
    const data = await apiPost("/domain-overrides/upsert", { etld1, action });
    document.getElementById("ovResult").textContent = JSON.stringify(data, null, 2);
    lastJson = data;
    document.getElementById("rawJson").textContent = JSON.stringify(data, null, 2);
    alert("Saved.");
  }

  async function refreshAll() {
    try {
      await refreshLicenses();
    } catch (e) {
      setApiStatus(false, "API error");
      document.getElementById("rawJson").textContent = String(e);
    }
  }

  refreshAll();
</script>
</body>
</html>
"""

@app.get("/admin/ui", response_class=HTMLResponse)
def admin_ui(credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    return HTMLResponse(content=ADMIN_UI_HTML, status_code=200)

# ---- Admin API (same-origin, Basic Auth protected) ----

@app.get("/admin/api/licenses")
def admin_api_licenses(credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    return db_get("/admin/licenses", timeout=25)

class _LicenseKeyBody(BaseModel):
    license_key: str = Field(default="", max_length=120)

@app.post("/admin/api/license/block")
def admin_api_license_block(body: _LicenseKeyBody, credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    lk = (body.license_key or "").strip()
    if not lk:
        raise HTTPException(status_code=400, detail="missing_license_key")
    return db_post("/admin/license/block", {"license_key": lk}, timeout=20)

@app.post("/admin/api/license/unblock")
def admin_api_license_unblock(body: _LicenseKeyBody, credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    lk = (body.license_key or "").strip()
    if not lk:
        raise HTTPException(status_code=400, detail="missing_license_key")
    return db_post("/admin/license/unblock", {"license_key": lk}, timeout=20)

@app.get("/admin/api/license/devices")
def admin_api_license_devices(license_key: str, credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    lk = (license_key or "").strip()
    if not lk:
        raise HTTPException(status_code=400, detail="missing_license_key")
    return db_get(f"/admin/license/devices?license_key={requests.utils.quote(lk)}", timeout=25)

class _RevokeDeviceBody(BaseModel):
    license_key: str = Field(default="", max_length=120)
    device_id: str = Field(default="", max_length=160)

@app.post("/admin/api/license/device/revoke")
def admin_api_license_device_revoke(body: _RevokeDeviceBody, credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    lk = (body.license_key or "").strip()
    did = (body.device_id or "").strip()
    if not lk or not did:
        raise HTTPException(status_code=400, detail="missing_license_or_device")
    return db_post("/admin/license/device/revoke", {"license_key": lk, "device_id": did}, timeout=25)

@app.get("/admin/api/domain-override")
def admin_api_domain_override(etld1: str, credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    et = safe_clean_domain(etld1)
    if not et:
        raise HTTPException(status_code=400, detail="invalid_etld1")
    return db_get(f"/admin/domain-override?etld1={requests.utils.quote(et)}", timeout=20)

class _DomainOverrideBody(BaseModel):
    etld1: str = Field(default="", max_length=200)
    action: Literal["allow", "deny"]

@app.post("/admin/api/domain-overrides/upsert")
def admin_api_domain_override_upsert(body: _DomainOverrideBody, credentials: HTTPBasicCredentials = Depends(_admin_basic)):
    require_admin_basic(credentials)
    require_db_api_config()
    et = safe_clean_domain(body.etld1)
    if not et:
        raise HTTPException(status_code=400, detail="invalid_etld1")
    if body.action not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="invalid_action")
    return db_post("/admin/domain-overrides/upsert", {"etld1": et, "action": body.action}, timeout=20)

# -----------------------------
# Stripe config
# -----------------------------
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()

STRIPE_PRICE_PRO_MONTHLY = os.environ.get("STRIPE_PRICE_PRO_MONTHLY", "").strip()
STRIPE_PRICE_PRO_YEARLY = os.environ.get("STRIPE_PRICE_PRO_YEARLY", "").strip()
STRIPE_PRICE_PRO_LIFETIME = os.environ.get("STRIPE_PRICE_PRO_LIFETIME", "").strip()


def require_stripe_config():
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET not configured")


def resolve_plan_from_price_id(price_id: str) -> Dict[str, Any]:
    pid = (price_id or "").strip()

    if STRIPE_PRICE_PRO_MONTHLY and pid == STRIPE_PRICE_PRO_MONTHLY:
        return {"plan": "pro", "duration_days": 30, "label": "AI Mail Genie Pro (Monthly)"}

    if STRIPE_PRICE_PRO_YEARLY and pid == STRIPE_PRICE_PRO_YEARLY:
        return {"plan": "pro", "duration_days": 365, "label": "AI Mail Genie Pro (Yearly)"}

    if STRIPE_PRICE_PRO_LIFETIME and pid == STRIPE_PRICE_PRO_LIFETIME:
        return {"plan": "pro", "duration_days": None, "label": "AI Mail Genie Pro (Lifetime)"}

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
# Manage License lookup
# -----------------------------
@app.get("/api/manage/lookup")
def manage_license_lookup(session_id: str):
    session_id = (session_id or "").strip()
    if not session_id:
        raise HTTPException(status_code=400, detail="missing_session_id")

    require_db_api_config()

    data = db_get(f"/admin/license/by-session?session_id={requests.utils.quote(session_id)}", timeout=20)

    license_key = (data.get("license_key") or "").strip()
    plan = data.get("plan")
    expires_at = data.get("expires_at")

    masked = "—"
    if len(license_key) > 8:
        masked = f"{license_key[:4]}…{license_key[-4:]}"

    status = "active"
    try:
        if expires_at:
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
# Stripe customer portal endpoint
# -----------------------------
class PortalRequest(BaseModel):
    session_id: str = Field(default="", max_length=200)


@app.post("/api/billing/portal")
def create_billing_portal(req: PortalRequest):
    require_stripe_config()
    stripe.api_key = STRIPE_SECRET_KEY

    sid = (req.session_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="missing_session_id")

    try:
        s = stripe.checkout.Session.retrieve(sid)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"stripe_retrieve_failed: {str(e)}")

    customer_id = getattr(s, "customer", None)
    if not customer_id:
        raise HTTPException(status_code=400, detail="no_customer_on_session")

    return_url = "https://aiemailgenie.com/manage.html"

    try:
        portal = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"stripe_portal_failed: {str(e)}")

    url = (getattr(portal, "url", "") or "").strip()
    if not url:
        raise HTTPException(status_code=502, detail="stripe_portal_missing_url")

    return {"ok": True, "url": url}


# -----------------------------
# Stripe Webhook (Checkout fulfillment)
# -----------------------------
@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
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

    try:
        full_session = stripe.checkout.Session.retrieve(
            session_id,
            expand=["line_items.data.price"],
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Stripe retrieve failed: {str(e)}")

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
# CRON: License renewal reminders
# -----------------------------
def reminder_email_html(kind: str, plan_name: str, expires_at: str, manage_url: str) -> str:
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
                      {pre}
                      Use the button below to manage billing and keep your <strong>{plan_name or "Pro"}</strong> plan active.
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
                      If the button does not work, open your Manage page and click “Manage Billing”.
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
    require_cron_secret(request)
    require_db_api_config()

    manage_url = "https://aiemailgenie.com/manage.html"

    batches = [
        {"days": 7, "kind": "7d"},
        {"days": 1, "kind": "1d"},
        {"days": 0, "kind": "expired"},
    ]

    out = {"ok": True, "sent": {"7d": 0, "1d": 0, "expired": 0}, "skipped_missing_email": 0}

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

            html = reminder_email_html(kind=kind if kind != "7d" else "7d", plan_name=str(plan), expires_at=str(expires_at), manage_url=manage_url)
            send_resend_email(email, subject, html)

            if isinstance(lic_id, int):
                sent_ids.append(lic_id)
            elif isinstance(lic_id, str) and lic_id.isdigit():
                sent_ids.append(int(lic_id))

        if sent_ids:
            db_post(
                "/admin/licenses/mark-reminded",
                {"kind": kind, "license_ids": sent_ids},
                timeout=30,
            )
            out["sent"][kind] += len(sent_ids)

    return out


# -----------------------------
# Helpers (privacy, parsing)
# -----------------------------
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
# License gate (uses Worker)
# -----------------------------
def _infer_tier_from_worker_plan(plan: Dict[str, Any]) -> str:
    """
    Your Worker returns plan like: {name:"pro", daily_limit:..., max_devices:...}
    It does NOT tell monthly/yearly/lifetime.
    So we default to "lifetime" only when expiry is missing; otherwise "monthly".
    This is a safe default for the extension UI.
    """
    return "monthly"


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
                return {"ok": True, "mode": "pro", "license_id": data.get("license_id"), "plan": plan}
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
        db_post("/usage/increment", {"license_key": license_key, "device_id": device_id, "amount": int(amount)}, timeout=12)
    except Exception:
        return


# -----------------------------
# NEW: Server-authoritative activation endpoint for extension
# -----------------------------
class LicenseActivateRequest(BaseModel):
    licenseKey: str = Field(default="", max_length=80)
    deviceId: str = Field(default="", max_length=120)


class PlanOut(BaseModel):
    mode: Literal["free", "pro"] = "free"
    tier: Literal["free", "monthly", "yearly", "lifetime"] = "free"
    expiresAt: Optional[str] = None
    strictness: Literal["normal", "strict_finance", "low_noise"] = "normal"


class LicenseActivateResponse(BaseModel):
    ok: bool = False
    error: Optional[str] = None
    plan: PlanOut


def _worker_try_activate_then_validate(license_key: str, device_id: str) -> Dict[str, Any]:
    """
    Robust strategy:
    1) Try Worker /license/activate (if it exists and works)
       - send BOTH payload styles (snake_case and camelCase) to avoid mismatch
    2) Regardless of activate outcome, call /license/validate and trust it
       - because validate is proven working in your environment
    """
    require_db_api_config()

    # 1) Try activate (best-effort; ignore failure)
    for payload in (
        {"license_key": license_key, "device_id": device_id},
        {"licenseKey": license_key, "deviceId": device_id},
    ):
        try:
            db_post("/license/activate", payload, timeout=10)
            break
        except HTTPException as e:
            if int(getattr(e, "status_code", 500)) in (400, 401, 403, 404, 409):
                continue
            continue
        except Exception:
            continue

    # 2) Validate (authoritative)
    data = db_post("/license/validate", {"license_key": license_key, "device_id": device_id}, timeout=12)
    return data if isinstance(data, dict) else {}


@app.post("/license/activate", response_model=LicenseActivateResponse)
def license_activate(req: LicenseActivateRequest):
    """
    This is what the extension calls when a user enters a key.
    It MUST NOT grant Pro unless Worker validate says valid.
    """
    license_key = (req.licenseKey or "").strip()
    device_id = (req.deviceId or "").strip()

    if not license_key:
        return LicenseActivateResponse(ok=False, error="licenseKey_required", plan=PlanOut(mode="free", tier="free"))
    if not device_id:
        return LicenseActivateResponse(ok=False, error="deviceId_required", plan=PlanOut(mode="free", tier="free"))

    if not DB_API_URL or not DB_API_KEY:
        # Fail closed (never grant Pro when DB is not reachable/configured)
        return LicenseActivateResponse(ok=False, error="db_not_configured", plan=PlanOut(mode="free", tier="free"))

    try:
        data = _worker_try_activate_then_validate(license_key, device_id)

        # Your validate shape (confirmed):
        # { valid: true, license_id: 7, plan: {name:"pro", daily_limit:..., max_devices:...} }
        if isinstance(data, dict) and "valid" in data:
            if data.get("valid") is True:
                plan = data.get("plan") or {}
                tier = _infer_tier_from_worker_plan(plan if isinstance(plan, dict) else {})
                return LicenseActivateResponse(
                    ok=True,
                    error=None,
                    plan=PlanOut(mode="pro", tier=tier, expiresAt=None, strictness="normal"),
                )
            reason = (data.get("reason") or "invalid_key").strip()
            if reason in ("invalid", "invalid_license", "invalid_key", "license_not_found"):
                reason = "invalid_key"
            return LicenseActivateResponse(ok=False, error=reason, plan=PlanOut(mode="free", tier="free"))

        return LicenseActivateResponse(ok=False, error="invalid_key", plan=PlanOut(mode="free", tier="free"))

    except Exception:
        return LicenseActivateResponse(ok=False, error="activation_failed", plan=PlanOut(mode="free", tier="free"))


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

    # Gmail UI 'Verified sender' badge (best-effort from extension)
    gmailVerifiedSender: bool = False

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
# System prompts (UNCHANGED)
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

    # Tranco legitimacy signal (heuristic only) with domain_overrides
    tranco = tranco_legitimacy_signal(sender_domain)
    # Known-bad threatlist override (FIRST PRIORITY)
    kb_hit = known_bad_lookup(req.senderEmail, sender_domain)


    if kb_hit.get("hit") is True:
        verdict = "HIGH RISK"
        conf = 0.99
        verdict_reasons = [kb_hit.get("reason") or "Matched known-bad list."]
    else:
            verdict, conf, verdict_reasons = decide_verdict(
                sender_domain=sender_domain,
                mailed_by=mailed_by,
                signed_by=signed_by,
                payment_changed=bool(req.paymentChanged),
                payment_intent=bool(req.paymentIntent),
                link_signals=link_signals,
                strictness=req.strictness,
                subject=req.subject,
                redacted_snippet=req.redactedSnippet,
                gmail_verified=bool(getattr(req, 'gmailVerifiedSender', False)),
                tranco_present=bool(tranco.get('tranco_present') is True),
            )

    reviewer_flags: Dict[str, Any] = {
        "sender_etld1": etld1(sender_domain) if sender_domain else "",
        "mailed_by_etld1": etld1(mailed_by) if mailed_by else "",
        "signed_by_etld1": etld1(signed_by) if signed_by else "",
        "mailed_by_etld1_match": bool(sender_domain and mailed_by and same_etld1(sender_domain, mailed_by)),
        "signed_by_etld1_match": bool(sender_domain and signed_by and same_etld1(sender_domain, signed_by)),
        "tranco_top_1m_present": bool(tranco.get("tranco_present") is True),
        "tranco_override_action": tranco.get("override_action"),
        "tranco_present_raw": tranco.get("tranco_present_raw"),
        "confidence_dampened_by_tranco": False,
        "known_bad_hit": bool(kb_hit.get("hit") is True),
        "known_bad_type": kb_hit.get("type") or "",
        "known_bad_value": kb_hit.get("value") or "",
        "known_bad_updated_at": (kb_hit.get("meta") or {}).get("updated_at", ""),
        "note": "Tranco is a legitimacy signal only; it does not override other checks.",
    }

    if kb_hit.get("hit") is True:
        dampened = False
    else:
        conf, dampened = apply_tranco_confidence_dampener(verdict, float(conf), tranco.get("tranco_present"))
    reviewer_flags["confidence_dampened_by_tranco"] = bool(dampened)

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

        "plan": {"mode": req.mode, "strictness": req.strictness},

        "computed_link_signals": link_signals,

        "legitimacy_signals": {"tranco": tranco},
        "reviewer_flags": reviewer_flags,

        "server_decision": {
            "verdict": verdict,
            "confidence": float(conf),
            "reasons": verdict_reasons[:8],
        }
    }
    return ctx


def count_followups(history: List[ChatMessage]) -> int:
    return sum(1 for h in (history or []) if h.role == "user")


# -----------------------------
# Link / domain helpers (UNCHANGED)
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
# Deterministic Verdict Layer (UNCHANGED)
# -----------------------------
def decide_verdict(
    sender_domain: str,
    mailed_by: str,
    signed_by: str,
    payment_changed: bool,
    payment_intent: bool,
    link_signals: Dict[str, Any],
    gmail_verified: bool = False,
    tranco_present: Optional[bool] = None,
    strictness: str = "normal",
    # NEW (backwards-compatible): pass these from build_context when available
    subject: str = "",
    redacted_snippet: str = "",
) -> Tuple[Verdict, float, List[str]]:
    sender_domain = safe_clean_domain(sender_domain)
    mailed_by = safe_clean_domain(mailed_by)
    signed_by = safe_clean_domain(signed_by)

    reasons: List[str] = []

    # -----------------------------
    # Helper: detect payment/billing pressure language
    # -----------------------------
    def _looks_like_payment_request(subj: str, snip: str) -> bool:
        t = f"{subj or ''}\n{snip or ''}".lower()
        keywords = [
            "payment", "billing", "invoice", "renew", "renewal", "subscription",
            "update payment", "update your payment", "payment method", "card expired",
            "failed payment", "payment declined", "charge", "refund",
            "account blocked", "account suspended", "suspended", "blocked",
            "verify your account", "verify billing", "confirm payment",
            "action required", "immediately", "urgent",
        ]
        return any(k in t for k in keywords)

    def _looks_like_threat_or_data_loss(subj: str, snip: str) -> bool:
        t = f"{subj or ''}\n{snip or ''}".lower()
        threats = [
            "will be deleted", "will be removed", "permanently deleted",
            "account will be deleted", "photos", "videos", "data will be deleted",
            "within 24", "within 48", "today", "tomorrow",
            "final notice", "last chance", "avoid suspension",
        ]
        return any(k in t for k in threats)

    def _looks_randomish_domain(d: str) -> bool:
        # Very lightweight heuristic: domains used in phishing often have
        # short labels with digits and few/no vowels (e.g. ktk56c.us).
        base = (d or "").strip().lower()
        if not base or "." not in base:
            return False
        label = base.split(".")[0]
        if len(label) < 5:
            return False
        has_digit = any(ch.isdigit() for ch in label)
        vowels = sum(1 for ch in label if ch in "aeiou")
        # No/low vowels + digits is a strong "random string" hint.
        if has_digit and vowels == 0:
            return True
        # High digit ratio is also suspicious.
        digit_ratio = (sum(1 for ch in label if ch.isdigit()) / max(1, len(label)))
        if digit_ratio >= 0.30:
            return True
        return False

    payment_request = bool(payment_intent) or _looks_like_payment_request(subject, redacted_snippet)
    threatening = _looks_like_threat_or_data_loss(subject, redacted_snippet)
    randomish_sender = _looks_randomish_domain(sender_domain)

    # -----------------------------
    # Risk flags
    # -----------------------------
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

    # -----------------------------
    # Legitimacy / alignment checks
    # -----------------------------
    legitimacy = 0
    if sender_domain:
        legitimacy += 1

    # Gmail verified badge and Tranco popularity are legitimacy signals (not trust overrides).
    # They help avoid over-escalation when mailed-by/signed-by are missing or unavailable.
    if gmail_verified:
        legitimacy = max(legitimacy, 2)
        reasons.append("Gmail shows this sender as verified (supporting legitimacy signal).")
    if tranco_present is True:
        legitimacy += 1
        reasons.append("Sender org domain is widely used (domain reputation supporting signal).")

    if mailed_by and sender_domain and same_etld1(mailed_by, sender_domain):
        legitimacy += 1
        reasons.append("Mailed-by matches sender org domain (eTLD+1) (supporting signal).")
    if signed_by and sender_domain and same_etld1(signed_by, sender_domain):
        legitimacy += 1
        reasons.append("Signed-by matches sender org domain (eTLD+1) (supporting signal).")

    strict_finance = (strictness or "").lower() == "strict_finance"
    low_noise = (strictness or "").lower() == "low_noise"

    if low_noise and moderate_flags > 0 and not payment_changed:
        moderate_flags = max(0, moderate_flags - 1)

    # -----------------------------
    # NEW: stronger payment-request escalation
    # -----------------------------
    # Key principle: "payment/billing + weak authenticity" is a primary phishing pattern.
    if payment_request and not payment_changed:
        weak_auth = (legitimacy < 2)  # missing mailed-by/signed-by alignment

        if threatening:
            reasons.append("Email uses urgency/threats of account/data loss alongside a billing/payment request.")
            if weak_auth or randomish_sender:
                return "HIGH RISK", 0.92, reasons

        if randomish_sender and weak_auth:
            reasons.append("Sender domain looks random/untrusted and lacks strong authenticity signals for a billing/payment request.")
            return "HIGH RISK", 0.90, reasons

        # Link mismatch/obfuscation is still a strong pattern.
        if weak_auth and (link_signals.get("has_sender_mismatch_domains") or link_signals.get("has_shortener")):
            reasons.append("Email requests billing/payment action with weak sender authenticity and non-matching/obfuscated link domains.")
            return "HIGH RISK", 0.88, reasons

        # Strict finance: be more aggressive even without link mismatch.
        if strict_finance and weak_auth:
            reasons.append("Email requests billing/payment action with weak sender authenticity (strict finance mode).")
            return "HIGH RISK", 0.86, reasons

        # Otherwise: never SAFE on payment request without strong authenticity.
        if weak_auth:
            reasons.append("Email requests billing/payment action but sender authenticity signals are weak.")
            moderate_flags = max(moderate_flags, 1)

    # -----------------------------
    # Existing decision logic (with guards)
    # -----------------------------
    if strong_flags >= 2 or (strong_flags >= 1 and moderate_flags >= 2):
        confidence = 0.88 if strong_flags >= 2 else 0.78
        return "HIGH RISK", confidence, reasons

    if strong_flags == 0:
        if moderate_flags == 0:
            if payment_request:
                return "CAUTION", 0.62 if not strict_finance else 0.58, reasons
            return "SAFE", 0.82, reasons
        if legitimacy >= 2 and not payment_changed:
            if payment_request:
                return "CAUTION", 0.62 if not strict_finance else 0.58, reasons
            return "SAFE", 0.72, reasons

    base_conf = 0.62
    if payment_intent and moderate_flags > 0:
        base_conf = 0.60
    if strict_finance and payment_intent and strong_flags == 0:
        base_conf = min(base_conf, 0.58)

    return "CAUTION", base_conf, reasons


# -----------------------------
# Core endpoint (UNCHANGED)
# -----------------------------
@app.post("/ai/chat", response_model=ChatResponse)
def ai_chat(req: ChatRequest):
    require_openai_api_key()

    license_info = license_validate_or_free_fallback(req.licenseKey, req.deviceId)
    mode_from_db = (license_info.get("mode") or "free").lower().strip()
    if mode_from_db not in ("free", "pro"):
        mode_from_db = "free"

    mode = mode_from_db

    if (req.userMessage and req.userMessage.strip()) and mode == "free":
        return ChatResponse(reply=upgrade_required_reply())

    max_followups = int(req.maxFollowups or 20)
    max_followups = 20 if max_followups <= 0 else max_followups
    max_followups = min(max_followups, 100)

    followups_used = req.followupCount
    if followups_used is None:
        followups_used = count_followups(req.history)

    if req.userMessage and req.userMessage.strip() and followups_used >= max_followups:
        return ChatResponse(
            reply=(
                "VERDICT: CAUTION\n"
                "CONFIDENCE: 0.50\n\n"
                "WHY (SHORT)\n"
                "Follow-up limit reached for this email thread.\n\n"
                "WHAT I CHECKED\n"
                "- Sender address & domain\n"
                "- Mailed-by / Signed-by (if available)\n"
                "- Links and link domains\n"
                "- Payment-change indicator (if provided)\n"
                "- Noise category (newsletter / sales / transactional / unknown)\n\n"
                "KEY FINDINGS\n"
                "- No further AI responses are allowed for this thread.\n\n"
                "RECOMMENDED NEXT STEP\n"
                "- Start a new thread or upgrade policy/settings if you need more help.\n"
            )
        )

    context = build_context(req)
    is_followup = bool(req.userMessage and req.userMessage.strip())

    if mode == "pro":
        system_prompt = SYSTEM_CHAT_PRO_FOLLOWUP if is_followup else SYSTEM_CHAT_PRO_INITIAL
    else:
        system_prompt = SYSTEM_CHAT_FREE_INITIAL

    messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt.strip()}]

    history = sanitize_history_for_followups(req.history) if is_followup else (req.history or [])
    for h in (history or [])[:12]:
        messages.append({"role": h.role, "content": (h.content or "")[:2000]})

    if is_followup:
        messages.append({"role": "user", "content": f"EMAIL_CONTEXT_JSON:\n{context}\n\nUser question: {req.userMessage.strip()[:2000]}"})
    else:
        messages.append({"role": "user", "content": f"EMAIL_CONTEXT_JSON:\n{context}\n\nGenerate the initial briefing in the required format."})

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.10,
            max_tokens=850 if mode == "pro" and not is_followup else 650,
            messages=messages,
        )
        reply = (completion.choices[0].message.content or "").strip()
        if not reply:
            raise ValueError("Empty reply")

        if mode == "pro":
            usage_increment_best_effort(req.licenseKey, req.deviceId, amount=1)

        return ChatResponse(reply=reply)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat failed: {str(e)}")
