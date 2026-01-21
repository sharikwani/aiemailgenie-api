import os
import re
from typing import List, Optional, Dict, Any, Literal, Tuple

import requests
from fastapi import FastAPI, HTTPException
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

app = FastAPI(title="AI Mail Genie AI API", version="3.2.1")

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
# Health endpoints
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/health/db")
def health_db():
    # Safe DB diagnostic: does not break /health
    if not DB_API_URL or not DB_API_KEY:
        return {"ok": True, "db": "not_configured"}

    try:
        data = db_get("/health/db", timeout=15)
        return {"ok": True, "db": data}
    except HTTPException as e:
        return {"ok": True, "db": "error", "detail": str(e.detail)[:300]}


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

    domains = list(dict.fromkeys([d for d in domains if d]))  # unique

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
    """
    Calls Worker /license/validate.
    Accepts BOTH response formats:
      A) Worker format: {"valid": true, "plan": {...}}
      B) Legacy format: {"ok": true, "mode": "pro"}
    Fails safe to free if anything is wrong.
    """
    license_key = (license_key or "").strip()
    device_id = (device_id or "").strip()

    # No license provided => free
    if not license_key or not device_id:
        return {"ok": True, "mode": "free"}

    # DB API not configured => free
    if not DB_API_URL or not DB_API_KEY:
        return {"ok": True, "mode": "free"}

    try:
        data = db_post("/license/validate", {"license_key": license_key, "device_id": device_id}, timeout=12)

        # --- Format A: Worker returns {"valid": true/false, plan: {...}} ---
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

        # --- Format B: Legacy returns {"ok": true, "mode": "pro"} ---
        if isinstance(data, dict) and data.get("ok") is True:
            mode = (data.get("mode") or "free").lower().strip()
            return {"ok": True, "mode": "pro" if mode == "pro" else "free"}

        return {"ok": True, "mode": "free"}

    except HTTPException as e:
        # If endpoint missing or errors, fail safe to free (no crashes)
        if e.status_code == 404:
            return {"ok": True, "mode": "free"}
        return {"ok": True, "mode": "free"}

    except Exception:
        return {"ok": True, "mode": "free"}


def usage_increment_best_effort(license_key: str, device_id: str, amount: int = 1) -> None:
    """
    Calls Worker /usage/increment, but never breaks user flow if it fails.
    Includes device_id to enforce anti-sharing server-side.
    """
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

    # chat
    userMessage: Optional[str] = Field(default=None, max_length=2000)
    history: List[ChatMessage] = Field(default_factory=list)

    # monetization / plan gating (client hint for now; server overrides)
    mode: PlanMode = "free"
    strictness: Literal["normal", "strict_finance", "low_noise"] = "normal"

    followupCount: Optional[int] = None
    maxFollowups: int = 5

    # NEW: License system inputs (extension will send these)
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
            # server will override for gating; kept for context/hints only
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
    return sum(1 for h in (history or []) if h.role == "user")


# -----------------------------
# Core endpoint
# -----------------------------
@app.post("/ai/chat", response_model=ChatResponse)
def ai_chat(req: ChatRequest):
    require_openai_api_key()

    # -----------------------------
    # Server-side plan enforcement from license (UPDATED)
    # -----------------------------
    license_info = license_validate_or_free_fallback(req.licenseKey, req.deviceId)
    mode_from_db = (license_info.get("mode") or "free").lower().strip()
    if mode_from_db not in ("free", "pro"):
        mode_from_db = "free"

    mode = mode_from_db  # override client hint with server truth

    # Follow-ups are Pro-only. Free users get the initial analysis only.
    if (req.userMessage and req.userMessage.strip()) and mode == "free":
        return ChatResponse(reply=upgrade_required_reply())

    # Pro follow-up backstop: keep an upper bound to prevent abuse in early builds.
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
        messages.append(
            {"role": "user", "content": f"EMAIL_CONTEXT_JSON:\n{context}\n\nUser question: {req.userMessage.strip()[:2000]}"}
        )
    else:
        messages.append(
            {"role": "user", "content": f"EMAIL_CONTEXT_JSON:\n{context}\n\nGenerate the initial briefing in the required format."}
        )

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

        # Best-effort usage tracking (won't break user experience)
        # Only meter Pro usage; include device_id to prevent key sharing.
        if mode == "pro":
            usage_increment_best_effort(req.licenseKey, req.deviceId, amount=1)

        return ChatResponse(reply=reply)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat failed: {str(e)}")
