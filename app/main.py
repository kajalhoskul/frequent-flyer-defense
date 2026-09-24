"""AeroPoints -- a mock airline frequent-flyer loyalty portal, built to
demo defense against the real attack pattern behind the 2025 Qantas and
Hawaiian Airlines breaches: account-recovery/MFA-reset abuse, not just
credential stuffing.

Run with:
    uvicorn app.main:app --port 8300
"""
import json
import os
import time

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, Signer

from .security import scoring
from .security.store import SecurityStore

BASE_DIR = os.path.dirname(__file__)
DATA_PATH = os.path.join(BASE_DIR, "data", "accounts.json")

with open(DATA_PATH) as f:
    DATA = json.load(f)

ACCOUNTS = {a["ff_number"]: a for a in DATA["accounts"]}

store = SecurityStore()
signer = Signer("aeropoints-demo-secret")

app = FastAPI(title="AeroPoints")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def client_key(request: Request) -> str:
    # DEMO SIMPLIFICATION: trusts X-Forwarded-For unconditionally so the
    # attack simulators can model different source IPs against one local
    # process. A real deployment must only trust XFF from a known,
    # trusted reverse proxy.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def current_account(request: Request):
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        ff_number = signer.unsign(token).decode()
    except BadSignature:
        return None
    return ACCOUNTS.get(ff_number)


@app.middleware("http")
async def block_gate(request: Request, call_next):
    if request.url.path.startswith("/admin") or request.url.path.startswith("/static"):
        return await call_next(request)
    key = client_key(request)
    if scoring.is_currently_blocked(store, key):
        return JSONResponse({"detail": "Too many attempts. Access temporarily blocked."},
                             status_code=429, headers={"Retry-After": "60"})
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "home.html", {"account": current_account(request)})


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, ff_number: str = Form(...), password: str = Form(...)):
    key = client_key(request)
    account = ACCOUNTS.get(ff_number)
    success = bool(account and account["password"] == password)

    score, reasons, blocked = scoring.evaluate_login(store, key, ff_number, success)
    if blocked:
        return JSONResponse({"detail": "Suspicious login activity detected.", "reasons": sorted(reasons)},
                             status_code=403)

    if not success:
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid frequent flyer number or password."},
                                           status_code=401)

    response = RedirectResponse("/account", status_code=303)
    response.set_cookie("session", signer.sign(ff_number.encode()).decode(), httponly=True, max_age=3600)
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session")
    return response


@app.get("/account-recovery", response_class=HTMLResponse)
async def recovery_form(request: Request):
    return templates.TemplateResponse(request, "recovery.html", {"error": None, "reset_link": None})


@app.post("/account-recovery", response_class=HTMLResponse)
async def recovery_submit(request: Request, ff_number: str = Form(...)):
    key = client_key(request)
    score, reasons, blocked = scoring.evaluate_recovery_request(store, key, ff_number)
    if blocked:
        return JSONResponse({"detail": "Suspicious recovery activity detected.", "reasons": sorted(reasons)},
                             status_code=403)

    account = ACCOUNTS.get(ff_number)
    if not account:
        # Deliberately the SAME response as a real request, to avoid
        # leaking which frequent-flyer numbers are valid (account
        # enumeration via response differences is its own real
        # vulnerability class).
        return templates.TemplateResponse(request, "recovery.html", {
            "error": None,
            "reset_link": f"/reset-password/{signer.sign(ff_number.encode()).decode()}",
        })

    store.record_recovery(ff_number, key)
    token = signer.sign(ff_number.encode()).decode()
    return templates.TemplateResponse(request, "recovery.html", {
        "error": None, "reset_link": f"/reset-password/{token}",
    })


@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_form(request: Request, token: str):
    return templates.TemplateResponse(request, "reset_password.html", {"token": token, "error": None})


@app.post("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_submit(request: Request, token: str, new_password: str = Form(...)):
    try:
        ff_number = signer.unsign(token).decode()
    except BadSignature:
        return HTMLResponse("Invalid or expired reset link.", status_code=400)

    account = ACCOUNTS.get(ff_number)
    if account:
        account["password"] = new_password
    response = RedirectResponse("/login", status_code=303)
    return response


@app.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    account = current_account(request)
    if not account:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "account.html", {"account": account, "message": None})


@app.post("/redeem-points", response_class=HTMLResponse)
async def redeem_points(request: Request, amount: int = Form(...), delivery_address: str = Form(...)):
    account = current_account(request)
    if not account:
        return RedirectResponse("/login", status_code=303)

    flagged = scoring.check_post_recovery_action(store, account["ff_number"], "redeem_points")
    account["points_balance"] = max(0, account["points_balance"] - amount)

    message = f"Redeemed {amount} points to {delivery_address}."
    if flagged:
        message += " (This action was flagged for fraud review: recent account recovery.)"
    return templates.TemplateResponse(request, "account.html", {"account": account, "message": message})


@app.post("/add-payment-method", response_class=HTMLResponse)
async def add_payment_method(request: Request, card_last4: str = Form(...)):
    account = current_account(request)
    if not account:
        return RedirectResponse("/login", status_code=303)

    flagged = scoring.check_post_recovery_action(store, account["ff_number"], "add_payment_method")
    message = f"Added card ending in {card_last4}."
    if flagged:
        message += " (This action was flagged for fraud review: recent account recovery.)"
    return templates.TemplateResponse(request, "account.html", {"account": account, "message": message})


# ---- Security operations dashboard --------------------------------------

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/admin/stats.json")
async def stats():
    return JSONResponse({
        "totals": store.totals(),
        "top_clients": store.top_clients(12),
        "recent_fraud_alerts": store.recent_fraud_alerts(10),
        "recent_blocks": store.recent_blocks(10),
        "server_time": time.time(),
    })
