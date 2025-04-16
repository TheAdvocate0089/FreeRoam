#!/usr/bin/env python3
import os
import sys
import json
import time
import logging
import random
import threading
import requests

from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from argparse import ArgumentParser

# ──────────────────────────────────────────────────────────────────────────────
# Configuration & Constants
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "USERNAME": "",
    "PASSWORD": "",
    "CARDBIN": "528911",
    "JWT_DEFAULT": "",
    "STATE_FILE": "state.json",
    "LOG_FILE": "flexiroam.log",
    "MAX_DAILY_ADDS": 4,
    "PLAN_THRESHOLD_PERCENT": 30,
    "PLAN_CHECK_INTERVAL": 120,   # secs
    "SESSION_REFRESH_INTERVAL": 3600,
    "MIN_PLAN_DELAY": 6,          # hours
}

API = {
    "LOGIN":       "https://prod-enduserservices.flexiroam.com/api/user/login",
    "CREDENTIALS": "https://www.flexiroam.com/api/auth/callback/credentials?",
    "CSRF":        "https://www.flexiroam.com/api/auth/csrf",
    "SESSION":     "https://www.flexiroam.com/api/auth/session",
    "PLANS":       "https://www.flexiroam.com/en-us/my-plans",
    "START_PLAN":  "https://prod-planservices.flexiroam.com/api/plan/start",
    "ELIG_CHECK":  "https://prod-enduserservices.flexiroam.com/api/user/redemption/check/eligibility",
    "REDEMPTION":  "https://prod-enduserservices.flexiroam.com/api/user/redemption/confirm",
}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def retry_on_failure(total=3, backoff=2):
    """Decorator to retry transient failures."""
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            delay = 1
            for attempt in range(1, total + 1):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    logging.warning(f"{fn.__name__} attempt {attempt} failed: {e}")
                    if attempt == total:
                        raise
                    time.sleep(delay)
                    delay *= backoff
        return wrapped
    return deco

def load_state(path):
    if Path(path).exists():
        return json.loads(Path(path).read_text())
    return {"day_adds": 0, "last_add": None}
def save_state(path, state):
    Path(path).write_text(json.dumps(state, default=str))

def setup_logging(log_file, level=logging.INFO):
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file)
    ]
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )

def create_session():
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[502,503,504])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

def luhn_checksum(num: str) -> int:
    digits = [int(d) for d in num]
    for i in range(len(digits) - 2, -1, -2):
        digits[i] = digits[i] * 2 - 9 if digits[i] * 2 > 9 else digits[i] * 2
    return sum(digits) % 10

def generate_card_number(bin_prefix, length=16):
    while True:
        core = bin_prefix + "".join(str(random.randint(0,9)) for _ in range(length - len(bin_prefix) -1))
        check = (10 - luhn_checksum(core + "0")) % 10
        full = core + str(check)
        if luhn_checksum(full) == 0:
            return full

def notify(subject, message):
    """Hook to send email/Slack on important events."""
    logging.info(f"NOTIFY: {subject} – {message}")
    # e.g. requests.post(slack_webhook, json={...})

# ──────────────────────────────────────────────────────────────────────────────
# API Client
# ──────────────────────────────────────────────────────────────────────────────
class FlexiroamClient:
    def __init__(self, config, session):
        self.cfg = config
        self.s   = session
        self.token    = None
        self.csrf     = None
        self.authcook = None

    @retry_on_failure()
    def login(self):
        resp = self.s.post(API["LOGIN"],
            headers={"Authorization": f"Bearer {self.cfg['JWT_DEFAULT']}", "Content-Type":"application/json"},
            json={"email": self.cfg["USERNAME"], "password": self.cfg["PASSWORD"], 
                  "device_udid":"iPhone17,2","device_model":"iPhone17,2",
                  "device_platform":"ios","device_version":"18.3.1","have_esim_supported_device":1,"notification_token":"undefined"}
        )
        data = resp.json()
        if data.get("message") != "Login Successful":
            raise RuntimeError(data.get("message"))
        self.token = data["data"]["token"]

    @retry_on_failure()
    def fetch_csrf(self):
        data = self.s.get(API["CSRF"]).json()
        self.csrf = data["csrfToken"]

    @retry_on_failure()
    def authenticate(self):
        resp = self.s.post(API["CREDENTIALS"],
            headers={"Content-Type":"application/x-www-form-urlencoded"},
            data={"token":self.token,"redirect":False,"csrfToken":self.csrf,"callbackUrl":"https://www.flexiroam.com/en-us/login"}
        )
        if "url" not in resp.json():
            raise RuntimeError("Credential callback failed")

    @retry_on_failure()
    def refresh_session(self):
        data = self.s.get(API["SESSION"]).json()
        if "expires" not in data:
            raise RuntimeError("Session refresh failed")

    @retry_on_failure()
    def get_plans(self):
        text = self.s.get(API["PLANS"], headers={"rsc":"1"}).text
        for line in text.splitlines():
            if line.startswith('{"plans":['):
                return json.loads(line)
        return {"plans":[]}

    @retry_on_failure()
    def start_plan(self, plan_id):
        resp = self.s.post(API["START_PLAN"],
            headers={"Authorization":f"Bearer {self.token}", "Content-Type":"application/json"},
            json={"sim_plan_id": plan_id}
        )
        data = resp.json()
        if "data" not in data:
            raise RuntimeError(data.get("message"))
        return True

    @retry_on_failure()
    def check_eligibility(self, cardnum):
        resp = self.s.post(API["ELIG_CHECK"],
            headers={"Authorization":f"Bearer {self.token}", "Content-Type":"application/json"},
            json={"email":self.cfg["USERNAME"], "lookup_value":cardnum}
        )
        msg = resp.json().get("message","")
        if "eligible" not in msg.lower():
            raise RuntimeError(msg)
        return resp.json()["data"]["redemption_id"]

    @retry_on_failure()
    def confirm_redemption(self, redemption_id):
        resp = self.s.post(API["REDEMPTION"],
            headers={"Authorization":f"Bearer {self.token}", "Content-Type":"application/json"},
            json={"redemption_id": redemption_id}
        )
        if resp.json().get("message") != "Redemption confirmed":
            raise RuntimeError("Redemption confirm failed")

# ──────────────────────────────────────────────────────────────────────────────
# Worker Threads
# ──────────────────────────────────────────────────────────────────────────────
def session_refresher(client: FlexiroamClient, stop_evt):
    while not stop_evt.is_set():
        try:
            client.refresh_session()
            logging.info("Session refreshed")
        except Exception as e:
            logging.error(f"Session refresh error: {e}")
            stop_evt.set()
        stop_evt.wait(client.cfg["SESSION_REFRESH_INTERVAL"])

def plan_manager(client: FlexiroamClient, stop_evt, state):
    last_add = datetime.fromisoformat(state.get("last_add")) if state.get("last_add") else datetime.min
    while not stop_evt.is_set():
        try:
            plans = client.get_plans()
            inactive = [p for p in plans["plans"] if p["status"]=="In-active"]
            active_pct = sum(p["circleChart"]["percentage"] for p in plans["plans"] if p["status"]=="Active")

            logging.info(f"Active: {active_pct}%  Inactive count: {len(inactive)}")
            # If active below threshold, activate first inactive
            if active_pct <= client.cfg["PLAN_THRESHOLD_PERCENT"] and inactive:
                pid = inactive[0]["planId"]
                client.start_plan(pid)
                logging.info(f"Started plan {pid}")
                notify("Plan Activated", f"Plan ID {pid} activated")
                last_add = datetime.now()
                state["last_add"] = last_add.isoformat()
                save_state(client.cfg["STATE_FILE"], state)

            # If we're below max daily adds and enough time passed, add new
            now = datetime.now()
            if (len(inactive) < 2 and 
                state["day_adds"] < client.cfg["MAX_DAILY_ADDS"] and 
                (now - last_add) >= timedelta(hours=client.cfg["MIN_PLAN_DELAY"])
            ):
                card = generate_card_number(client.cfg["CARDBIN"])
                rid  = client.check_eligibility(card)
                client.confirm_redemption(rid)
                logging.info(f"Redeemed new plan with card {card}")
                state["day_adds"] += 1
                last_add = now
                state["last_add"] = last_add.isoformat()
                save_state(client.cfg["STATE_FILE"], state)
        except Exception as e:
            logging.error(f"Plan manager error: {e}")
        stop_evt.wait(client.cfg["PLAN_CHECK_INTERVAL"])

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    # parse CLI / env
    parser = ArgumentParser()
    parser.add_argument("--username", default=os.getenv("FLEXI_USER"))
    parser.add_argument("--password", default=os.getenv("FLEXI_PWD"))
    parser.add_argument("--jwt",      default=os.getenv("FLEXI_JWT"))
    args = parser.parse_args()

    cfg = DEFAULT_CONFIG.copy()
    cfg.update({
        "USERNAME": args.username,
        "PASSWORD": args.password,
        "JWT_DEFAULT": args.jwt,
    })
    setup_logging(cfg["LOG_FILE"])
    logging.info("Starting Flexiroam auto‑plan script…")

    state = load_state(cfg["STATE_FILE"])
    session = create_session()
    client  = FlexiroamClient(cfg, session)

    # initial auth
    client.login()
    client.fetch_csrf()
    client.authenticate()

    stop_evt = threading.Event()
    # start threads
    threading.Thread(target=session_refresher, args=(client,stop_evt), daemon=True).start()
    threading.Thread(target=plan_manager,    args=(client,stop_evt,state), daemon=True).start()

    # wait for CTRL+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down…")
        stop_evt.set()

if __name__ == "__main__":
    main()
