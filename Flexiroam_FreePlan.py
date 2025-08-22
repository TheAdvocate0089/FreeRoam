# -*- coding: utf-8 -*-
import logging
import requests
import json # Already imported
import random
import time
import threading
import argparse
import os
import sys
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
# --- FIX 1: Remove JSONDecodeError from this line ---
from requests.exceptions import RequestException
# --- FIX 2: JSONDecodeError will be referenced via 'json.JSONDecodeError' below ---
from dotenv import load_dotenv # pip install python-dotenv

# --- Configuration & Constants ---

# Load environment variables from .env file
load_dotenv()

# Default Configuration (can be overridden by environment variables or command-line args)
DEFAULT_USERNAME: Optional[str] = os.getenv("FLEXIROAM_USERNAME")
DEFAULT_PASSWORD: Optional[str] = os.getenv("FLEXIROAM_PASSWORD")
DEFAULT_CARDBIN: str = os.getenv("FLEXIROAM_CARDBIN", "528911") # Default BIN if not set
DEFAULT_JWT_TOKEN: str = os.getenv(
    "FLEXIROAM_JWT_DEFAULT",
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOjQsImZpcnN0X25hbWUiOiJUcmF2ZWwiLCJsYXN0X25hbWUiOiJBcHAiLCJlbWFpbCI6InRyYXZlbGFwcEBmbGV4aXJvYW0uY29tIiwidHlwZSI6IkNsaWVudCIsImFjY2Vzc190eXBlIjoiQXBwIiwidXNlcl9hY2NvdW50X2lkIjo2LCJ1c2VyX3JvbGUiOiJWaWV3ZXIiLCJwZXJtaXNzaW9uIjpbXSwiZXhwaXJlIjoxODc5NjcwMjYwfQ.-RtM_zNG-zBsD_S2oOEyy4uSbqR7wReAI92gp9uh-0Y"
)
DEFAULT_LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
DEFAULT_LOG_FILE: Optional[str] = os.getenv("LOG_FILE", "flexiroam_auto.log") # Set to None to disable file logging

# API Endpoints
BASE_API_URL = "https://prod-enduserservices.flexiroam.com/api"
BASE_PLAN_API_URL = "https://prod-planservices.flexiroam.com/api"
WEB_BASE_URL = "https://www.flexiroam.com"
LOGIN_URL = f"{BASE_API_URL}/user/login"
CREDENTIALS_CALLBACK_URL = f"{WEB_BASE_URL}/api/auth/callback/credentials?"
SESSION_UPDATE_URL = f"{WEB_BASE_URL}/api/auth/session"
CSRF_URL = f"{WEB_BASE_URL}/api/auth/csrf"
MY_PLANS_URL = f"{WEB_BASE_URL}/en-us/my-plans" # Adjust locale if needed
START_PLAN_URL = f"{BASE_PLAN_API_URL}/plan/start"
ELIGIBILITY_CHECK_URL = f"{BASE_API_URL}/user/redemption/check/eligibility"
REDEMPTION_CONFIRM_URL = f"{BASE_API_URL}/user/redemption/confirm"

# Script Behavior Constants
SESSION_UPDATE_INTERVAL_SECONDS: int = 3600  # 1 hour
PLAN_CHECK_INTERVAL_SECONDS: int = 180      # 3 minutes
LOW_DATA_THRESHOLD_PERCENTAGE: float = 30.0 # Activate new plan if active data is below this %
MIN_INACTIVE_PLANS_BEFORE_REDEEM: int = 2   # Minimum number of inactive plans to maintain
MAX_DAILY_REDEMPTIONS: int = 4              # Max redemptions per ~24h cycle
REDEMPTION_COOLDOWN_HOURS: int = 6          # Cooldown between redemption attempts
RETRY_DELAY_SECONDS: int = 10               # Delay between retries for API calls
MAX_RETRIES: int = 3                        # Max retries for failed API calls
LIVENESS_SLEEP_INTERVAL_SECONDS: int = 60   # How often the main thread checks if worker threads are alive

# User Agent
USER_AGENT = "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36"

# Global shutdown event
shutdown_event = threading.Event()

# --- Logging Setup ---
def setup_logging(log_level_str: str, log_file: Optional[str]):
    """Configures logging."""
    log_level = getattr(logging, log_level_str, logging.INFO)
    log_format = '%(asctime)s.%(msecs)03d [%(levelname)s] [%(threadName)s] [%(filename)s:%(lineno)d] %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    handlers = [logging.StreamHandler(sys.stdout)] # Always log to console
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            handlers.append(file_handler)
        except IOError as e:
            logging.error(f"Could not open log file {log_file}: {e}")

    logging.basicConfig(level=log_level, format=log_format, datefmt=date_format, handlers=handlers)

# --- Luhn Algorithm ---
def luhn_checksum(card_number: str) -> int:
    """Calculates Luhn checksum digit."""
    digits = [int(d) for d in card_number]
    # Double every second digit from right to left
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10

def generate_card_number(bin_prefix: str, length: int = 16) -> str:
    """Generates a valid Luhn card number based on a BIN prefix."""
    if not bin_prefix.isdigit() or not (6 <= len(bin_prefix) < length):
        raise ValueError("Invalid BIN prefix provided.")

    while True:
        # Generate random digits for the middle part
        num_random_digits = length - len(bin_prefix) - 1
        if num_random_digits < 0:
             raise ValueError("BIN prefix is too long for the specified card length.")
        card_base = bin_prefix + ''.join(str(random.randint(0, 9)) for _ in range(num_random_digits))

        # Calculate check digit
        check_digit = (10 - luhn_checksum(card_base + "0")) % 10
        full_card_number = card_base + str(check_digit)

        # Final validation (should always pass if logic is correct)
        if len(full_card_number) == length and luhn_checksum(full_card_number) == 0:
            return full_card_number
        # This loop should ideally terminate quickly. Add a failsafe if needed.

# --- Flexiroam API Client ---
class FlexiroamClient:
    """Handles interaction with the Flexiroam API."""

    def __init__(self, username: str, password: str, jwt_default: str, user_agent: str):
        self.username = username
        self.password = password
        self.jwt_default = jwt_default
        self.session = requests.Session()
        self.session.headers.update({"user-agent": user_agent})
        self.bearer_token: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.last_api_error: Optional[str] = None

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        """Makes an HTTP request with retry logic."""
        self.last_api_error = None # Reset last error
        for attempt in range(MAX_RETRIES + 1):
            if shutdown_event.is_set():
                 raise InterruptedError("Shutdown signal received during request.")
            try:
                response = self.session.request(method, url, timeout=30, **kwargs) # Added timeout
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                return response
            except RequestException as e:
                self.last_api_error = str(e)
                logging.warning(f"Request failed ({method} {url}): {e}. Attempt {attempt + 1}/{MAX_RETRIES + 1}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY_SECONDS * (attempt + 1)) # Exponential backoff basic
                else:
                    logging.error(f"Max retries exceeded for {method} {url}.")
                    raise # Re-raise the last exception
            except Exception as e: # Catch other unexpected errors
                 self.last_api_error = f"Unexpected error: {str(e)}"
                 logging.exception(f"Unexpected error during request ({method} {url}): {e}")
                 raise

    def login(self) -> bool:
        """Logs in to Flexiroam and obtains a bearer token."""
        logging.info("Attempting to login and obtain bearer token...")
        headers = {
            "authorization": f"Bearer {self.jwt_default}",
            "content-type": "application/json",
        }
        payload = {
            "email": self.username,
            "password": self.password,
            "device_udid": "iPhone17,2", # Consider making configurable or randomizing
            "device_model": "iPhone17,2",
            "device_platform": "ios",
            "device_version": "18.3.1",
            "have_esim_supported_device": 1,
            "notification_token": "undefined" # Or generate a fake one
        }
        try:
            response = self._request_with_retry("POST", LOGIN_URL, headers=headers, json=payload)
            data = response.json()
            if data.get("message") == "Login Successful" and "token" in data.get("data", {}):
                self.bearer_token = data["data"]["token"]
                logging.info("Login successful, bearer token obtained.")
                return True
            else:
                message = data.get('message', 'Unknown login error')
                self.last_api_error = message
                logging.error(f"Login failed: {message}")
                return False
        # --- FIX 3: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, KeyError, InterruptedError) as e:
            logging.error(f"Login process failed: {e}")
            # Check if it was a JSON error specifically
            if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...") # Log partial response
            self.last_api_error = f"Login process failed: {str(e)}"
            return False

    def get_csrf_token(self) -> bool:
        """Fetches the CSRF token required for web authentication."""
        if not self.bearer_token:
             logging.error("Cannot get CSRF token without prior login.")
             return False
        logging.info("Fetching CSRF token...")
        headers = {"referer": f"{WEB_BASE_URL}/en-us/login"} # Referer might be important
        try:
            response = self._request_with_retry("GET", CSRF_URL, headers=headers)
            data = response.json()
            if "csrfToken" in data:
                self.csrf_token = data["csrfToken"]
                logging.info("CSRF token obtained successfully.")
                return True
            else:
                message = data.get('message', 'CSRF token not found in response')
                self.last_api_error = message
                logging.error(f"Failed to get CSRF token: {message}")
                return False
        # --- FIX 4: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, KeyError, InterruptedError) as e:
            logging.error(f"Fetching CSRF token failed: {e}")
            if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...")
            self.last_api_error = f"Fetching CSRF token failed: {str(e)}"
            return False

    def authenticate_session(self) -> bool:
        """Authenticates the web session using the bearer and CSRF tokens."""
        if not self.bearer_token or not self.csrf_token:
            logging.error("Cannot authenticate session without bearer and CSRF tokens.")
            return False
        logging.info("Authenticating web session...")
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "referer": f"{WEB_BASE_URL}/en-us/login",
            "x-auth-return-redirect": "1" # This header seems important
        }
        payload = {
            "token": self.bearer_token,
            "redirect": "false", # API expects string 'false'
            "csrfToken": self.csrf_token,
            "callbackUrl": f"{WEB_BASE_URL}/en-us/login"
        }
        try:
            response = self._request_with_retry("POST", CREDENTIALS_CALLBACK_URL, headers=headers, data=payload)
            data = response.json()
            if response.status_code == 200 and "url" in data:
                 if '__Secure-authjs.session-token' in self.session.cookies or 'authjs.session-token' in self.session.cookies:
                    logging.info("Web session authenticated successfully (cookies set).")
                    return True
                 else:
                    self.last_api_error = "Authentication call succeeded but session cookies not found."
                    logging.error(self.last_api_error)
                    return False
            else:
                message = data.get('message', f'Authentication failed with status {response.status_code}')
                self.last_api_error = message
                logging.error(f"Web session authentication failed: {message}")
                return False
        # --- FIX 5: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, InterruptedError) as e:
            logging.error(f"Web session authentication failed: {e}")
            if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...")
            self.last_api_error = f"Web session authentication failed: {str(e)}"
            return False

    def update_session(self) -> bool:
        """Updates the web session periodically."""
        logging.info("Attempting to update web session...")
        headers = {"referer": f"{WEB_BASE_URL}/en-us/home"}
        try:
            response = self._request_with_retry("GET", SESSION_UPDATE_URL, headers=headers)
            data = response.json()
            if "expires" in data and "user" in data:
                logging.info(f"Web session updated successfully. Expires at: {data['expires']}")
                return True
            else:
                message = data.get('message', 'Session update response missing expected data.')
                self.last_api_error = message
                logging.warning(f"Web session update might have failed: {message}")
                return True
        # --- FIX 6: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, KeyError, InterruptedError) as e:
            logging.error(f"Web session update failed: {e}")
            if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...")
            self.last_api_error = f"Web session update failed: {str(e)}"
            return False

    def get_plans(self) -> Tuple[bool, Optional[List[Dict[str, Any]]]]:
        """Retrieves the list of data plans from the web interface."""
        logging.debug("Fetching plan list...")
        headers = {
            "referer": f"{WEB_BASE_URL}/en-us/home",
            "rsc": "1",
            "accept": "text/x-component",
        }
        raw_plans_json = None
        try:
            response = self._request_with_retry("GET", MY_PLANS_URL, headers=headers)

            import re
            found_json = None
            for line in response.text.splitlines():
                 line = line.strip()
                 if line.startswith('{"plans":[') and line.endswith('}'):
                    if '"planId":' in line and '"status":' in line:
                        found_json = line
                        break

            if found_json:
                try:
                     raw_plans_json = json.loads(found_json)
                     if isinstance(raw_plans_json.get("plans"), list):
                         logging.debug("Successfully parsed plan data from web page.")
                         if not raw_plans_json["plans"] or "planId" in raw_plans_json["plans"][0]:
                              return True, raw_plans_json["plans"]
                         else:
                             logging.warning("Parsed plan data looks incomplete or malformed.")
                             self.last_api_error = "Parsed plan data malformed."
                             return False, None
                     else:
                         logging.error("Plan data extraction found JSON, but 'plans' key is not a list.")
                         self.last_api_error = "Extracted plan JSON format error ('plans' not a list)."
                         return False, None
                # --- FIX 7: Catch json.JSONDecodeError ---
                except json.JSONDecodeError as json_e:
                    logging.error(f"Failed to decode extracted JSON: {json_e}")
                    logging.debug(f"Problematic JSON string: {found_json}")
                    self.last_api_error = f"JSON Decode Error: {json_e}"
                    return False, None
            else:
                 logging.warning("Could not find plan data JSON in the page response.")
                 if "Login" in response.text or "Sign in" in response.text:
                      self.last_api_error = "Not logged in or session expired (Login page detected)."
                      logging.error(self.last_api_error)
                 else:
                     self.last_api_error = "Plan data signature not found in page content."
                     logging.warning(self.last_api_error)
                 if "<html" in response.text and "flexiroam" in response.text:
                     logging.info("No plan data block found, assuming no plans exist currently.")
                     return True, []
                 else:
                     logging.error("Failed to load My Plans page correctly.")
                     self.last_api_error = "My Plans page did not load correctly."
                     return False, None

        except (RequestException, InterruptedError) as e:
            logging.error(f"Failed to retrieve plans page: {e}")
            self.last_api_error = f"Failed to retrieve plans page: {str(e)}"
            return False, None

    def start_plan(self, sim_plan_id: int) -> Tuple[bool, str]:
        """Activates an inactive data plan."""
        if not self.bearer_token:
             return False, "Cannot start plan without bearer token (login required)."
        logging.info(f"Attempting to activate plan ID: {sim_plan_id}")
        headers = {
            "authorization": f"Bearer {self.bearer_token}",
            "content-type": "application/json",
        }
        payload = {"sim_plan_id": sim_plan_id}
        try:
            response = self._request_with_retry("POST", START_PLAN_URL, headers=headers, json=payload)
            data = response.json()
            if response.status_code == 200 and ("data" in data or "Plan started successfully" in data.get("message", "")):
                 message = data.get("message", "Plan activation successful (assumed).")
                 logging.info(f"Successfully activated plan {sim_plan_id}: {message}")
                 return True, message
            else:
                 message = data.get("message", f"Failed to activate plan {sim_plan_id}")
                 self.last_api_error = message
                 logging.error(message)
                 return False, message
        # --- FIX 8: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, KeyError, InterruptedError) as e:
             error_msg = f"Error activating plan {sim_plan_id}: {e}"
             logging.error(error_msg)
             if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...")
             self.last_api_error = error_msg
             return False, error_msg

    def check_card_eligibility(self, card_number: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Checks if a card number is eligible for the promotion."""
        if not self.bearer_token:
            return False, "Cannot check eligibility without bearer token (login required).", None
        logging.debug(f"Checking eligibility for card BIN {card_number[:6]}******")
        headers = {
            "authorization": f"Bearer {self.bearer_token}",
            "content-type": "application/json",
        }
        payload = {
            "email": self.username,
            "lookup_value": card_number
        }
        try:
            response = self._request_with_retry("POST", ELIGIBILITY_CHECK_URL, headers=headers, json=payload)
            data = response.json()
            message = data.get("message", "")

            if "Authorization Failed" in message:
                return False, "Authorization Failed (Account may be flagged/banned). Cannot proceed.", None
            if "Your Mastercard is not eligible for the offer" in message:
                 return False, "Card number is not eligible for the offer.", None
            if "We are currently processing your previous redemption" in message:
                return False, "Previous redemption still processing, cooldown required.", "PROCESSING_COOLDOWN"
            if "invalid card number length" in message.lower():
                 return False, "Invalid card number length passed to API.", None
            if "3GB Global Data Plan" in message and "data" in data and "redemption_id" in data["data"]:
                redemption_id = data["data"]["redemption_id"]
                logging.info(f"Card eligibility check successful. Redemption ID: {redemption_id}")
                return True, redemption_id, None
            else:
                self.last_api_error = message or "Eligibility check failed with unknown message."
                logging.warning(f"Eligibility check failed: {self.last_api_error}")
                return False, self.last_api_error, None

        # --- FIX 9: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, KeyError, InterruptedError) as e:
             error_msg = f"Error during eligibility check: {e}"
             logging.error(error_msg)
             if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...")
             self.last_api_error = error_msg
             return False, error_msg, None

    def confirm_redemption(self, redemption_id: str) -> Tuple[bool, str]:
        """Confirms the redemption using the ID from the eligibility check."""
        if not self.bearer_token:
             return False, "Cannot confirm redemption without bearer token (login required)."
        logging.info(f"Confirming redemption ID: {redemption_id}")
        headers = {
            "authorization": f"Bearer {self.bearer_token}",
            "content-type": "application/json",
        }
        payload = {"redemption_id": redemption_id}
        try:
            response = self._request_with_retry("POST", REDEMPTION_CONFIRM_URL, headers=headers, json=payload)
            data = response.json()
            message = data.get("message", "")

            if message == "Redemption confirmed":
                logging.info("Redemption confirmed successfully! New plan should be added shortly.")
                return True, message
            else:
                self.last_api_error = message or "Redemption confirmation failed with unknown message."
                logging.error(f"Redemption confirmation failed: {self.last_api_error}")
                return False, self.last_api_error

        # --- FIX 10: Catch json.JSONDecodeError ---
        except (RequestException, json.JSONDecodeError, KeyError, InterruptedError) as e:
             error_msg = f"Error confirming redemption: {e}"
             logging.error(error_msg)
             if isinstance(e, json.JSONDecodeError):
                 logging.error(f"Response content was not valid JSON: {response.text[:500]}...")
             self.last_api_error = error_msg
             return False, error_msg


# --- Worker Threads ---

def session_updater_thread(client: FlexiroamClient):
    """Periodically updates the web session."""
    threading.current_thread().name = "SessionUpdater"
    logging.info("Session update thread started.")
    while not shutdown_event.is_set():
        try:
            if client.update_session():
                 logging.info("Session update check completed.")
            else:
                 logging.warning(f"Session update failed. Last API error: {client.last_api_error}")

            shutdown_event.wait(SESSION_UPDATE_INTERVAL_SECONDS)

        except InterruptedError:
             logging.info("Shutdown signal received, stopping session updater.")
             break
        except Exception as e:
            logging.exception(f"Unexpected error in session updater thread: {e}")
            shutdown_event.wait(60)

    logging.info("Session update thread finished.")


def plan_manager_thread(client: FlexiroamClient, card_bin: str):
    """Manages data plans: activates when low, redeems new ones when needed."""
    threading.current_thread().name = "PlanManager"
    logging.info("Plan manager thread started.")

    daily_redemption_count = 0
    last_redemption_attempt_time = datetime.min
    last_daily_reset_time = datetime.now()

    while not shutdown_event.is_set():
        try:
            now = datetime.now()

            if now - last_daily_reset_time >= timedelta(days=1):
                logging.info(f"Resetting daily redemption counter. Previous count: {daily_redemption_count}")
                daily_redemption_count = 0
                last_daily_reset_time = now

            get_success, plans = client.get_plans()
            if not get_success:
                 logging.error(f"Failed to get plans. Last API error: {client.last_api_error}. Skipping cycle.")
                 shutdown_event.wait(PLAN_CHECK_INTERVAL_SECONDS)
                 continue

            if plans is None:
                 logging.error("get_plans returned success but plans is None. Skipping cycle.")
                 shutdown_event.wait(PLAN_CHECK_INTERVAL_SECONDS)
                 continue

            active_plans = []
            inactive_plans = []
            total_active_percentage = 0.0
            total_inactive_percentage = 0.0

            for plan in plans:
                 if not all(k in plan for k in ["status", "planId", "circleChart"]):
                     logging.warning(f"Skipping malformed plan entry: {plan.get('planId', 'N/A')}")
                     continue

                 percentage = plan["circleChart"].get("percentage", 0.0)
                 if not isinstance(percentage, (int, float)):
                      logging.warning(f"Invalid percentage type in plan {plan['planId']}: {percentage}. Treating as 0.")
                      percentage = 0.0

                 if plan["status"] == 'Active' and percentage > 0:
                    active_plans.append(plan)
                    total_active_percentage += percentage
                 elif plan["status"] == 'In-active':
                     inactive_plans.append(plan)
                     total_inactive_percentage += percentage

            active_gb = (total_active_percentage / 100.0) * 3.0
            inactive_gb = (total_inactive_percentage / 100.0) * 3.0
            inactive_count = len(inactive_plans)

            logging.info(f"Plan status: Active GB: {active_gb:.2f}, Inactive GB: {inactive_gb:.2f}, Inactive Count: {inactive_count}")

            if total_active_percentage < LOW_DATA_THRESHOLD_PERCENTAGE and inactive_count > 0:
                plan_to_activate = inactive_plans[0]
                plan_id = plan_to_activate["planId"]
                logging.warning(f"Active data ({total_active_percentage:.1f}%) below threshold ({LOW_DATA_THRESHOLD_PERCENTAGE:.1f}%). Activating plan ID: {plan_id}")

                activate_success, activate_msg = client.start_plan(plan_id)
                if activate_success:
                     logging.info(f"Successfully initiated activation for plan {plan_id}.")
                     shutdown_event.wait(PLAN_CHECK_INTERVAL_SECONDS)
                     continue
                else:
                     logging.error(f"Failed to activate plan {plan_id}: {activate_msg}")

            can_redeem_today = daily_redemption_count < MAX_DAILY_REDEMPTIONS
            cooldown_passed = (now - last_redemption_attempt_time) >= timedelta(hours=REDEMPTION_COOLDOWN_HOURS)

            if inactive_count < MIN_INACTIVE_PLANS_BEFORE_REDEEM and can_redeem_today and cooldown_passed:
                logging.info(f"Inactive plan count ({inactive_count}) is low. Attempting to redeem a new plan (Attempt {daily_redemption_count + 1}/{MAX_DAILY_REDEMPTIONS}).")
                last_redemption_attempt_time = now

                card_number = generate_card_number(card_bin)
                logging.info(f"Generated card number: {card_number[:6]}**********{card_number[-4:]}")

                eligible, result, code = client.check_card_eligibility(card_number)

                if eligible and isinstance(result, str):
                     redemption_id = result
                     confirm_success, confirm_msg = client.confirm_redemption(redemption_id)
                     if confirm_success:
                         logging.info(f"Successfully redeemed new plan using card {card_number[:6]}******. Message: {confirm_msg}")
                         daily_redemption_count += 1
                     else:
                         logging.error(f"Failed to confirm redemption {redemption_id} for card {card_number[:6]}******. Message: {confirm_msg}")

                elif code == "PROCESSING_COOLDOWN":
                     logging.warning(f"Redemption attempt failed: {result}. Waiting for previous redemption to process.")
                     last_redemption_attempt_time = now + timedelta(hours=2)
                elif not eligible and "Authorization Failed" in str(result):
                     logging.critical(f"Redemption failed: {result}. Stopping script as account might be banned.")
                     shutdown_event.set()
                     break
                else:
                     logging.warning(f"Card eligibility check failed for {card_number[:6]}******. Reason: {result}")

            elif inactive_count >= MIN_INACTIVE_PLANS_BEFORE_REDEEM:
                 logging.debug(f"Inactive plan count ({inactive_count}) is sufficient.")
            elif not can_redeem_today:
                 logging.info(f"Maximum daily redemptions ({MAX_DAILY_REDEMPTIONS}) reached.")
            elif not cooldown_passed:
                 wait_time = (last_redemption_attempt_time + timedelta(hours=REDEMPTION_COOLDOWN_HOURS)) - now
                 logging.info(f"Waiting for redemption cooldown. Time remaining: {wait_time}")

            shutdown_event.wait(PLAN_CHECK_INTERVAL_SECONDS)

        except InterruptedError:
             logging.info("Shutdown signal received, stopping plan manager.")
             break
        except ValueError as ve:
             logging.critical(f"Configuration error: {ve}. Stopping script.")
             shutdown_event.set()
             break
        except Exception as e:
            logging.exception(f"Unexpected error in plan manager thread: {e}")
            shutdown_event.wait(60)

    logging.info("Plan manager thread finished.")


# --- Main Execution ---
def main():
    """Main function to parse arguments, set up, and run the threads."""

    parser = argparse.ArgumentParser(description="Flexiroam Auto MasterCard Plan Redeemer")
    parser.add_argument("-u", "--username", default=DEFAULT_USERNAME, help="Flexiroam Username/Email")
    parser.add_argument("-p", "--password", default=DEFAULT_PASSWORD, help="Flexiroam Password")
    parser.add_argument("-b", "--bin", default=DEFAULT_CARDBIN, help="MasterCard BIN prefix for generating card numbers")
    parser.add_argument("--jwt", default=DEFAULT_JWT_TOKEN, help="Default JWT token for initial login")
    parser.add_argument("--log-level", default=DEFAULT_LOG_LEVEL, choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Logging level")
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE, help="Path to log file (omit for console only)")
    parser.add_argument("--no-log-file", action="store_true", help="Disable logging to file")

    args = parser.parse_args()

    log_file_path = None if args.no_log_file else args.log_file

    setup_logging(args.log_level, log_file_path)

    logging.info("Starting Flexiroam Auto Redeemer Script...")
    logging.info(f"Log Level: {args.log_level}, Log File: {log_file_path or 'Console only'}")

    if not args.username or not args.password:
        logging.critical("Username and Password are required. Set environment variables (FLEXIROAM_USERNAME, FLEXIROAM_PASSWORD) or use command-line arguments.")
        sys.exit(1)
    if not args.bin or len(args.bin) < 6:
         logging.critical("A valid MasterCard BIN (at least 6 digits) is required. Set FLEXIROAM_CARDBIN or use --bin.")
         sys.exit(1)

    logging.info(f"Using Username: {args.username}")
    logging.info(f"Using Card BIN: {args.bin}")

    client = FlexiroamClient(args.username, args.password, args.jwt, USER_AGENT)

    if not client.login():
        logging.critical(f"Initial login failed. Last error: {client.last_api_error}. Exiting.")
        sys.exit(1)

    if not client.get_csrf_token():
         logging.critical(f"Failed to get CSRF token. Last error: {client.last_api_error}. Exiting.")
         sys.exit(1)

    if not client.authenticate_session():
         logging.critical(f"Failed to authenticate web session. Last error: {client.last_api_error}. Exiting.")
         sys.exit(1)

    logging.info("Initial authentication successful. Starting background threads.")

    threads = []
    session_thread = threading.Thread(target=session_updater_thread, args=(client,), daemon=True)
    plan_thread = threading.Thread(target=plan_manager_thread, args=(client, args.bin), daemon=True)

    threads.extend([session_thread, plan_thread])

    session_thread.start()
    time.sleep(2)
    plan_thread.start()

    try:
        while not shutdown_event.is_set():
             all_alive = all(t.is_alive() for t in threads)
             if not all_alive:
                 logging.warning("One or more worker threads have stopped unexpectedly.")
                 for t in threads:
                     if not t.is_alive():
                          logging.error(f"Thread {t.name} is no longer alive.")
                 logging.error("Initiating shutdown due to thread failure.")
                 shutdown_event.set()
                 break

             time.sleep(LIVENESS_SLEEP_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        logging.info("Ctrl+C detected. Initiating graceful shutdown...")
        shutdown_event.set()

    logging.info("Waiting for worker threads to complete...")
    for t in threads:
        try:
             t.join(timeout=30)
             if t.is_alive():
                  logging.warning(f"Thread {t.name} did not exit cleanly after timeout.")
        except Exception as e:
             logging.error(f"Error joining thread {t.name}: {e}")

    logging.info("All threads finished. Exiting script.")
    sys.exit(0)


if __name__ == "__main__":
    main()
