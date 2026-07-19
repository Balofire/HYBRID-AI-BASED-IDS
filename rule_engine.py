"""
rule_engine.py
Rule-Based Intrusion Detection Engine
--------------------------------------
Implements five detection rules:
  1. Brute Force       — >5 failed logins from same IP within 60s
  2. DoS               — >10 requests from same IP within 10s
  3. API Abuse         — >10 requests to same endpoint within 10s
  4. Large Payload     — request body exceeds configurable byte threshold
  5. Invalid Form      — missing, malformed, or unexpected field values
"""

import time
from collections import defaultdict

# ════════════════════════════════════════════════════════════════════
#  CONFIGURABLE THRESHOLDS
# ════════════════════════════════════════════════════════════════════

BRUTE_FORCE_MAX_ATTEMPTS  = 4     # max failed logins before flagging
BRUTE_FORCE_WINDOW_SEC    = 10    # rolling window in seconds

DOS_MAX_REQUESTS          = 5    # max requests per IP before flagging
DOS_WINDOW_SEC            = 10    # rolling window in seconds

API_ABUSE_MAX_REQUESTS    = 5    # max hits to same endpoint before flagging
API_ABUSE_WINDOW_SEC      = 10    # rolling window in seconds

LARGE_PAYLOAD_THRESHOLD   = 2048  # bytes — flag if body exceeds this


# ════════════════════════════════════════════════════════════════════
#  IN-MEMORY STORES  (keyed by IP or endpoint)
# ════════════════════════════════════════════════════════════════════

# Each value is a list of UNIX timestamps
_brute_force_store: dict[str, list[float]] = defaultdict(list)
_dos_store:         dict[str, list[float]] = defaultdict(list)
_api_abuse_store:   dict[str, list[float]] = defaultdict(list)


def _prune(timestamps: list[float], window: float) -> list[float]:
    """Remove timestamps older than `window` seconds from now."""
    cutoff = time.time() - window
    return [t for t in timestamps if t > cutoff]


# ════════════════════════════════════════════════════════════════════
#  RULE 1 — BRUTE FORCE
# ════════════════════════════════════════════════════════════════════

def record_failed_login(ip: str) -> None:
    """Call this every time a login attempt FAILS for the given IP."""
    _brute_force_store[ip] = _prune(_brute_force_store[ip], BRUTE_FORCE_WINDOW_SEC)
    _brute_force_store[ip].append(time.time())


def reset_failed_logins(ip: str) -> None:
    """Call this when a login SUCCEEDS so the counter resets."""
    _brute_force_store[ip] = []


def check_brute_force(ip: str) -> dict:
    """
    Returns a result dict.
    Flagged when failed attempts in the last 60 s exceed the threshold.
    """
    _brute_force_store[ip] = _prune(_brute_force_store[ip], BRUTE_FORCE_WINDOW_SEC)
    count = len(_brute_force_store[ip])

    if count > BRUTE_FORCE_MAX_ATTEMPTS:
        return {
            "flagged":  True,
            "rule":     "BRUTE_FORCE",
            "message":  (
                f"Brute force detected: {count} failed login attempts "
                f"from {ip} within {BRUTE_FORCE_WINDOW_SEC}s "
                f"(threshold: {BRUTE_FORCE_MAX_ATTEMPTS})"
            ),
            "count":    count,
            "ip":       ip,
        }
    return {"flagged": False, "rule": "BRUTE_FORCE", "count": count}


# ════════════════════════════════════════════════════════════════════
#  RULE 2 — DENIAL OF SERVICE
# ════════════════════════════════════════════════════════════════════

def check_dos(ip: str) -> dict:
    """
    Records every call and flags when the same IP exceeds
    DOS_MAX_REQUESTS within DOS_WINDOW_SEC seconds.
    Call this at the top of every route you want protected.
    """
    _dos_store[ip] = _prune(_dos_store[ip], DOS_WINDOW_SEC)
    _dos_store[ip].append(time.time())
    count = len(_dos_store[ip])

    if count > DOS_MAX_REQUESTS:
        return {
            "flagged":  True,
            "rule":     "DOS",
            "message":  (
                f"DoS detected: {count} requests from {ip} "
                f"within {DOS_WINDOW_SEC}s "
                f"(threshold: {DOS_MAX_REQUESTS})"
            ),
            "count":    count,
            "ip":       ip,
        }
    return {"flagged": False, "rule": "DOS", "count": count}


# ════════════════════════════════════════════════════════════════════
#  RULE 3 — API ABUSE
# ════════════════════════════════════════════════════════════════════

def check_api_abuse(endpoint: str) -> dict:
    """
    Records every call to `endpoint` and flags when it exceeds
    API_ABUSE_MAX_REQUESTS within API_ABUSE_WINDOW_SEC seconds.
    `endpoint` should be a stable string, e.g. request.path.
    """
    _api_abuse_store[endpoint] = _prune(
        _api_abuse_store[endpoint], API_ABUSE_WINDOW_SEC
    )
    _api_abuse_store[endpoint].append(time.time())
    count = len(_api_abuse_store[endpoint])

    if count > API_ABUSE_MAX_REQUESTS:
        return {
            "flagged":  True,
            "rule":     "DOS",
            "message":  (
                f"API abuse detected: {count} requests to '{endpoint}' "
                f"within {API_ABUSE_WINDOW_SEC}s "
                f"(threshold: {API_ABUSE_MAX_REQUESTS})"
            ),
            "count":    count,
            "endpoint": endpoint,
        }
    return {"flagged": False, "rule": "DOS", "count": count}


# ════════════════════════════════════════════════════════════════════
#  RULE 4 — LARGE PAYLOAD
# ════════════════════════════════════════════════════════════════════

def check_large_payload(request_data: str | bytes,
                        threshold: int = LARGE_PAYLOAD_THRESHOLD) -> dict:
    """
    Flags when the serialised request body exceeds `threshold` bytes.
    Pass request.get_data() or json.dumps(request.json) as request_data.
    """
    if isinstance(request_data, str):
        size = len(request_data.encode("utf-8"))
    else:
        size = len(request_data)

    if size > threshold:
        return {
            "flagged":  True,
            "rule":     "LARGE_PAYLOAD",
            "message":  (
                f"Large payload detected: {size} bytes received "
                f"(threshold: {threshold} bytes)"
            ),
            "size_bytes": size,
        }
    return {"flagged": False, "rule": "LARGE_PAYLOAD", "size_bytes": size}


# ════════════════════════════════════════════════════════════════════
#  RULE 5 — INVALID / MALFORMED FORM INPUT
# ════════════════════════════════════════════════════════════════════

def check_invalid_form(fields: dict,
                       required: list[str] | None = None,
                       numeric: list[str]  | None = None) -> dict:
    """
    Validates a flat dict of form values.

    Parameters
    ----------
    fields   : dict of field_name → value (strings expected)
    required : list of field names that must be non-empty
    numeric  : list of field names whose values must be parseable as float

    Returns a flagged result if any check fails.
    """
    required = required or []
    numeric  = numeric  or []

    # 1 — missing / empty required fields
    for name in required:
        val = str(fields.get(name, "")).strip()
        if not val:
            return {
                "flagged": True,
                "rule":    "INVALID_FORM",
                "message": f"Missing required field: '{name}'",
                "field":   name,
            }

    # 2 — non-numeric values in numeric fields
    for name in numeric:
        val = str(fields.get(name, "")).strip()
        try:
            float(val)
        except (ValueError, TypeError):
            return {
                "flagged": True,
                "rule":    "INVALID_FORM",
                "message": (
                    f"Invalid value for numeric field '{name}': "
                    f"received '{val}'"
                ),
                "field":   name,
            }

    # 3 — unexpected / suspiciously long individual field values
    for name, val in fields.items():
        val_str = str(val)
        if len(val_str) > 512:
            return {
                "flagged": True,
                "rule":    "INVALID_FORM",
                "message": (
                    f"Suspiciously long value in field '{name}': "
                    f"{len(val_str)} characters"
                ),
                "field":   name,
            }

    return {"flagged": False, "rule": "INVALID_FORM"}


# ════════════════════════════════════════════════════════════════════
#  COMPOSITE HELPER — run all relevant rules in one call
# ════════════════════════════════════════════════════════════════════

def run_all_rules(ip: str,
                  endpoint: str,
                  request_body: str | bytes = "",
                  form_fields:  dict | None = None,
                  required_fields: list[str] | None = None,
                  numeric_fields:  list[str] | None = None) -> dict:
    """
    Convenience wrapper that runs DoS, API abuse, large payload,
    and optional form checks in sequence.
    Returns the FIRST flagged result, or a clean result if all pass.

    Note: brute-force is NOT included here because it requires
    explicit recording of failed attempts — call check_brute_force()
    separately inside your login route.
    """
    checks = [
        check_dos(ip),
        check_api_abuse(endpoint),
        check_large_payload(request_body),
    ]

    if form_fields is not None:
        checks.append(
            check_invalid_form(
                form_fields,
                required=required_fields,
                numeric=numeric_fields,
            )
        )

    for result in checks:
        if result.get("flagged"):
            return result

    return {
        "flagged": False,
        "rule":    "NONE",
        "message": "All rule checks passed",
    }
