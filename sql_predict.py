"""
sql_predict.py
SQL Injection AI Detection Module
-----------------------------------
Loads a saved Random Forest model + vectorizer and exposes a single
function:  predict_sql_injection(text)  →  dict

Expected files in the project root (same folder as app.py):
    sql_rf_model.pkl      — trained RandomForestClassifier
    sql_vectorizer.pkl    — fitted TfidfVectorizer (or CountVectorizer)

If either file is missing the module falls back gracefully and logs a
warning — the rest of the app continues to work via the rule engine
and the traffic-based IDS model.
"""

import os
import logging
import joblib

logger = logging.getLogger(__name__)

# ── Paths ────────────────────────────────────────────────────────────
_BASE      = os.path.dirname(__file__)
MODEL_PATH = os.path.join(_BASE, "rf_ids_sqli.pkl")
VEC_PATH   = os.path.join(_BASE, "vector_sqli.pkl")

# ── Load once at import time ─────────────────────────────────────────
_model      = None
_vectorizer = None
_available  = False

try:
    _model      = joblib.load(MODEL_PATH)
    _vectorizer = joblib.load(VEC_PATH)
    _available  = True
    logger.info("SQL injection model and vectorizer loaded successfully.")
except FileNotFoundError as e:
    logger.warning(
        f"SQL injection model files not found ({e}). "
        "SQL-AI detection will be skipped — rule engine still active."
    )
except Exception as e:
    logger.error(f"Failed to load SQL injection model: {e}")


# ════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ════════════════════════════════════════════════════════════════════

def is_available() -> bool:
    """Returns True if the model and vectorizer loaded successfully."""
    return _available


def predict_sql_injection(text: str) -> dict:
    """
    Vectorises `text` and runs the Random Forest classifier.

    Parameters
    ----------
    text : str
        Raw user input from any form field (recipient, amount, note, etc.)
        Multiple fields should be concatenated before passing in:
            predict_sql_injection(recipient + " " + amount + " " + note)

    Returns
    -------
    dict with keys:
        is_sql      : bool   — True if injection detected
        confidence  : float  — probability of injection (0.0 – 1.0)
        label       : str    — "SQL_INJECTION" or "NORMAL"
        available   : bool   — False if model files were missing
        raw_text    : str    — the input that was tested (for logging)
    """
    if not _available:
        return {
            "is_sql":     False,
            "confidence": 0.0,
            "label":      "UNAVAILABLE",
            "available":  False,
            "raw_text":   text,
        }

    try:
        # Vectorise
        X = _vectorizer.transform([text])

        # Predict
        prediction  = _model.predict(X)[0]          # 0 = normal, 1 = SQL injection
        probability = _model.predict_proba(X)[0]     # [prob_normal, prob_sql]

        # Probability of the positive (injection) class
        # Works whether the model has classes_ [0,1] or [1,0]
        classes = list(_model.classes_)
        if 1 in classes:
            sql_prob = float(probability[classes.index(1)])
        else:
            sql_prob = float(probability[1])         # fallback

        is_sql = bool(prediction == 1)

        logger.debug(
            f"SQL predict | input='{text[:60]}...' | "
            f"result={'INJECTION' if is_sql else 'NORMAL'} | "
            f"confidence={sql_prob:.3f}"
        )

        return {
            "is_sql":     is_sql,
            "confidence": sql_prob,
            "label":      "SQL_INJECTION" if is_sql else "NORMAL",
            "available":  True,
            "raw_text":   text,
        }

    except Exception as e:
        logger.error(f"SQL prediction error: {e}")
        return {
            "is_sql":     False,
            "confidence": 0.0,
            "label":      "ERROR",
            "available":  False,
            "raw_text":   text,
            "error":      str(e),
        }


def predict_sql_from_fields(fields: dict) -> dict:
    """
    Convenience wrapper: concatenates all string values from `fields`
    dict and passes the combined string to predict_sql_injection().

    Usage:
        result = predict_sql_from_fields({
            "recipient": request.json.get("recipient"),
            "amount":    request.json.get("amount"),
        })
    """
    combined = " ".join(str(v) for v in fields.values() if v is not None)
    return predict_sql_injection(combined)
