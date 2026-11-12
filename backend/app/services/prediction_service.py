"""
PhishGuard AI - Machine Learning Prediction Service
===================================================
Loads the trained Scikit-learn phishing detection pipeline and executes inference
on extracted URL characteristics.

Guarantees:
- Never fakes predictions or hardcodes random outputs.
- Gracefully reports ML as unavailable if the model artifact is missing.
- Keeps ML prediction and rule-based risk score conceptually separate.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
import joblib
import numpy as np
import pandas as pd
from app.config.settings import settings

logger = logging.getLogger("phishguard.ml")

# Canonical 11 features matching the model training pipeline
CANONICAL_FEATURE_NAMES: List[str] = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "special_char_count",
    "digits_count",
    "entropy",
    "tld",
]


class PredictionService:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.MODEL_PATH
        self.resolved_model_path: Optional[str] = None
        self.model: Optional[Any] = None
        self.feature_names: List[str] = CANONICAL_FEATURE_NAMES
        self.metadata: Dict[str, Any] = {}
        self.is_loaded: bool = False
        self.status_message: str = "ML model has not been initialized."

    def _resolve_path(self, target_path: str) -> Optional[str]:
        """Resolve model path across various working directory execution contexts."""
        if not target_path:
            return None

        # If an explicit custom model path is provided, strictly check only that target
        if target_path != settings.MODEL_PATH:
            if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                return os.path.abspath(target_path)
            cwd_cand = os.path.join(os.getcwd(), target_path)
            if os.path.exists(cwd_cand) and os.path.getsize(cwd_cand) > 0:
                return os.path.abspath(cwd_cand)
            return None

        # When resolving the default model path, check multiple standard locations
        candidates = [
            target_path,
            os.path.abspath(target_path),
            os.path.join(os.getcwd(), target_path),
            # Workspace root relative
            os.path.join(os.getcwd(), "model", "artifacts", "phishing_model.pkl"),
            # Backend relative
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "model", "artifacts", "phishing_model.pkl"),
        ]

        for cand in candidates:
            if cand and os.path.exists(cand) and os.path.getsize(cand) > 0:
                return os.path.abspath(cand)

        return None

    def load_model(self) -> bool:
        """
        Load serialized ML model, feature names, and metadata from disk if available.
        Does not fake predictions or fail the application if files are missing or uninitialized.
        """
        resolved = self._resolve_path(self.model_path)
        if not resolved:
            self.is_loaded = False
            self.model = None
            self.status_message = "ML model artifact not found. Rule-based URL analysis remains available."
            logger.info("ML Model status: %s (attempted: %s)", self.status_message, self.model_path)
            return False

        self.resolved_model_path = resolved

        try:
            logger.info("Loading Scikit-learn phishing detection pipeline from %s...", self.resolved_model_path)
            self.model = joblib.load(self.resolved_model_path)

            base_dir = os.path.dirname(self.resolved_model_path)
            feature_names_path = os.path.join(base_dir, "feature_names.json")
            if os.path.exists(feature_names_path):
                with open(feature_names_path, "r", encoding="utf-8") as f:
                    self.feature_names = json.load(f)
                logger.info("Loaded %d feature names from %s", len(self.feature_names), feature_names_path)
            else:
                self.feature_names = CANONICAL_FEATURE_NAMES

            metadata_path = os.path.join(base_dir, "model_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            self.is_loaded = True
            self.status_message = "ML model loaded successfully and ready for inference."
            logger.info("ML Model status: %s", self.status_message)
            return True

        except Exception as exc:
            self.is_loaded = False
            self.model = None
            self.status_message = f"Failed to deserialize ML model: {str(exc)}"
            logger.error("Error loading ML model from %s: %s", self.resolved_model_path, exc)
            return False

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic status of the ML prediction subsystem."""
        return {
            "available": self.is_loaded,
            "model_path": self.resolved_model_path or self.model_path,
            "model_version": self.metadata.get("version", "1.0.0" if self.is_loaded else None),
            "algorithm": self.metadata.get("algorithm", "Random Forest" if self.is_loaded else None),
            "features_count": len(self.feature_names) if self.feature_names else 0,
            "message": self.status_message,
        }

    def predict(self, url_characteristics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference if model is loaded.
        Returns prediction details with clear availability status.
        """
        if not self.is_loaded or self.model is None:
            return {
                "available": False,
                "prediction": None,
                "confidence": None,
                "phishing_probability": None,
                "model_version": None,
                "features_evaluated": 0,
                "message": (
                    "Machine learning analysis is currently unavailable. "
                    "This result is based on the available URL security checks."
                ),
            }

        try:
            # Build DataFrame matching the exact feature names expected by ColumnTransformer
            row_dict = self._build_feature_row(url_characteristics)
            X_df = pd.DataFrame([row_dict])

            # Ensure columns are in the exact order expected
            feature_order = self.feature_names if self.feature_names else CANONICAL_FEATURE_NAMES
            X_df = X_df[feature_order]

            raw_prediction = self.model.predict(X_df)[0]

            # Normalize output to canonical string label
            if isinstance(raw_prediction, (int, np.integer)):
                pred_label = "PHISHING" if int(raw_prediction) == 1 else "LEGITIMATE"
            else:
                pred_label = str(raw_prediction).upper()

            # Confidence estimation via predict_proba
            confidence = None
            phishing_probability = None
            if hasattr(self.model, "predict_proba"):
                try:
                    probas = self.model.predict_proba(X_df)[0]
                    classes = list(self.model.classes_)
                    # Confidence is probability assigned to the predicted class
                    pred_class = raw_prediction if raw_prediction in classes else (
                        1 if pred_label == "PHISHING" else 0
                    )
                    if pred_class in classes:
                        confidence = float(probas[classes.index(pred_class)])
                    else:
                        confidence = float(np.max(probas))

                    # Phishing probability specifically
                    if 1 in classes:
                        phishing_probability = float(probas[classes.index(1)])
                    elif "1" in classes:
                        phishing_probability = float(probas[classes.index("1")])
                    elif "PHISHING" in classes:
                        phishing_probability = float(probas[classes.index("PHISHING")])
                except Exception as prob_err:
                    logger.warning("predict_proba failed: %s", prob_err)

            return {
                "available": True,
                "prediction": pred_label,
                "confidence": round(confidence, 4) if confidence is not None else None,
                "phishing_probability": round(phishing_probability, 4) if phishing_probability is not None else None,
                "model_version": self.metadata.get("version", "1.0.0"),
                "features_evaluated": len(feature_order),
                "message": f"ML model inference executed successfully ({pred_label}).",
            }

        except Exception as exc:
            logger.error("Inference execution failed: %s", exc)
            return {
                "available": False,
                "prediction": None,
                "confidence": None,
                "phishing_probability": None,
                "model_version": None,
                "features_evaluated": 0,
                "message": f"ML inference error: {str(exc)}",
            }

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        """Safely coerce any numeric or string value to integer."""
        if isinstance(val, (int, np.integer)):
            return int(val)
        if isinstance(val, bool):
            return 1 if val else 0
        try:
            return int(float(val))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _safe_float(val: Any, default: float = 0.0) -> float:
        """Safely coerce any numeric or string value to float."""
        if isinstance(val, (int, float, np.floating, np.integer)):
            return float(val)
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def _build_feature_row(self, char: Dict[str, Any]) -> Dict[str, Any]:
        """Convert URL characteristics dict to dictionary of 11 canonical features."""
        # Handle has_https boolean / int / string
        has_https_val = char.get("has_https", 0)
        has_https = 1 if (has_https_val is True or has_https_val == 1 or str(has_https_val).lower() == "true") else 0

        # Handle has_ip boolean / int / string
        has_ip_val = char.get("has_ip", 0)
        has_ip = 1 if (has_ip_val is True or has_ip_val == 1 or str(has_ip_val).lower() == "true") else 0

        # Handle TLD (default Unknown if missing)
        tld_val = char.get("tld")
        if not tld_val or tld_val == "None":
            tld_val = "Unknown"

        return {
            "url_length": self._safe_int(char.get("url_length")),
            "num_dots": self._safe_int(char.get("num_dots", char.get("dot_count"))),
            "has_https": has_https,
            "has_ip": has_ip,
            "num_subdirs": self._safe_int(char.get("num_subdirs")),
            "num_params": self._safe_int(char.get("num_params", char.get("param_count"))),
            "suspicious_words": self._safe_int(char.get("suspicious_words", char.get("suspicious_keywords_count"))),
            "special_char_count": self._safe_int(char.get("special_char_count")),
            "digits_count": self._safe_int(char.get("digits_count")),
            "entropy": self._safe_float(char.get("entropy", char.get("url_entropy"))),
            "tld": str(tld_val),
        }


# Singleton instance
prediction_service = PredictionService()
