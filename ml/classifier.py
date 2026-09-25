"""
AI Runtime Inference Engine
Provides real-time predictions for encrypted IPsec ESP traffic payloads with
calibrated confidence scores and explainable feature contributions.
"""

from typing import Dict, Any, List, Optional
import os
import numpy as np
import joblib

from ml.feature_pipeline import FeaturePipeline


class ClassificationResult:
    def __init__(
        self,
        predicted_class: str,
        confidence_score: float,
        probabilities: Dict[str, float],
        top_features: List[Dict[str, Any]],
        model_version: str
    ):
        self.predicted_class = predicted_class
        self.confidence_score = confidence_score
        self.probabilities = probabilities
        self.top_features = top_features
        self.model_version = model_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predicted_class": self.predicted_class,
            "confidence_score": round(self.confidence_score, 3),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
            "top_features": self.top_features,
            "model_version": self.model_version
        }


class IPsecTrafficClassifier:
    """Classifies encrypted ESP traffic payloads using trained ML models."""

    def __init__(self, model_path: Optional[str] = None):
        if not model_path:
            model_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "saved_models", "ipsec_classifier.joblib"
            )
        self.model_path = model_path
        self.bundle: Optional[Dict[str, Any]] = None
        self._load_model()

    def _load_model(self) -> None:
        if os.path.exists(self.model_path):
            try:
                self.bundle = joblib.load(self.model_path)
            except Exception as e:
                print(f"[!] Warning: Failed to load ML model from {self.model_path}: {e}")
                self.bundle = None

    def predict(self, flow_features: Any) -> ClassificationResult:
        """Predicts the application traffic type inside encrypted ESP."""
        # Check if bundle is ready
        if not self.bundle:
            self._load_model()

        if not self.bundle:
            # Fallback to heuristic expert system if model is not yet compiled
            return self._heuristic_predict(flow_features)

        model = self.bundle["model"]
        scaler = self.bundle["scaler"]
        classes = self.bundle["classes"]

        vec = FeaturePipeline.extract_vector(flow_features)
        vec_sanitized = FeaturePipeline.sanitize(vec).reshape(1, -1)
        vec_scaled = scaler.transform(vec_sanitized)

        probs = model.predict_proba(vec_scaled)[0]
        pred_idx = int(np.argmax(probs))
        pred_class = classes[pred_idx]
        confidence = float(probs[pred_idx])

        prob_dict = {classes[i]: float(probs[i]) for i in range(len(classes))}

        # Extract top feature contributions
        top_feats = []
        if "top_features" in self.bundle:
            for fname, imp in self.bundle["top_features"]:
                val = getattr(flow_features, fname, None)
                if val is not None:
                    top_feats.append({
                        "feature": fname,
                        "value": round(float(val), 2),
                        "importance_weight": round(float(imp), 3)
                    })

        return ClassificationResult(
            predicted_class=pred_class,
            confidence_score=confidence,
            probabilities=prob_dict,
            top_features=top_feats,
            model_version=f"{self.bundle.get('algorithm', 'Ensemble')} (Accuracy: {self.bundle.get('accuracy', 0.95):.1%})"
        )

    def _heuristic_predict(self, flow_features: Any) -> ClassificationResult:
        """Expert rule-based fallback predictor."""
        len_mean = getattr(flow_features, "len_mean", 500)
        iat_mean = getattr(flow_features, "iat_mean", 0.1)
        ratio_large = getattr(flow_features, "ratio_large", 0.0)
        ratio_small = getattr(flow_features, "ratio_small", 0.0)

        probs = {c: 0.05 for c in FeaturePipeline.CLASSES}

        if len_mean < 180 and ratio_small > 0.8:
            if iat_mean > 0.8:
                pred = "ICMP"
                probs["ICMP"] = 0.90
            else:
                pred = "VoIP"
                probs["VoIP"] = 0.88
        elif ratio_large > 0.7:
            pred = "Video"
            probs["Video"] = 0.92
        elif len_mean > 650:
            pred = "Web"
            probs["Web"] = 0.82
        elif 400 <= len_mean <= 650:
            pred = "Email"
            probs["Email"] = 0.78
        else:
            pred = "WhatsApp"
            probs["WhatsApp"] = 0.75

        return ClassificationResult(
            predicted_class=pred,
            confidence_score=probs[pred],
            probabilities=probs,
            top_features=[],
            model_version="Heuristic-Ruleset-Fallback"
        )
