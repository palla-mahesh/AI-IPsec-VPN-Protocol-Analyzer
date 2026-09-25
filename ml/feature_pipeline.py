"""
ML Feature Pipeline
Preprocesses flow feature vectors, handles normalization and scaling for inference.
"""

from typing import List, Dict, Any, Tuple
import numpy as np


class FeaturePipeline:
    """Pipelines extracted flow features into numeric arrays suitable for machine learning."""

    FEATURE_NAMES = [
        "len_mean", "len_std", "len_min", "len_max", "len_median",
        "len_q25", "len_q75", "len_q90", "len_skewness",
        "iat_mean", "iat_std", "iat_min", "iat_max", "jitter",
        "pkt_rate", "byte_rate",
        "ratio_small", "ratio_medium", "ratio_large",
        "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio", "avg_burst_size"
    ]

    CLASSES = ["VoIP", "WhatsApp", "Web", "Email", "Video", "ICMP"]

    @staticmethod
    def extract_vector(flow_features: Any) -> np.ndarray:
        """Converts a FlowFeatures object or dict into a 1D numpy array."""
        if hasattr(flow_features, "to_vector"):
            vec = flow_features.to_vector()
        elif isinstance(flow_features, dict):
            vec = [float(flow_features.get(k, 0.0)) for k in FeaturePipeline.FEATURE_NAMES]
        else:
            vec = list(flow_features)
        return np.array(vec, dtype=np.float64)

    @staticmethod
    def sanitize(vector: np.ndarray) -> np.ndarray:
        """Handles any NaN or infinite values safely."""
        return np.nan_to_num(vector, nan=0.0, posinf=1e6, neginf=-1e6)
