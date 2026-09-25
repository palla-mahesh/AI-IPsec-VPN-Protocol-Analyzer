"""
Flow Feature Extraction Engine
Extracts flow-level statistical and temporal features from encrypted IPsec ESP traffic
for AI-based traffic payload fingerprinting and classification.
"""

from typing import List, Dict, Any, Tuple
import numpy as np


class FlowFeatures:
    """Container for computed statistical features of a network flow."""

    def __init__(self):
        # Packet length metrics
        self.pkt_count: int = 0
        self.byte_count: int = 0
        self.duration: float = 0.0
        self.len_mean: float = 0.0
        self.len_std: float = 0.0
        self.len_min: float = 0.0
        self.len_max: float = 0.0
        self.len_median: float = 0.0
        self.len_q25: float = 0.0
        self.len_q75: float = 0.0
        self.len_q90: float = 0.0
        self.len_skewness: float = 0.0

        # Inter-arrival time (IAT) metrics
        self.iat_mean: float = 0.0
        self.iat_std: float = 0.0
        self.iat_min: float = 0.0
        self.iat_max: float = 0.0
        self.jitter: float = 0.0

        # Rate metrics
        self.pkt_rate: float = 0.0
        self.byte_rate: float = 0.0

        # Packet size bin ratios
        self.ratio_small: float = 0.0   # < 200B
        self.ratio_medium: float = 0.0  # 200B - 900B
        self.ratio_large: float = 0.0   # > 900B

        # Directional & burst features
        self.fwd_bwd_pkt_ratio: float = 1.0
        self.fwd_bwd_byte_ratio: float = 1.0
        self.burst_count: int = 0
        self.avg_burst_size: float = 0.0

    def to_vector(self) -> List[float]:
        """Returns the numerical feature vector in fixed order for ML model input."""
        return [
            self.len_mean,
            self.len_std,
            self.len_min,
            self.len_max,
            self.len_median,
            self.len_q25,
            self.len_q75,
            self.len_q90,
            self.len_skewness,
            self.iat_mean,
            self.iat_std,
            self.iat_min,
            self.iat_max,
            self.jitter,
            self.pkt_rate,
            self.byte_rate,
            self.ratio_small,
            self.ratio_medium,
            self.ratio_large,
            self.fwd_bwd_pkt_ratio,
            self.fwd_bwd_byte_ratio,
            self.avg_burst_size
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "len_mean", "len_std", "len_min", "len_max", "len_median",
            "len_q25", "len_q75", "len_q90", "len_skewness",
            "iat_mean", "iat_std", "iat_min", "iat_max", "jitter",
            "pkt_rate", "byte_rate",
            "ratio_small", "ratio_medium", "ratio_large",
            "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio", "avg_burst_size"
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pkt_count": self.pkt_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration, 4),
            "len_mean": round(self.len_mean, 2),
            "len_std": round(self.len_std, 2),
            "len_min": round(self.len_min, 1),
            "len_max": round(self.len_max, 1),
            "len_median": round(self.len_median, 1),
            "iat_mean": round(self.iat_mean, 5),
            "iat_std": round(self.iat_std, 5),
            "jitter": round(self.jitter, 5),
            "pkt_rate": round(self.pkt_rate, 2),
            "byte_rate": round(self.byte_rate, 2),
            "ratio_small": round(self.ratio_small, 3),
            "ratio_medium": round(self.ratio_medium, 3),
            "ratio_large": round(self.ratio_large, 3),
            "fwd_bwd_pkt_ratio": round(self.fwd_bwd_pkt_ratio, 3),
            "avg_burst_size": round(self.avg_burst_size, 2)
        }


class FlowExtractor:
    """Extracts flow features from raw packets."""

    @staticmethod
    def extract_from_packets(packets: List[Dict[str, Any]]) -> FlowFeatures:
        ff = FlowFeatures()
        esp_packets = [p for p in packets if p.get("protocol") in ("ESP", "ESP-in-UDP")]

        if not esp_packets:
            return ff

        ff.pkt_count = len(esp_packets)
        lengths = [p.get("length", 0) for p in esp_packets]
        timestamps = [p.get("timestamp", 0.0) for p in esp_packets]
        ff.byte_count = sum(lengths)

        # Sort chronologically
        sorted_pairs = sorted(zip(timestamps, lengths, esp_packets), key=lambda x: x[0])
        timestamps = [x[0] for x in sorted_pairs]
        lengths = [x[1] for x in sorted_pairs]

        t_min = timestamps[0]
        t_max = timestamps[-1]
        ff.duration = max(0.001, t_max - t_min)

        # Length metrics
        arr_len = np.array(lengths, dtype=np.float64)
        ff.len_mean = float(np.mean(arr_len))
        ff.len_std = float(np.std(arr_len)) if len(arr_len) > 1 else 0.0
        ff.len_min = float(np.min(arr_len))
        ff.len_max = float(np.max(arr_len))
        ff.len_median = float(np.median(arr_len))
        ff.len_q25 = float(np.percentile(arr_len, 25))
        ff.len_q75 = float(np.percentile(arr_len, 75))
        ff.len_q90 = float(np.percentile(arr_len, 90))

        # Skewness calculation
        if ff.len_std > 0 and len(arr_len) > 2:
            m3 = np.mean((arr_len - ff.len_mean) ** 3)
            ff.len_skewness = float(m3 / (ff.len_std ** 3))

        # Inter-arrival times
        if len(timestamps) > 1:
            iats = np.diff(timestamps)
            # Remove negative jitter if any
            iats = np.maximum(iats, 0.0)
            ff.iat_mean = float(np.mean(iats))
            ff.iat_std = float(np.std(iats))
            ff.iat_min = float(np.min(iats))
            ff.iat_max = float(np.max(iats))
            # Jitter: mean difference between consecutive IATs
            if len(iats) > 1:
                ff.jitter = float(np.mean(np.abs(np.diff(iats))))

        # Rate metrics
        ff.pkt_rate = ff.pkt_count / ff.duration
        ff.byte_rate = ff.byte_count / ff.duration

        # Size bin ratios
        small_count = sum(1 for l in lengths if l < 200)
        med_count = sum(1 for l in lengths if 200 <= l <= 900)
        large_count = sum(1 for l in lengths if l > 900)
        total = float(len(lengths))
        ff.ratio_small = small_count / total
        ff.ratio_medium = med_count / total
        ff.ratio_large = large_count / total

        # Directional calculation (first seen IP is forward)
        fwd_ip = esp_packets[0].get("src_ip", "")
        fwd_pkts = sum(1 for p in esp_packets if p.get("src_ip") == fwd_ip)
        bwd_pkts = max(1, len(esp_packets) - fwd_pkts)
        ff.fwd_bwd_pkt_ratio = fwd_pkts / float(bwd_pkts)

        fwd_bytes = sum(p.get("length", 0) for p in esp_packets if p.get("src_ip") == fwd_ip)
        bwd_bytes = max(1, sum(p.get("length", 0) for p in esp_packets if p.get("src_ip") != fwd_ip))
        ff.fwd_bwd_byte_ratio = fwd_bytes / float(bwd_bytes)

        # Burst calculations (packets within 50ms of each other)
        bursts = []
        current_burst = 1
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i-1] < 0.05:
                current_burst += 1
            else:
                bursts.append(current_burst)
                current_burst = 1
        bursts.append(current_burst)
        ff.burst_count = len(bursts)
        ff.avg_burst_size = float(np.mean(bursts)) if bursts else 1.0

        return ff
