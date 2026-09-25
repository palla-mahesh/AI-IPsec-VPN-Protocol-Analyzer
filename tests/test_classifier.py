"""Unit Tests for Machine Learning Flow Classification Engine"""

import pytest
import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_pipeline import FeaturePipeline
from ml.classifier import IPsecTrafficClassifier
from core.flow_extractor import FlowFeatures


def test_feature_pipeline_conversion():
    ff = FlowFeatures()
    ff.len_mean = 140.0
    ff.len_std = 15.0
    ff.iat_mean = 0.02
    ff.pkt_count = 100

    vec = FeaturePipeline.extract_vector(ff)
    assert len(vec) == 22
    assert vec[0] == 140.0

    sanitized = FeaturePipeline.sanitize(np.array([np.nan, np.inf, 42.0]))
    assert sanitized[0] == 0.0
    assert sanitized[1] == 1e6
    assert sanitized[2] == 42.0


def test_classifier_voip_inference():
    classifier = IPsecTrafficClassifier()
    assert classifier.bundle is not None, "Model bundle should be loaded"

    ff = FlowFeatures()
    ff.len_mean = 135.0
    ff.len_std = 12.0
    ff.len_min = 80.0
    ff.len_max = 200.0
    ff.len_median = 135.0
    ff.len_q25 = 125.0
    ff.len_q75 = 145.0
    ff.len_q90 = 155.0
    ff.len_skewness = 0.05
    ff.iat_mean = 0.02
    ff.iat_std = 0.003
    ff.iat_min = 0.015
    ff.iat_max = 0.025
    ff.jitter = 0.002
    ff.pkt_rate = 50.0
    ff.byte_rate = 6750.0
    ff.ratio_small = 0.95
    ff.ratio_medium = 0.05
    ff.ratio_large = 0.0
    ff.fwd_bwd_pkt_ratio = 1.0
    ff.fwd_bwd_byte_ratio = 1.0
    ff.avg_burst_size = 1.2

    res = classifier.predict(ff)
    assert res.predicted_class == "VoIP"
    assert res.confidence_score > 0.70
    assert "VoIP" in res.probabilities
    assert len(res.top_features) > 0


def test_classifier_video_inference():
    classifier = IPsecTrafficClassifier()

    ff = FlowFeatures()
    ff.len_mean = 1380.0
    ff.len_std = 40.0
    ff.len_min = 100.0
    ff.len_max = 1480.0
    ff.len_median = 1460.0
    ff.len_q25 = 1400.0
    ff.len_q75 = 1460.0
    ff.len_q90 = 1480.0
    ff.len_skewness = -1.5
    ff.iat_mean = 0.008
    ff.iat_std = 0.003
    ff.iat_min = 0.001
    ff.iat_max = 0.05
    ff.jitter = 0.003
    ff.pkt_rate = 250.0
    ff.byte_rate = 345000.0
    ff.ratio_small = 0.02
    ff.ratio_medium = 0.05
    ff.ratio_large = 0.93
    ff.fwd_bwd_pkt_ratio = 0.1
    ff.fwd_bwd_byte_ratio = 0.02
    ff.avg_burst_size = 18.0

    res = classifier.predict(ff)
    assert res.predicted_class == "Video"
    assert res.confidence_score > 0.70
