"""
ensemble.py — Hybrid ML & DL Malware Detection Soft-Voting Ensemble Engine.

Combines two independent AI perspectives:
  1. Static Structural Analysis (LightGBM on 2,381 PE features)
  2. Deep Learning Vision Analysis (ResNet-18 2D-CNN on 256x256 byte images)

Soft-Voting Fusion:
  P_ensemble = w_lgbm * P_lgbm + w_cnn * P_cnn (default: 50/50 weighting)

Confidence & Risk Branching:
  - High Malicious Confidence: P >= 0.75  -> MALWARE (HIGH Risk)
  - Grey Zone / Disagreement: 0.40 <= P < 0.75 -> SUSPICIOUS (MEDIUM Risk)
  - High Safe Confidence: P < 0.40       -> SAFE (LOW Risk)
  - Auto-Quarantine Eligible: P >= 0.85
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from .engine import Engine, MLResult, get_engine, MALWARE, SAFE, ERROR
from .vision import VisionEngine, VisionResult, get_vision_engine
from .hashing import sha256_bytes

SUSPICIOUS = "SUSPICIOUS"


@dataclass
class EnsembleResult:
    """Consolidated verdict from both LightGBM and ResNet-18 engines."""
    final_verdict: str                # MALWARE | SUSPICIOUS | SAFE | ERROR
    risk_level: str                   # HIGH | MEDIUM | LOW | UNKNOWN
    lgbm_verdict: str                 # MALWARE | SAFE | ERROR
    cnn_verdict: str                  # MALWARE | SAFE | ERROR
    combined_prob: float | None = None  # Ensemble soft-voted probability P in [0.0, 1.0]
    lgbm_prob: float | None = None
    cnn_prob: float | None = None
    models_disagree: bool = False     # True if one model is MALWARE and the other SAFE
    auto_quarantine: bool = False     # True if P >= 0.85
    error: str | None = None


class EnsembleEngine:
    """Orchestrates independent predictions from LightGBM and ResNet-18."""

    def __init__(
        self,
        lgbm_engine: Engine | None = None,
        vision_engine: VisionEngine | None = None,
        w_lgbm: float = 0.50,
        w_cnn: float = 0.50,
        high_threshold: float = 0.75,
        low_threshold: float = 0.40,
        quarantine_threshold: float = 0.85,
    ):
        self.lgbm_engine = lgbm_engine or get_engine()
        self.vision_engine = vision_engine or get_vision_engine()
        self.w_lgbm = w_lgbm
        self.w_cnn = w_cnn
        self.high_threshold = high_threshold
        self.low_threshold = low_threshold
        self.quarantine_threshold = quarantine_threshold

    def combine_probabilities(
        self, lgbm_res: MLResult, cnn_res: VisionResult
    ) -> EnsembleResult:
        """Fuses independent probabilities using calibrated soft-voting."""
        lp = lgbm_res.lgbm_prob
        cp = cnn_res.cnn_prob

        # Case 1: Both models successfully evaluated
        if lp is not None and cp is not None:
            combined = (self.w_lgbm * lp) + (self.w_cnn * cp)
            disagree = (lgbm_res.ml_verdict != cnn_res.cnn_verdict)

            if combined >= self.high_threshold:
                verdict = MALWARE
                risk = "HIGH"
            elif combined >= self.low_threshold:
                verdict = SUSPICIOUS
                risk = "MEDIUM"
            else:
                verdict = SAFE
                risk = "LOW"

            auto_q = bool(combined >= self.quarantine_threshold)

            return EnsembleResult(
                final_verdict=verdict,
                combined_prob=round(combined, 4),
                risk_level=risk,
                lgbm_verdict=lgbm_res.ml_verdict,
                lgbm_prob=round(lp, 4),
                cnn_verdict=cnn_res.cnn_verdict,
                cnn_prob=round(cp, 4),
                models_disagree=disagree,
                auto_quarantine=auto_q,
                error=None,
            )

        # Case 2: One model succeeded, one failed (graceful degradation)
        if lp is not None and cp is None:
            # Fall back to LightGBM
            verdict = lgbm_res.ml_verdict
            risk = "HIGH" if verdict == MALWARE else "LOW"
            return EnsembleResult(
                final_verdict=verdict,
                combined_prob=round(lp, 4),
                risk_level=risk,
                lgbm_verdict=lgbm_res.ml_verdict,
                lgbm_prob=round(lp, 4),
                cnn_verdict=cnn_res.cnn_verdict,
                cnn_prob=None,
                models_disagree=False,
                auto_quarantine=bool(lp >= self.quarantine_threshold),
                error=f"Vision model degraded: {cnn_res.error}",
            )

        if cp is not None and lp is None:
            # Fall back to Vision ResNet-18
            verdict = cnn_res.cnn_verdict
            risk = "HIGH" if verdict == MALWARE else "LOW"
            return EnsembleResult(
                final_verdict=verdict,
                combined_prob=round(cp, 4),
                risk_level=risk,
                lgbm_verdict=lgbm_res.ml_verdict,
                lgbm_prob=None,
                cnn_verdict=cnn_res.cnn_verdict,
                cnn_prob=round(cp, 4),
                models_disagree=False,
                auto_quarantine=bool(cp >= self.quarantine_threshold),
                error=f"LightGBM model degraded: {lgbm_res.error}",
            )

        # Case 3: Both models errored (fail-closed policy)
        return EnsembleResult(
            final_verdict=ERROR,
            combined_prob=None,
            risk_level="UNKNOWN",
            lgbm_verdict=ERROR,
            cnn_verdict=ERROR,
            error=f"LGBM error: {lgbm_res.error}; CNN error: {cnn_res.error}",
        )

    def classify_bytes(self, data: bytes) -> EnsembleResult:
        """Run parallel analysis on raw bytes through both engines."""
        lgbm_res = self.lgbm_engine.classify_bytes(data)
        cnn_res = self.vision_engine.classify_bytes(data)
        return self.combine_probabilities(lgbm_res, cnn_res)

    def classify_file(self, path: Path | str) -> Tuple[EnsembleResult, str | None, int]:
        """Read file once, generate SHA-256 hash, and execute hybrid classification."""
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            err_res = EnsembleResult(
                final_verdict=ERROR,
                combined_prob=None,
                risk_level="UNKNOWN",
                lgbm_verdict=ERROR,
                cnn_verdict=ERROR,
                error=f"Read failed: {e}",
            )
            return err_res, None, 0

        sha = sha256_bytes(data)
        ens_res = self.classify_bytes(data)
        return ens_res, sha, len(data)


# ── Shared Singleton Instance ────────────────────────────────────────────────

_ENSEMBLE_ENGINE: EnsembleEngine | None = None


def get_ensemble_engine() -> EnsembleEngine:
    """Returns a shared singleton instance of EnsembleEngine."""
    global _ENSEMBLE_ENGINE
    if _ENSEMBLE_ENGINE is None:
        _ENSEMBLE_ENGINE = EnsembleEngine()
    return _ENSEMBLE_ENGINE


def reset_ensemble_engine() -> None:
    """Resets the singleton instance."""
    global _ENSEMBLE_ENGINE
    _ENSEMBLE_ENGINE = None
