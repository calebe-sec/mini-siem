from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES, WindowFeatures, to_matrix

logger = logging.getLogger(__name__)

# Bump when the saved payload layout changes.
MODEL_FORMAT_VERSION = 1


@dataclass(frozen=True)
class Anomaly:
    """What the ML layer hands to the alert manager and to the LLM triage step."""

    entity: str                                
    window_start: datetime
    window_end: datetime
    score: float                                
    threshold: float                           
    features: dict[str, float]
    top_deviations: list[tuple[str, float]]     
    source: str = "ml"                          

    def to_dict(self) -> dict:
        """JSON-ready dict, for the LLM prompt or a future logrecon_client call."""
        return {
            "source": self.source,
            "entity": self.entity,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "score": self.score,
            "threshold": self.threshold,
            "features": self.features,
            "top_deviations": [{"feature": f, "z": z} for f, z in self.top_deviations],
        }


@dataclass(frozen=True)
class _FittedState:
    model: IsolationForest
    threshold: float
    mean: np.ndarray
    std: np.ndarray


class AnomalyDetector:
    def __init__(self,
        n_estimators: int = 200,
        threshold_percentile: float = 1.0,
        random_state: int | None = 42,
        min_train_windows: int = 100,
        top_k: int = 3, ) -> None:

        if n_estimators < 1:
            raise ValueError("n_estimators must be at least 1")
        if not 0 < threshold_percentile < 50:
            raise ValueError("threshold_percentile must be between 0 and 50 (exclusive)")
        if top_k < 1:
            raise ValueError("top_k must be at least 1")
        
        self.n_estimators = n_estimators
        self.threshold_percentile = threshold_percentile
        self.random_state = random_state
        self.min_train_windows = min_train_windows
        self.top_k = top_k
        self._state: _FittedState | None = None

    def fit(self,
        windows: Sequence[WindowFeatures],
        calibration: Sequence[WindowFeatures] | None = None, ) -> "AnomalyDetector":
        
        if len(windows) < self.min_train_windows:
            raise ValueError(
                f"Need at least {self.min_train_windows} clean windows to train, got {len(windows)}."
            )

        X = to_matrix(windows)
        # No scaler: trees compare each feature to split points, so scale does not matter.
        model = IsolationForest(n_estimators=self.n_estimators, random_state=self.random_state)
        model.fit(X)

        reference = to_matrix(calibration) if calibration else X
        if len(reference) * self.threshold_percentile / 100 < 1:
            logger.warning(
                "Reference set has %d windows: the %.2f percentile is unstable below %d.",
                len(reference),
                self.threshold_percentile,
                math.ceil(100 / self.threshold_percentile),
            )
        threshold = float(np.percentile(model.score_samples(reference), self.threshold_percentile))

        std = X.std(axis=0)
        self._state = _FittedState(
            model=model,
            threshold=threshold,
            mean=X.mean(axis=0),
            std=np.where(std > 0, std, 1.0),   # constant feature: avoid dividing by zero
        )
        logger.info(
            "Fitted on %d windows, threshold=%.4f (percentile %.2f of %s)",
            len(windows),
            threshold,
            self.threshold_percentile,
            "calibration set" if calibration else "training set",
        )
        return self

    # ----------------------------------------------------------------- inference

    @property
    def is_fitted(self) -> bool:
        return self._state is not None

    @property
    def threshold_(self) -> float | None:
        return None if self._state is None else self._state.threshold

    def score(self, windows: Sequence[WindowFeatures]) -> np.ndarray:
        """Raw anomaly scores, one per window. Lower means more anomalous."""
        state = self._require_fitted()
        if not windows:
            return np.empty(0, dtype=float)
        return state.model.score_samples(to_matrix(windows))

    def detect(self, windows: Sequence[WindowFeatures]) -> list[Anomaly]:
        """Return the windows scoring below the threshold, most anomalous first."""
        state = self._require_fitted()
        if not windows:
            return []

        X = to_matrix(windows)
        scores = state.model.score_samples(X)

        anomalies = [
            Anomaly(
                entity=windows[i].entity,
                window_start=windows[i].window_start,
                window_end=windows[i].window_end,
                score=float(scores[i]),
                threshold=state.threshold,
                features=windows[i].as_dict(),
                top_deviations=self._top_deviations(state, X[i]),
            )
            for i in np.flatnonzero(scores < state.threshold)
        ]
        anomalies.sort(key=lambda a: a.score)
        return anomalies

    def _top_deviations(self, state: _FittedState, x: np.ndarray) -> list[tuple[str, float]]:
        """Features furthest from the clean baseline, in standard deviations.

        Isolation Forest has no built-in explanation; this simple comparison is what
        gives the LLM something concrete to talk about.
        """
        z = (x - state.mean) / state.std
        order = np.argsort(-np.abs(z))[: self.top_k]
        return [(FEATURE_NAMES[i], float(z[i])) for i in order]

    # --------------------------------------------------------------- persistence

    def save(self, path: str | Path) -> None:
        state = self._require_fitted()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "version": MODEL_FORMAT_VERSION,
                "feature_names": FEATURE_NAMES,
                "params": {
                    "n_estimators": self.n_estimators,
                    "threshold_percentile": self.threshold_percentile,
                    "random_state": self.random_state,
                    "min_train_windows": self.min_train_windows,
                    "top_k": self.top_k,
                },
                "state": state,
            },
            target,
        )

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        payload = joblib.load(path)
        if payload.get("version") != MODEL_FORMAT_VERSION:
            raise ValueError(f"Unsupported model format version: {payload.get('version')!r}")
        if tuple(payload["feature_names"]) != FEATURE_NAMES:
            raise ValueError(
                "The saved model was trained with different features. Retrain it with the current features."
            )
        detector = cls(**payload["params"])
        detector._state = payload["state"]
        return detector

    def _require_fitted(self) -> _FittedState:
        if self._state is None:
            raise RuntimeError("AnomalyDetector is not fitted yet: call fit() or load() first.")
        return self._state