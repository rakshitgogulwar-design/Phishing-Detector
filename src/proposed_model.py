"""
Proposed Multi-Modal Phishing Detection System
Combines:
- URL + Domain + HTML Structure + Security Context features
- Non-linear feature interaction engineering & domain anomaly indicators
- Advanced gradient boosting (LightGBM, XGBoost) and Stacking Ensembles
- Probability calibration (Platt scaling / Isotonic regression)
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, ClassifierMixin, TransformerMixin
from sklearn.ensemble import RandomForestClassifier, StackingClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
try:
    import lightgbm as lgb
except (ImportError, OSError, Exception):
    lgb = None

try:
    import xgboost as xgb
except (ImportError, OSError, Exception):
    xgb = None
import joblib

from src.data_loader import ALL_FEATURES, FEATURE_CATEGORIES


class MultiModalFeatureEngineer(BaseEstimator, TransformerMixin):
    """
    Constructs high-order domain interactions and cross-modal risk indicators:
    - SFH x URL_of_Anchor (Severe form hijacking signal)
    - SSL State x Domain Registration (Brand spoofing / short-lived SSL signal)
    - Subdomain x Prefix-Suffix (Typosquatting & deep subdomain cloaking)
    - Iframe x Popup (Deceptive overlay signature)
    - Multi-Modal Composite Risk Score
    """

    def __init__(self):
        self.engineered_feature_names: List[str] = []

    def fit(self, X: pd.DataFrame, y=None):
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        X_out = X.copy()
        
        # Cross-modal interactions
        if "SFH" in X_out.columns and "URL_of_Anchor" in X_out.columns:
            # Form pointing to external/blank while anchor links are foreign
            X_out["SFH_x_Anchor"] = X_out["SFH"] * X_out["URL_of_Anchor"]

        if "SSLfinal_State" in X_out.columns and "Domain_registeration_length" in X_out.columns:
            # SSL invalid + short domain lifetime
            X_out["SSL_x_DomainAge"] = X_out["SSLfinal_State"] * X_out["Domain_registeration_length"]

        if "having_Sub_Domain" in X_out.columns and "Prefix_Suffix" in X_out.columns:
            # Multi-level subdomain + hyphen prefix (classic brand mimicry)
            X_out["Subdomain_x_Prefix"] = X_out["having_Sub_Domain"] * X_out["Prefix_Suffix"]

        if "Iframe" in X_out.columns and "popUpWidnow" in X_out.columns:
            # Hidden iframe + popup
            X_out["Iframe_x_Popup"] = X_out["Iframe"] * X_out["popUpWidnow"]

        if "Request_URL" in X_out.columns and "Links_in_tags" in X_out.columns:
            # High foreign asset requests
            X_out["Request_x_Links"] = X_out["Request_URL"] * X_out["Links_in_tags"]

        # Composite multi-modal threat index (count of phishing-indicative values == -1)
        feature_cols = [c for c in ALL_FEATURES if c in X_out.columns]
        X_out["composite_threat_index"] = (X_out[feature_cols] == -1).sum(axis=1)
        
        return X_out


class ProposedMultiModalPipeline:
    """
    Proposed End-to-End Multi-Modal Detection Pipeline:
    Multi-Modal Features -> Feature Engineering -> Scaler -> Tuned Ensemble -> Probability Calibration
    """

    def __init__(
        self,
        model_type: str = "lightgbm",
        calibrate: bool = True,
        calibration_method: str = "sigmoid",
        random_state: int = 42
    ):
        self.model_type = model_type
        self.calibrate = calibrate
        self.calibration_method = calibration_method
        self.random_state = random_state
        self.feature_names = ALL_FEATURES
        self.engineer = MultiModalFeatureEngineer()
        self.raw_model = self._create_base_model(model_type)
        self.pipeline: Optional[Pipeline] = None

    def _create_base_model(self, model_type: str):
        if model_type == "lightgbm":
            if lgb is not None:
                return lgb.LGBMClassifier(
                    n_estimators=200,
                    learning_rate=0.05,
                    max_depth=6,
                    num_leaves=31,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    random_state=self.random_state,
                    n_jobs=-1,
                    verbose=-1
                )
            else:
                return HistGradientBoostingClassifier(
                    max_iter=200,
                    learning_rate=0.05,
                    max_depth=6,
                    random_state=self.random_state
                )
        elif model_type == "xgboost":
            if xgb is not None:
                return xgb.XGBClassifier(
                    n_estimators=200,
                    learning_rate=0.05,
                    max_depth=5,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    random_state=self.random_state,
                    eval_metric="logloss",
                    n_jobs=-1
                )
            else:
                return HistGradientBoostingClassifier(
                    max_iter=200,
                    learning_rate=0.05,
                    max_depth=5,
                    random_state=self.random_state
                )
        elif model_type == "random_forest":
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=4,
                class_weight="balanced",
                random_state=self.random_state,
                n_jobs=-1
            )
        elif model_type == "stacking":
            lgb_estimator = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.05, max_depth=5, random_state=self.random_state, verbose=-1, n_jobs=-1) if lgb is not None else HistGradientBoostingClassifier(max_iter=100, learning_rate=0.05, max_depth=5, random_state=self.random_state)
            xgb_estimator = xgb.XGBClassifier(n_estimators=100, learning_rate=0.05, max_depth=4, random_state=self.random_state, eval_metric="logloss", n_jobs=-1) if xgb is not None else HistGradientBoostingClassifier(max_iter=100, learning_rate=0.05, max_depth=4, random_state=self.random_state)
            estimators = [
                ("lgb", lgb_estimator),
                ("xgb", xgb_estimator),
                ("rf", RandomForestClassifier(n_estimators=100, max_depth=10, random_state=self.random_state, n_jobs=-1))
            ]
            return StackingClassifier(
                estimators=estimators,
                final_estimator=LogisticRegression(C=1.0, max_iter=500),
                cv=3,
                n_jobs=-1
            )
        else:
            raise ValueError(f"Unknown proposed model type: {model_type}")

    def fit(self, X: pd.DataFrame, y: pd.Series, X_val: Optional[pd.DataFrame] = None, y_val: Optional[pd.Series] = None) -> "ProposedMultiModalPipeline":
        available_feats = [f for f in self.feature_names if f in X.columns]
        X_sub = X[available_feats].copy()
        
        # Feature Engineering
        X_trans = self.engineer.fit_transform(X_sub)
        self.engineered_feature_cols = list(X_trans.columns)

        # Base classifier
        base_clf = self.raw_model

        if self.calibrate:
            # 3-Fold cross-validation probability calibration (Platt scaling / Sigmoid)
            calibrated_clf = CalibratedClassifierCV(
                estimator=base_clf,
                method=self.calibration_method,
                cv=3
            )
            calibrated_clf.fit(X_trans, y)
            self.final_model = calibrated_clf
        else:
            base_clf.fit(X_trans, y)
            self.final_model = base_clf

        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        available_feats = [f for f in self.feature_names if f in X.columns]
        X_sub = X[available_feats].copy()
        X_trans = self.engineer.transform(X_sub)
        return self.final_model.predict(X_trans)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        available_feats = [f for f in self.feature_names if f in X.columns]
        X_sub = X[available_feats].copy()
        X_trans = self.engineer.transform(X_sub)
        return self.final_model.predict_proba(X_trans)

    def get_feature_names_out(self) -> List[str]:
        return self.engineered_feature_cols

    def save(self, filepath: str) -> None:
        joblib.dump({
            "model": self.final_model,
            "raw_model": self.raw_model,
            "engineer": self.engineer,
            "features": self.feature_names,
            "engineered_features": self.engineered_feature_cols,
            "type": self.model_type,
            "calibrated": self.calibrate
        }, filepath)

    @classmethod
    def load(cls, filepath: str) -> "ProposedMultiModalPipeline":
        data = joblib.load(filepath)
        obj = cls(model_type=data["type"], calibrate=data["calibrated"])
        obj.final_model = data["model"]
        obj.raw_model = data["raw_model"]
        obj.engineer = data["engineer"]
        obj.feature_names = data["features"]
        obj.engineered_feature_cols = data["engineered_features"]
        return obj
