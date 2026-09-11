"""
Baseline Phishing Detection Model Suite
Faithfully reproduces the reference paper's methodology:
- Features restricted strictly to URL and Domain characteristics.
- Models evaluated: Random Forest, Logistic Regression, Decision Tree, Gaussian Naive Bayes, K-Nearest Neighbors.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

from src.data_loader import FEATURE_CATEGORIES


class BaselinePipeline:
    """
    Baseline Phishing Detection System:
    URL + Domain features -> Standard Preprocessing -> Feature Selection -> Benchmark Classifier
    """

    def __init__(self, model_type: str = "random_forest", k_features: Optional[int] = None, random_state: int = 42):
        self.model_type = model_type
        self.k_features = k_features
        self.random_state = random_state
        self.feature_names = FEATURE_CATEGORIES["url_domain_baseline"]
        self.model = self._create_model(model_type)
        self.pipeline: Optional[Pipeline] = None

    def _create_model(self, model_type: str):
        if model_type == "random_forest":
            return RandomForestClassifier(n_estimators=100, max_depth=12, random_state=self.random_state, n_jobs=-1)
        elif model_type == "logistic_regression":
            return LogisticRegression(max_iter=1000, random_state=self.random_state)
        elif model_type == "decision_tree":
            return DecisionTreeClassifier(max_depth=10, random_state=self.random_state)
        elif model_type == "naive_bayes":
            return GaussianNB()
        elif model_type == "knn":
            return KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
        else:
            raise ValueError(f"Unknown baseline model type: {model_type}")

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "BaselinePipeline":
        # Filter strictly to baseline features
        available_feats = [f for f in self.feature_names if f in X.columns]
        X_base = X[available_feats].copy()

        steps = [
            ("scaler", StandardScaler()),
        ]

        if self.k_features and self.k_features < len(available_feats):
            steps.append(("selector", SelectKBest(score_func=mutual_info_classif, k=self.k_features)))

        steps.append(("classifier", self.model))
        self.pipeline = Pipeline(steps)
        self.pipeline.fit(X_base, y)
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        available_feats = [f for f in self.feature_names if f in X.columns]
        X_base = X[available_feats].copy()
        return self.pipeline.predict(X_base)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        available_feats = [f for f in self.feature_names if f in X.columns]
        X_base = X[available_feats].copy()
        if hasattr(self.pipeline.named_steps["classifier"], "predict_proba"):
            return self.pipeline.predict_proba(X_base)
        else:
            # Fallback for models without native predict_proba
            preds = self.pipeline.predict(X_base)
            return np.column_stack([1 - preds, preds])

    def save(self, filepath: str) -> None:
        joblib.dump({"pipeline": self.pipeline, "features": self.feature_names, "type": self.model_type}, filepath)

    @classmethod
    def load(cls, filepath: str) -> "BaselinePipeline":
        data = joblib.load(filepath)
        obj = cls(model_type=data["type"])
        obj.pipeline = data["pipeline"]
        obj.feature_names = data["features"]
        return obj


def train_all_baselines(X_train: pd.DataFrame, y_train: pd.Series, random_state: int = 42) -> Dict[str, BaselinePipeline]:
    """
    Trains all 5 baseline models reported in research papers for systematic comparison.
    """
    models = {}
    for mtype in ["random_forest", "logistic_regression", "decision_tree", "naive_bayes", "knn"]:
        pipe = BaselinePipeline(model_type=mtype, random_state=random_state)
        pipe.fit(X_train, y_train)
        models[mtype] = pipe
    return models
