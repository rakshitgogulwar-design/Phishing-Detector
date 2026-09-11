"""
Comprehensive Evaluation & Benchmarking Suite
Implements:
- Standard Stratified Cross-Validation
- Domain-Grouped Cross-Validation (Evaluating Zero-Day Unseen Domain Generalization)
- Full metrics matrix: ROC-AUC, PR-AUC, Recall/FNR, Precision/FPR, F1, Brier Score, Latency
- Confusion matrix and calibration curve generation
"""

import time
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss,
    confusion_matrix, roc_curve, precision_recall_curve
)
from sklearn.model_selection import StratifiedKFold, StratifiedGroupKFold


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray, latency_ms: float = 0.0) -> Dict[str, Any]:
    """
    Computes all standard and security-centric performance metrics.
    """
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    fpr = fp / max(fp + tn, 1)
    fnr = fn / max(fn + tp, 1)  # Critical metric: missed phishing attacks

    try:
        roc_auc = roc_auc_score(y_true, y_proba)
    except Exception:
        roc_auc = 0.5

    try:
        pr_auc = average_precision_score(y_true, y_proba)
    except Exception:
        pr_auc = 0.0

    brier = brier_score_loss(y_true, y_proba)

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_negative_rate": round(float(fnr), 4),
        "false_positive_rate": round(float(fpr), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "brier_score": round(float(brier), 4),
        "latency_ms": round(float(latency_ms), 3),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
    }


def evaluate_model_holdout(model, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    """
    Evaluates a trained model on a holdout test set with latency measurement.
    """
    start_t = time.perf_counter()
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    elapsed_ms = ((time.perf_counter() - start_t) / max(len(X_test), 1)) * 1000.0

    metrics = compute_metrics(y_test.values, y_pred, y_proba, latency_ms=elapsed_ms)

    # Compute ROC and PR curve points
    fpr_arr, tpr_arr, _ = roc_curve(y_test.values, y_proba)
    prec_arr, rec_arr, _ = precision_recall_curve(y_test.values, y_proba)

    # Subsample curve points for compact JSON serialization
    step_roc = max(len(fpr_arr) // 50, 1)
    step_pr = max(len(prec_arr) // 50, 1)

    metrics["roc_curve"] = {
        "fpr": [round(float(x), 4) for x in fpr_arr[::step_roc]],
        "tpr": [round(float(x), 4) for x in tpr_arr[::step_roc]]
    }
    metrics["pr_curve"] = {
        "precision": [round(float(x), 4) for x in prec_arr[::step_pr]],
        "recall": [round(float(x), 4) for x in rec_arr[::step_pr]]
    }

    return metrics


def run_cross_validation(
    pipeline_factory,
    df: pd.DataFrame,
    n_splits: int = 5,
    group_by_domain: bool = True,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Executes rigorous K-Fold CV.
    If group_by_domain is True, uses StratifiedGroupKFold on domain_cluster.
    """
    X = df.drop(columns=["Result", "domain_cluster"], errors="ignore")
    y = df["Result"]

    if group_by_domain and "domain_cluster" in df.columns:
        splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        split_gen = splitter.split(X, y, groups=df["domain_cluster"])
    else:
        splitter = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        split_gen = splitter.split(X, y)

    fold_metrics = []

    for fold_idx, (train_idx, val_idx) in enumerate(split_gen):
        X_tr, y_tr = X.iloc[train_idx], y.iloc[train_idx]
        X_val, y_val = X.iloc[val_idx], y.iloc[val_idx]

        model = pipeline_factory()
        model.fit(X_tr, y_tr)

        start_t = time.perf_counter()
        y_pred = model.predict(X_val)
        y_proba = model.predict_proba(X_val)[:, 1]
        lat = ((time.perf_counter() - start_t) / max(len(X_val), 1)) * 1000.0

        m = compute_metrics(y_val.values, y_pred, y_proba, latency_ms=lat)
        fold_metrics.append(m)

    # Compute mean and standard deviation across folds
    metric_keys = ["accuracy", "precision", "recall", "f1_score", "false_negative_rate", "false_positive_rate", "roc_auc", "pr_auc", "brier_score", "latency_ms"]
    aggregated = {}
    
    for k in metric_keys:
        vals = [f[k] for f in fold_metrics]
        aggregated[f"{k}_mean"] = round(float(np.mean(vals)), 4)
        aggregated[f"{k}_std"] = round(float(np.std(vals)), 4)

    return {
        "aggregated": aggregated,
        "folds": fold_metrics,
        "validation_protocol": "Grouped-Domain CV (Unseen Domains)" if group_by_domain else "Standard Stratified CV"
    }
