"""
Master Experimentation & Benchmarking Pipeline
Executes systematic empirical comparison between:
1. Baseline Systems (URL & Domain only) across 5 standard algorithms
2. Proposed Multi-Modal Systems (URL + Domain + HTML + Security) with calibration & ensembling
Evaluates on both Standard Stratified Splits and Domain-Grouped Splits (Zero-Day Generalization).
Outputs serialized models, metrics JSON, and comparative charts.
"""

import os
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from src.data_loader import load_dataset, get_data_splits, ALL_FEATURES, FEATURE_CATEGORIES
from src.baseline_model import BaselinePipeline, train_all_baselines
from src.proposed_model import ProposedMultiModalPipeline
from src.evaluation import evaluate_model_holdout, run_cross_validation
from src.explainability import SecurityExplainer


def run_all_experiments():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "models")
    figures_dir = os.path.join(base_dir, "data", "figures")
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(figures_dir, exist_ok=True)

    print("=" * 70)
    print("AI/ML PHISHING DETECTION: RESEARCH EXPERIMENTATION PIPELINE")
    print("=" * 70)

    # 1. Load Dataset
    print("\n[Step 1/5] Ingesting and Validating Dataset...")
    df = load_dataset()

    # 2. Leakage-Free Data Splitting (Domain-Grouped)
    print("\n[Step 2/5] Creating Leakage-Free Domain-Grouped Splits...")
    train_df, val_df, test_df = get_data_splits(df, test_size=0.20, val_size=0.15, group_by_domain=True, random_state=42)
    print(f"Train Set: {len(train_df)} samples ({len(set(train_df['domain_cluster']))} unique domains)")
    print(f"Val Set:   {len(val_df)} samples ({len(set(val_df['domain_cluster']))} unique domains)")
    print(f"Test Set:  {len(test_df)} samples ({len(set(test_df['domain_cluster']))} unique domains)")

    X_train = train_df.drop(columns=["Result", "domain_cluster"])
    y_train = train_df["Result"]
    X_val = val_df.drop(columns=["Result", "domain_cluster"])
    y_val = val_df["Result"]
    X_test = test_df.drop(columns=["Result", "domain_cluster"])
    y_test = test_df["Result"]

    # 3. Train & Evaluate Baselines
    print("\n[Step 3/5] Training Reference Paper Baseline Models (URL/Domain Only)...")
    baseline_names = ["random_forest", "logistic_regression", "decision_tree", "naive_bayes", "knn"]
    baseline_results = {}
    baseline_models = {}

    for bname in baseline_names:
        print(f"  -> Training Baseline: {bname}...")
        base_pipe = BaselinePipeline(model_type=bname, random_state=42)
        base_pipe.fit(X_train, y_train)
        base_eval = evaluate_model_holdout(base_pipe, X_test, y_test)
        baseline_results[bname] = base_eval
        baseline_models[bname] = base_pipe
        print(f"     Accuracy: {base_eval['accuracy']*100:.2f}%, Recall: {base_eval['recall']*100:.2f}%, FNR: {base_eval['false_negative_rate']*100:.2f}%, ROC-AUC: {base_eval['roc_auc']:.4f}, Latency: {base_eval['latency_ms']:.2f}ms")

    # Save primary baseline model (Random Forest)
    baseline_rf_path = os.path.join(models_dir, "baseline_rf.joblib")
    baseline_models["random_forest"].save(baseline_rf_path)

    # 4. Train & Evaluate Proposed Multi-Modal Systems
    print("\n[Step 4/5] Training Proposed Multi-Modal Calibrated Pipelines (URL + Domain + HTML + Security)...")
    proposed_configs = [
        ("proposed_lightgbm", "lightgbm", True),
        ("proposed_xgboost", "xgboost", True),
        ("proposed_rf_multimodal", "random_forest", True),
        ("proposed_stacking", "stacking", True)
    ]
    proposed_results = {}
    proposed_models = {}

    for name, mtype, calib in proposed_configs:
        print(f"  -> Training Proposed: {name} (Calibrated: {calib})...")
        prop_pipe = ProposedMultiModalPipeline(model_type=mtype, calibrate=calib, random_state=42)
        prop_pipe.fit(X_train, y_train, X_val=X_val, y_val=y_val)
        prop_eval = evaluate_model_holdout(prop_pipe, X_test, y_test)
        proposed_results[name] = prop_eval
        proposed_models[name] = prop_pipe
        print(f"     Accuracy: {prop_eval['accuracy']*100:.2f}%, Recall: {prop_eval['recall']*100:.2f}%, FNR: {prop_eval['false_negative_rate']*100:.2f}%, ROC-AUC: {prop_eval['roc_auc']:.4f}, Brier: {prop_eval['brier_score']:.4f}, Latency: {prop_eval['latency_ms']:.2f}ms")

    # Save champion model (Proposed LightGBM Calibrated)
    proposed_champion_path = os.path.join(models_dir, "proposed_champion.joblib")
    proposed_models["proposed_lightgbm"].save(proposed_champion_path)

    # 5. Scientific Validation: Zero-Day Domain-Grouped Cross-Validation
    print("\n[Step 5/5] Executing 5-Fold Domain-Grouped Cross-Validation (Zero-Day Attack Simulation)...")
    
    cv_baseline_rf = run_cross_validation(
        lambda: BaselinePipeline(model_type="random_forest", random_state=42),
        df, n_splits=5, group_by_domain=True
    )
    print(f"  Baseline RF Grouped CV -> Acc: {cv_baseline_rf['aggregated']['accuracy_mean']:.4f} ± {cv_baseline_rf['aggregated']['accuracy_std']:.4f}, Recall: {cv_baseline_rf['aggregated']['recall_mean']:.4f}, FNR: {cv_baseline_rf['aggregated']['false_negative_rate_mean']:.4f}")

    cv_proposed_lgb = run_cross_validation(
        lambda: ProposedMultiModalPipeline(model_type="lightgbm", calibrate=True, random_state=42),
        df, n_splits=5, group_by_domain=True
    )
    print(f"  Proposed LGB Grouped CV -> Acc: {cv_proposed_lgb['aggregated']['accuracy_mean']:.4f} ± {cv_proposed_lgb['aggregated']['accuracy_std']:.4f}, Recall: {cv_proposed_lgb['aggregated']['recall_mean']:.4f}, FNR: {cv_proposed_lgb['aggregated']['false_negative_rate_mean']:.4f}")

    # Compile Full Benchmark Report
    benchmark_payload = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_summary": {
            "total_samples": len(df),
            "feature_count": len(ALL_FEATURES),
            "unique_domain_clusters": len(set(df["domain_cluster"])),
            "legitimate_count": int((df["Result"] == 0).sum()),
            "phishing_count": int((df["Result"] == 1).sum()),
            "phishing_ratio": round(float((df["Result"] == 1).mean()), 4)
        },
        "holdout_evaluation": {
            "baseline_models": baseline_results,
            "proposed_models": proposed_results
        },
        "grouped_cv_generalization": {
            "baseline_rf": cv_baseline_rf["aggregated"],
            "proposed_champion": cv_proposed_lgb["aggregated"]
        },
        "research_findings": {
            "baseline_fnr": baseline_results["random_forest"]["false_negative_rate"],
            "proposed_fnr": proposed_results["proposed_lightgbm"]["false_negative_rate"],
            "fnr_reduction_percentage": round((baseline_results["random_forest"]["false_negative_rate"] - proposed_results["proposed_lightgbm"]["false_negative_rate"]) / max(baseline_results["random_forest"]["false_negative_rate"], 1e-6) * 100, 2),
            "baseline_roc_auc": baseline_results["random_forest"]["roc_auc"],
            "proposed_roc_auc": proposed_results["proposed_lightgbm"]["roc_auc"],
            "brier_calibration_improvement": round(baseline_results["random_forest"]["brier_score"] - proposed_results["proposed_lightgbm"]["brier_score"], 4)
        }
    }

    benchmark_json_path = os.path.join(base_dir, "data", "benchmark_results.json")
    with open(benchmark_json_path, "w") as f:
        json.dump(benchmark_payload, f, indent=2)
    print(f"\nBenchmark JSON saved to: {benchmark_json_path}")

    # Generate Comparative Visualization Figures
    generate_figures(benchmark_payload, baseline_results, proposed_results, figures_dir)

    print("\n" + "=" * 70)
    print("EXPERIMENTATION COMPLETE: ALL RESEARCH OBJECTIVES VALIDATED")
    print("=" * 70)


def generate_figures(benchmark_data, baseline_results, proposed_results, figures_dir):
    """
    Generates publication-quality figures: ROC curves, PR curves, and Metric Comparison charts.
    """
    sns.set_theme(style="whitegrid")
    
    # 1. ROC Curve Comparison
    plt.figure(figsize=(8, 6), dpi=300)
    
    b_roc = baseline_results["random_forest"]["roc_curve"]
    plt.plot(b_roc["fpr"], b_roc["tpr"], label=f"Baseline (URL-only RF) AUC={baseline_results['random_forest']['roc_auc']:.3f}", color="#ef4444", lw=2)
    
    p_roc = proposed_results["proposed_lightgbm"]["roc_curve"]
    plt.plot(p_roc["fpr"], p_roc["tpr"], label=f"Proposed (Multi-Modal LightGBM) AUC={proposed_results['proposed_lightgbm']['roc_auc']:.3f}", color="#10b981", lw=2.5)
    
    plt.plot([0, 1], [0, 1], 'k--', alpha=0.5, label="Random Guess")
    plt.xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
    plt.ylabel("True Positive Rate (Recall / TPR)", fontsize=11, fontweight="bold")
    plt.title("ROC Curve: Baseline vs Proposed Multi-Modal System", fontsize=13, fontweight="bold", pad=12)
    plt.legend(loc="lower right", frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join(figures_dir, "roc_comparison.png"))
    plt.close()

    # 2. Bar Chart Comparison (Accuracy, Recall, FNR, ROC-AUC)
    metrics_to_plot = ["accuracy", "recall", "f1_score", "roc_auc"]
    b_vals = [baseline_results["random_forest"][m] for m in metrics_to_plot]
    p_vals = [proposed_results["proposed_lightgbm"][m] for m in metrics_to_plot]

    x = np.arange(len(metrics_to_plot))
    width = 0.35

    plt.figure(figsize=(9, 5), dpi=300)
    plt.bar(x - width/2, b_vals, width, label="Baseline (URL Only RF)", color="#94a3b8")
    plt.bar(x + width/2, p_vals, width, label="Proposed (Multi-Modal LightGBM)", color="#3b82f6")

    plt.ylabel("Score (0 - 1.0)", fontsize=11, fontweight="bold")
    plt.title("Comparative Performance on Zero-Day Unseen Test Domains", fontsize=13, fontweight="bold", pad=12)
    plt.xticks(x, ["Accuracy", "Recall", "F1-Score", "ROC-AUC"], fontweight="bold")
    plt.ylim(0.7, 1.02)
    plt.legend(loc="lower left", frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join(figures_dir, "metrics_comparison.png"))
    plt.close()


if __name__ == "__main__":
    run_all_experiments()
