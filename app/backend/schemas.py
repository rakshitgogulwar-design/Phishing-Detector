"""
Pydantic Request and Response Schemas for PhishGuard API
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect for phishing indicators")
    html_content: Optional[str] = Field(None, description="Optional raw HTML content for DOM inspection")
    save_to_history: bool = Field(True, description="Whether to automatically store scan in history")


class MessageScanRequest(BaseModel):
    message: str = Field(..., description="Raw text of email, SMS, or chat message to analyze")
    save_to_history: bool = Field(True, description="Whether to automatically store scan in history")


class FeedbackRequest(BaseModel):
    scan_id: Optional[int] = Field(None, description="ID of the related scan if available")
    target: str = Field(..., description="The URL or message that was misclassified")
    reported_as: str = Field(..., description="'false_positive', 'false_negative', or 'other'")
    comments: Optional[str] = Field(None, description="User explanation / details")


class SettingsUpdateRequest(BaseModel):
    weight_rules: Optional[float] = Field(None, ge=0.0, le=1.0)
    weight_ml: Optional[float] = Field(None, ge=0.0, le=1.0)
    weight_intel: Optional[float] = Field(None, ge=0.0, le=1.0)
    passive_only: Optional[bool] = None
    theme: Optional[str] = None


class ChecklistItem(BaseModel):
    status: str
    indicator: str
    details: str


class ScanResponse(BaseModel):
    id: Optional[int] = None
    scan_type: str
    target: str
    status: str
    risk_tier: str
    risk_score: int
    confidence: float
    reasons: List[str]
    recommendation: str
    checklist: Optional[List[Dict[str, Any]]] = None
    components: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None


class HistoryResponse(BaseModel):
    scans: List[Dict[str, Any]]
    total_count: int
    limit: int
    offset: int


class StatisticsResponse(BaseModel):
    total_scans: int
    safe_count: int
    safe_percentage: float
    suspicious_count: int
    suspicious_percentage: float
    phishing_count: int
    phishing_percentage: float
    average_risk_score: float
    recent_scans: List[Dict[str, Any]]
    detection_accuracy: float
