// ═══════════════════════════════════════════════════════════════════════
// Data Subject Rights — GDPR Articles 15-22 and CCPA
//
// Structured operations for access, rectification, erasure, portability,
// restriction, objection, automated decision exemption, and CCPA rights.
// ═══════════════════════════════════════════════════════════════════════

use std::fmt;

use rune_identity::IdentityId;

use crate::error::PrivacyError;

const GDPR_DEADLINE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const CCPA_DEADLINE_MS: i64 = 45 * 24 * 60 * 60 * 1000;

// ── SubjectRight ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectRight {
    Access,
    Rectification,
    Erasure,
    RestrictProcessing,
    DataPortability,
    ObjectToProcessing,
    NotBeSubjectToAutomatedDecision,
    CcpaOptOut,
    CcpaDelete,
    CcpaKnow,
}

impl SubjectRight {
    pub fn is_ccpa(&self) -> bool {
        matches!(self, Self::CcpaOptOut | Self::CcpaDelete | Self::CcpaKnow)
    }

    pub fn regulation_article(&self) -> &'static str {
        match self {
            Self::Access => "GDPR Art. 15",
            Self::Rectification => "GDPR Art. 16",
            Self::Erasure => "GDPR Art. 17",
            Self::RestrictProcessing => "GDPR Art. 18",
            Self::DataPortability => "GDPR Art. 20",
            Self::ObjectToProcessing => "GDPR Art. 21",
            Self::NotBeSubjectToAutomatedDecision => "GDPR Art. 22",
            Self::CcpaOptOut => "CCPA §1798.120",
            Self::CcpaDelete => "CCPA §1798.105",
            Self::CcpaKnow => "CCPA §1798.110",
        }
    }
}

impl fmt::Display for SubjectRight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── RequestStatus ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RequestStatus {
    Received,
    InProgress,
    PendingVerification,
    Completed,
    Denied { reason: String },
    Overdue,
}

impl fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Received => write!(f, "Received"),
            Self::InProgress => write!(f, "InProgress"),
            Self::PendingVerification => write!(f, "PendingVerification"),
            Self::Completed => write!(f, "Completed"),
            Self::Denied { reason } => write!(f, "Denied({reason})"),
            Self::Overdue => write!(f, "Overdue"),
        }
    }
}

// ── ResponseType ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ResponseType {
    DataProvided,
    DataCorrected,
    DataDeleted,
    ProcessingRestricted,
    DataExported { format: String },
    ObjectionAccepted,
    ObjectionDenied { reason: String },
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataProvided => write!(f, "DataProvided"),
            Self::DataCorrected => write!(f, "DataCorrected"),
            Self::DataDeleted => write!(f, "DataDeleted"),
            Self::ProcessingRestricted => write!(f, "ProcessingRestricted"),
            Self::DataExported { format } => write!(f, "DataExported({format})"),
            Self::ObjectionAccepted => write!(f, "ObjectionAccepted"),
            Self::ObjectionDenied { reason } => write!(f, "ObjectionDenied({reason})"),
        }
    }
}

// ── RightsResponse ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RightsResponse {
    pub request_id: String,
    pub completed_at: i64,
    pub response_type: ResponseType,
    pub data: Option<String>,
    pub detail: String,
}

// ── RightsRequest ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RightsRequest {
    pub id: String,
    pub subject: IdentityId,
    pub right: SubjectRight,
    pub submitted_at: i64,
    pub deadline_at: i64,
    pub status: RequestStatus,
    pub handler: Option<String>,
    pub response: Option<RightsResponse>,
    pub notes: Vec<String>,
}

// ── RightsManager ─────────────────────────────────────────────────────

#[derive(Default)]
pub struct RightsManager {
    pub requests: Vec<RightsRequest>,
    next_id: u64,
}

impl RightsManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deadline_for_right(right: &SubjectRight) -> i64 {
        if right.is_ccpa() {
            CCPA_DEADLINE_MS
        } else {
            GDPR_DEADLINE_MS
        }
    }

    pub fn submit_request(
        &mut self,
        subject: IdentityId,
        right: SubjectRight,
        now: i64,
    ) -> RightsRequest {
        self.next_id += 1;
        let deadline = now + Self::deadline_for_right(&right);
        let request = RightsRequest {
            id: format!("req-{}", self.next_id),
            subject,
            right,
            submitted_at: now,
            deadline_at: deadline,
            status: RequestStatus::Received,
            handler: None,
            response: None,
            notes: Vec::new(),
        };
        self.requests.push(request.clone());
        request
    }

    pub fn update_status(
        &mut self,
        request_id: &str,
        status: RequestStatus,
    ) -> Result<(), PrivacyError> {
        let req = self
            .requests
            .iter_mut()
            .find(|r| r.id == request_id)
            .ok_or_else(|| PrivacyError::RightsRequestNotFound(request_id.to_string()))?;
        req.status = status;
        Ok(())
    }

    pub fn complete_request(
        &mut self,
        request_id: &str,
        response: RightsResponse,
    ) -> Result<(), PrivacyError> {
        let req = self
            .requests
            .iter_mut()
            .find(|r| r.id == request_id)
            .ok_or_else(|| PrivacyError::RightsRequestNotFound(request_id.to_string()))?;
        req.status = RequestStatus::Completed;
        req.response = Some(response);
        Ok(())
    }

    pub fn overdue_requests(&self, now: i64) -> Vec<&RightsRequest> {
        self.requests
            .iter()
            .filter(|r| now > r.deadline_at && !matches!(r.status, RequestStatus::Completed))
            .collect()
    }

    pub fn requests_for_subject(&self, subject: &IdentityId) -> Vec<&RightsRequest> {
        self.requests.iter().filter(|r| &r.subject == subject).collect()
    }

    pub fn pending_requests(&self) -> Vec<&RightsRequest> {
        self.requests
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    RequestStatus::Received | RequestStatus::InProgress | RequestStatus::PendingVerification
                )
            })
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_request_creates_with_deadline() {
        let mut mgr = RightsManager::new();
        let req = mgr.submit_request(IdentityId::new("user:alice"), SubjectRight::Access, 1000);
        assert_eq!(req.deadline_at, 1000 + GDPR_DEADLINE_MS);
        assert_eq!(req.status, RequestStatus::Received);
    }

    #[test]
    fn test_gdpr_deadline_30_days() {
        assert_eq!(
            RightsManager::deadline_for_right(&SubjectRight::Access),
            30 * 24 * 60 * 60 * 1000
        );
    }

    #[test]
    fn test_ccpa_deadline_45_days() {
        assert_eq!(
            RightsManager::deadline_for_right(&SubjectRight::CcpaDelete),
            45 * 24 * 60 * 60 * 1000
        );
    }

    #[test]
    fn test_overdue_detected() {
        let mut mgr = RightsManager::new();
        mgr.submit_request(IdentityId::new("user:alice"), SubjectRight::Access, 1000);
        let now = 1000 + GDPR_DEADLINE_MS + 1;
        assert_eq!(mgr.overdue_requests(now).len(), 1);
    }

    #[test]
    fn test_complete_request() {
        let mut mgr = RightsManager::new();
        let req = mgr.submit_request(IdentityId::new("user:alice"), SubjectRight::Access, 1000);
        mgr.complete_request(
            &req.id,
            RightsResponse {
                request_id: req.id.clone(),
                completed_at: 2000,
                response_type: ResponseType::DataProvided,
                data: Some("{...}".into()),
                detail: "all records returned".into(),
            },
        )
        .unwrap();
        assert_eq!(mgr.requests[0].status, RequestStatus::Completed);
    }

    #[test]
    fn test_pending_filters() {
        let mut mgr = RightsManager::new();
        let r1 = mgr.submit_request(IdentityId::new("user:alice"), SubjectRight::Access, 1000);
        mgr.submit_request(IdentityId::new("user:bob"), SubjectRight::Erasure, 1000);
        mgr.update_status(&r1.id, RequestStatus::Completed).unwrap();
        assert_eq!(mgr.pending_requests().len(), 1);
    }

    #[test]
    fn test_all_gdpr_rights_present() {
        let _ = SubjectRight::Access;
        let _ = SubjectRight::Rectification;
        let _ = SubjectRight::Erasure;
        let _ = SubjectRight::RestrictProcessing;
        let _ = SubjectRight::DataPortability;
        let _ = SubjectRight::ObjectToProcessing;
        let _ = SubjectRight::NotBeSubjectToAutomatedDecision;
    }

    #[test]
    fn test_ccpa_rights_present() {
        assert!(SubjectRight::CcpaOptOut.is_ccpa());
        assert!(SubjectRight::CcpaDelete.is_ccpa());
        assert!(SubjectRight::CcpaKnow.is_ccpa());
    }

    #[test]
    fn test_subject_right_display() {
        assert_eq!(SubjectRight::Access.to_string(), "Access");
        assert_eq!(SubjectRight::CcpaOptOut.to_string(), "CcpaOptOut");
    }

    #[test]
    fn test_request_status_display() {
        assert_eq!(RequestStatus::Received.to_string(), "Received");
        assert_eq!(RequestStatus::Completed.to_string(), "Completed");
    }

    #[test]
    fn test_requests_for_subject() {
        let mut mgr = RightsManager::new();
        mgr.submit_request(IdentityId::new("user:alice"), SubjectRight::Access, 1000);
        mgr.submit_request(IdentityId::new("user:bob"), SubjectRight::Access, 1000);
        assert_eq!(mgr.requests_for_subject(&IdentityId::new("user:alice")).len(), 1);
    }

    #[test]
    fn test_regulation_article() {
        assert_eq!(SubjectRight::Access.regulation_article(), "GDPR Art. 15");
        assert_eq!(SubjectRight::Erasure.regulation_article(), "GDPR Art. 17");
    }
}
