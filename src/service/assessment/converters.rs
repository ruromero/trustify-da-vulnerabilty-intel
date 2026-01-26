//! Converters from extracted LLM models to domain models

use crate::model::assessments::{
    ExtractedCertainty, ExtractedExploitability, ExtractedExploitabilityStatus, ExtractedImpact,
    ExtractedImpactLevel, ExtractedImpactSeverity, ExtractedLimitation, ExtractedLimitationReason,
};
use crate::model::{
    ClaimCertainty, ExploitabilityAssessment, ExploitabilityStatus, ImpactAssessment, ImpactLevel,
    ImpactSeverity, Limitation, LimitationReason,
};

/// Convert extracted exploitability to domain model
pub fn convert_exploitability(extracted: ExtractedExploitability) -> ExploitabilityAssessment {
    let status = match extracted.status {
        ExtractedExploitabilityStatus::Exploitable => ExploitabilityStatus::Exploitable,
        ExtractedExploitabilityStatus::ConditionallyExploitable => {
            ExploitabilityStatus::ConditionallyExploitable
        }
        ExtractedExploitabilityStatus::NotExploitable => ExploitabilityStatus::NotExploitable,
        ExtractedExploitabilityStatus::Unknown => ExploitabilityStatus::Unknown,
    };

    let certainty = match extracted.certainty {
        ExtractedCertainty::Conditional => ClaimCertainty::Conditional,
        ExtractedCertainty::Strong => ClaimCertainty::Strong,
        ExtractedCertainty::IdentificationOnly => ClaimCertainty::IdentificationOnly,
        ExtractedCertainty::Indicative => ClaimCertainty::Indicative,
    };

    ExploitabilityAssessment {
        status,
        certainty,
        conditions: extracted.conditions,
        notes: extracted.notes,
    }
}

/// Convert extracted impact to domain model
pub fn convert_impact(extracted: ExtractedImpact) -> ImpactAssessment {
    let severity = match extracted.severity {
        ExtractedImpactSeverity::Low => ImpactSeverity::Low,
        ExtractedImpactSeverity::Medium => ImpactSeverity::Medium,
        ExtractedImpactSeverity::High => ImpactSeverity::High,
        ExtractedImpactSeverity::Critical => ImpactSeverity::Critical,
        ExtractedImpactSeverity::Unknown => ImpactSeverity::Unknown,
    };

    let confidentiality = extracted.confidentiality.map(|l| match l {
        ExtractedImpactLevel::None => ImpactLevel::None,
        ExtractedImpactLevel::Low => ImpactLevel::Low,
        ExtractedImpactLevel::Medium => ImpactLevel::Medium,
        ExtractedImpactLevel::High => ImpactLevel::High,
        ExtractedImpactLevel::Critical => ImpactLevel::Critical,
    });

    let integrity = extracted.integrity.map(|l| match l {
        ExtractedImpactLevel::None => ImpactLevel::None,
        ExtractedImpactLevel::Low => ImpactLevel::Low,
        ExtractedImpactLevel::Medium => ImpactLevel::Medium,
        ExtractedImpactLevel::High => ImpactLevel::High,
        ExtractedImpactLevel::Critical => ImpactLevel::Critical,
    });

    let availability = extracted.availability.map(|l| match l {
        ExtractedImpactLevel::None => ImpactLevel::None,
        ExtractedImpactLevel::Low => ImpactLevel::Low,
        ExtractedImpactLevel::Medium => ImpactLevel::Medium,
        ExtractedImpactLevel::High => ImpactLevel::High,
        ExtractedImpactLevel::Critical => ImpactLevel::Critical,
    });

    ImpactAssessment {
        severity,
        confidentiality,
        integrity,
        availability,
        notes: extracted.notes,
    }
}

/// Convert extracted limitation to domain model
pub fn convert_limitation(extracted: ExtractedLimitation) -> Limitation {
    let reason = match extracted.reason {
        ExtractedLimitationReason::InsufficientData => LimitationReason::InsufficientData,
        ExtractedLimitationReason::RuntimeDependent => LimitationReason::RuntimeDependent,
        ExtractedLimitationReason::EnvironmentSpecific => LimitationReason::EnvironmentSpecific,
        ExtractedLimitationReason::ConflictingData => LimitationReason::ConflictingData,
    };

    Limitation {
        reason,
        description: extracted.description,
    }
}
