//! Converters from LLM-extracted models to domain models

use crate::model::remediations::action_extraction::{
    ExtractedInstruction, ExtractedRemediationAction,
};
use crate::model::{InstructionDomain, RemediationAction, RemediationInstruction, RemediationKind};

/// Convert extracted remediation action to domain model
pub fn convert_to_remediation_action(
    extracted: ExtractedRemediationAction,
    kind: RemediationKind,
    description: String,
    language: Option<String>,
) -> RemediationAction {
    RemediationAction {
        kind,
        description,
        language,
        instructions: extracted
            .instructions
            .into_iter()
            .map(convert_instruction)
            .collect(),
        preconditions: extracted.preconditions,
        confirmation_risks: extracted.confirmation_risks,
        expected_outcomes: extracted.expected_outcomes,
    }
}

/// Convert extracted instruction to domain model
fn convert_instruction(extracted: ExtractedInstruction) -> RemediationInstruction {
    let domain = match extracted.domain.to_lowercase().as_str() {
        "dependency" => InstructionDomain::Dependency,
        "code" => InstructionDomain::Code,
        "configuration" => InstructionDomain::Configuration,
        "build" => InstructionDomain::Build,
        "annotation" => InstructionDomain::Annotation,
        _ => {
            // Default to Code if unknown
            tracing::warn!(
                domain = %extracted.domain,
                "Unknown instruction domain, defaulting to Code"
            );
            InstructionDomain::Code
        }
    };

    RemediationInstruction {
        domain,
        action: extracted.action,
        parameters: extracted.parameters,
    }
}
