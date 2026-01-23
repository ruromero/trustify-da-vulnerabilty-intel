use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::VendorRemediation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedHatCsafResponse {
    pub references: Vec<Reference>,
    pub remediations: Vec<VendorRemediation>,
    pub notes: Vec<CsafNote>,
    /// Raw JSON content for use by retrievers
    pub raw_json: Option<String>,
}

impl RedHatCsafResponse {
    pub fn empty() -> Self {
        Self {
            references: vec![],
            remediations: vec![],
            notes: vec![],
            raw_json: None,
        }
    }

    /// Build normalized markdown content from notes
    pub fn build_normalized_content(&self) -> String {
        let mut content = String::new();

        for note in &self.notes {
            if let Some(ref title) = note.title {
                content.push_str(&format!("# {}\n\n", title));
            }
            if let Some(ref text) = note.text {
                content.push_str(text);
                content.push_str("\n\n");
            }
        }

        content.trim().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub url: Url,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsafNote {
    pub title: Option<String>,
    pub text: Option<String>,
    pub category: Option<String>,
}
