//! Reference document service for retrieval and persistence

use futures::future::join_all;
use url::Url;

use crate::db::models::{ListDocumentsQuery, PaginatedDocuments};
use crate::db::repository::ReferenceDocumentRepository;
use crate::db::DbError;
use crate::model::{ReferenceDocument, RetrieverConfig};
use crate::retriever::{RetrieverDispatcher, RetrieverError};
use crate::service::cache::VulnerabilityCache;

#[derive(Debug, thiserror::Error)]
pub enum DocumentServiceError {
    #[error("Database error: {0}")]
    DbError(#[from] DbError),

    #[error("Retriever error: {0}")]
    RetrieverError(#[from] RetrieverError),
}

/// Service for managing reference documents
pub struct DocumentService {
    repository: ReferenceDocumentRepository,
    dispatcher: RetrieverDispatcher,
}

impl DocumentService {
    pub fn new(
        repository: ReferenceDocumentRepository,
        retriever_config: RetrieverConfig,
        cache: Option<VulnerabilityCache>,
    ) -> Self {
        Self {
            repository,
            dispatcher: RetrieverDispatcher::new(retriever_config, cache),
        }
    }

    /// Retrieve and persist documents for multiple URLs
    /// Returns the IDs of successfully retrieved documents
    pub async fn retrieve_and_persist(&self, urls: Vec<Url>) -> Vec<String> {
        let futures: Vec<_> = urls
            .into_iter()
            .map(|url| self.retrieve_single(url))
            .collect();

        let results = join_all(futures).await;

        results.into_iter().flatten().collect()
    }

    /// Retrieve a single URL and persist if successful
    async fn retrieve_single(&self, url: Url) -> Option<String> {
        // First check if we already have this document (by URL, need to fetch to compute hash)
        match self.dispatcher.retrieve(&url).await {
            Ok(retrieved) => {
                let doc = retrieved.into_reference_document();
                let doc_id = doc.id.clone();

                // Check if already exists
                match self.repository.exists(&doc_id).await {
                    Ok(true) => {
                        tracing::debug!(id = %doc_id, url = %url, "Document already cached");
                        return Some(doc_id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, url = %url, "Failed to check document existence");
                    }
                }

                // Persist the document
                match self.repository.upsert(&doc).await {
                    Ok(_) => {
                        tracing::info!(id = %doc_id, url = %url, "Document retrieved and persisted");
                        Some(doc_id)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, url = %url, "Failed to persist document");
                        None
                    }
                }
            }
            Err(e) => {
                match &e {
                    crate::retriever::RetrieverError::RateLimited => {
                        tracing::warn!(url = %url, "Rate limited while retrieving document, skipping");
                    }
                    _ => {
                        tracing::debug!(error = %e, url = %url, "Failed to retrieve document, skipping");
                    }
                }
                None
            }
        }
    }

    /// Get a document by ID
    pub async fn get_by_id(&self, id: &str) -> Result<ReferenceDocument, DocumentServiceError> {
        self.repository
            .get_by_id(id)
            .await
            .map_err(DocumentServiceError::from)
    }

    /// List documents with pagination and filters
    pub async fn list(
        &self,
        query: ListDocumentsQuery,
    ) -> Result<PaginatedDocuments, DocumentServiceError> {
        self.repository
            .list(query)
            .await
            .map_err(DocumentServiceError::from)
    }

    /// Delete a document by ID
    /// Returns true if the document was deleted, false if it didn't exist
    pub async fn delete(&self, id: &str) -> Result<bool, DocumentServiceError> {
        self.repository
            .delete(id)
            .await
            .map_err(DocumentServiceError::from)
    }
}
