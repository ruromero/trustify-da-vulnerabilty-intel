//! REST API endpoints for reference documents

use actix_web::{HttpResponse, Responder, get, web};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::error::ApiError;
use crate::db::models::ListDocumentsQuery;
use crate::service::DocumentService;

/// Query parameters for listing documents
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListDocumentsParams {
    /// Page number (1-indexed, default: 1)
    pub page: Option<u32>,
    /// Page size (default: 20, max: 100)
    pub page_size: Option<u32>,
    /// Filter by retriever type (nvd, git_cve_v5, git_advisory, git_issue, git_commit, generic)
    pub retriever_type: Option<String>,
    /// Filter by domain URL
    pub domain_url: Option<String>,
}

/// Paginated response for documents
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentListResponse {
    pub documents: Vec<DocumentSummary>,
    pub page: u32,
    pub page_size: u32,
    pub total_count: i64,
    pub total_pages: u32,
}

/// Summary of a document for list response
#[derive(Debug, Serialize, ToSchema)]
pub struct DocumentSummary {
    pub id: String,
    pub url: String,
    pub retriever_type: String,
    pub title: Option<String>,
    pub retrieved_at: String,
}

/// List reference documents with pagination and filters
#[utoipa::path(
    get,
    path = "/v1/documents",
    params(ListDocumentsParams),
    responses(
        (status = 200, description = "Documents retrieved successfully", body = DocumentListResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "documents"
)]
#[get("/v1/documents")]
pub async fn list_documents(
    service: web::Data<DocumentService>,
    query: web::Query<ListDocumentsParams>,
) -> Result<impl Responder, ApiError> {
    let db_query = ListDocumentsQuery {
        page: query.page,
        page_size: query.page_size,
        retriever_type: query.retriever_type.clone(),
        domain_url: query.domain_url.clone(),
    };

    let paginated = service.list(db_query).await?;

    let summaries: Vec<DocumentSummary> = paginated
        .documents
        .into_iter()
        .map(|doc| DocumentSummary {
            id: doc.id,
            url: doc.canonical_url.to_string(),
            retriever_type: format!("{:?}", doc.retriever).to_lowercase(),
            title: doc.metadata.and_then(|m| m.title),
            retrieved_at: doc.retrieved_at.to_rfc3339(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(DocumentListResponse {
        documents: summaries,
        page: paginated.page,
        page_size: paginated.page_size,
        total_count: paginated.total_count,
        total_pages: paginated.total_pages,
    }))
}

/// Get a reference document by ID
#[utoipa::path(
    get,
    path = "/v1/documents/{id}",
    params(
        ("id" = String, Path, description = "Document ID (content hash)")
    ),
    responses(
        (status = 200, description = "Document retrieved successfully", body = crate::model::ReferenceDocument),
        (status = 404, description = "Document not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "documents"
)]
#[get("/v1/documents/{id}")]
pub async fn get_document(
    service: web::Data<DocumentService>,
    path: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    let id = path.into_inner();

    let doc = service.get_by_id(&id).await?;

    Ok(HttpResponse::Ok().json(doc))
}

/// Delete a reference document by ID
#[utoipa::path(
    delete,
    path = "/v1/documents/{id}",
    params(
        ("id" = String, Path, description = "Document ID (content hash)")
    ),
    responses(
        (status = 204, description = "Document deleted successfully"),
        (status = 404, description = "Document not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "documents"
)]
#[actix_web::delete("/v1/documents/{id}")]
pub async fn delete_document(
    service: web::Data<DocumentService>,
    path: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    let id = path.into_inner();

    let deleted = service.delete(&id).await?;

    if deleted {
        tracing::info!(id = %id, "Document deleted");
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(ApiError::DocumentNotFound(id))
    }
}

/// Configure document routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_documents)
        .service(get_document)
        .service(delete_document);
}
