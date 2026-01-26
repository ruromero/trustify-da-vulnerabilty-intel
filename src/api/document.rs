//! REST API endpoints for reference documents

use actix_web::{HttpResponse, Responder, get, web};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

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
) -> impl Responder {
    let db_query = ListDocumentsQuery {
        page: query.page,
        page_size: query.page_size,
        retriever_type: query.retriever_type.clone(),
        domain_url: query.domain_url.clone(),
    };

    match service.list(db_query).await {
        Ok(paginated) => {
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

            HttpResponse::Ok().json(DocumentListResponse {
                documents: summaries,
                page: paginated.page,
                page_size: paginated.page_size,
                total_count: paginated.total_count,
                total_pages: paginated.total_pages,
            })
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list documents");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list documents",
                "message": e.to_string()
            }))
        }
    }
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
) -> impl Responder {
    let id = path.into_inner();

    match service.get_by_id(&id).await {
        Ok(doc) => HttpResponse::Ok().json(doc),
        Err(crate::service::document::DocumentServiceError::DbError(
            crate::db::DbError::NotFound(_),
        )) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Document not found",
            "id": id
        })),
        Err(e) => {
            tracing::error!(error = %e, id = %id, "Failed to get document");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get document",
                "message": e.to_string()
            }))
        }
    }
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
) -> impl Responder {
    let id = path.into_inner();

    match service.delete(&id).await {
        Ok(true) => {
            tracing::info!(id = %id, "Document deleted");
            HttpResponse::NoContent().finish()
        }
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Document not found",
            "id": id
        })),
        Err(e) => {
            tracing::error!(error = %e, id = %id, "Failed to delete document");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete document",
                "message": e.to_string()
            }))
        }
    }
}

/// Configure document routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_documents)
        .service(get_document)
        .service(delete_document);
}
