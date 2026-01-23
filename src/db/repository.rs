//! Repository for reference document database operations

use sqlx::PgPool;

use super::models::{
    content_type_to_string, retriever_type_to_string, ListDocumentsQuery, PaginatedDocuments,
    ReferenceDocumentRow,
};
use super::DbError;
use crate::model::ReferenceDocument;

const DEFAULT_PAGE_SIZE: u32 = 20;

/// Repository for reference document operations
#[derive(Clone)]
pub struct ReferenceDocumentRepository {
    pool: PgPool,
}

impl ReferenceDocumentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert or update a reference document
    pub async fn upsert(&self, doc: &ReferenceDocument) -> Result<(), DbError> {
        let retriever_type = retriever_type_to_string(&doc.retriever);
        let content_type = content_type_to_string(&doc.content_type);
        let metadata_json = doc
            .metadata
            .as_ref()
            .map(|m| serde_json::to_value(m).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));

        let domain_url = doc.domain_url.as_ref().map(|u| u.to_string());

        sqlx::query(
            r#"
            INSERT INTO reference_documents (
                id, retrieved_from, canonical_url, domain_url, retriever_type,
                retrieved_at, published, last_modified,
                raw_content, normalized_content, content_type, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO UPDATE SET
                retrieved_from = EXCLUDED.retrieved_from,
                canonical_url = EXCLUDED.canonical_url,
                domain_url = EXCLUDED.domain_url,
                retriever_type = EXCLUDED.retriever_type,
                retrieved_at = EXCLUDED.retrieved_at,
                published = EXCLUDED.published,
                last_modified = EXCLUDED.last_modified,
                raw_content = EXCLUDED.raw_content,
                normalized_content = EXCLUDED.normalized_content,
                content_type = EXCLUDED.content_type,
                metadata = EXCLUDED.metadata
            "#,
        )
        .bind(&doc.id)
        .bind(doc.retrieved_from.to_string())
        .bind(doc.canonical_url.to_string())
        .bind(&domain_url)
        .bind(retriever_type)
        .bind(&doc.retrieved_at)
        .bind(&doc.published)
        .bind(&doc.last_modified)
        .bind(&doc.raw_content)
        .bind(&doc.normalized_content)
        .bind(content_type)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await?;

        tracing::debug!(id = %doc.id, "Upserted reference document");
        Ok(())
    }

    /// Get a reference document by ID
    pub async fn get_by_id(&self, id: &str) -> Result<ReferenceDocument, DbError> {
        let row: ReferenceDocumentRow = sqlx::query_as(
            r#"
            SELECT * FROM reference_documents WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound(id.to_string()))?;

        row.into_domain()
            .map_err(|e| DbError::Serialization(e))
    }

    /// Check if a document exists by ID
    pub async fn exists(&self, id: &str) -> Result<bool, DbError> {
        let result: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT 1 FROM reference_documents WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.is_some())
    }

    /// Delete a reference document by ID
    /// Returns true if the document was deleted, false if it didn't exist
    pub async fn delete(&self, id: &str) -> Result<bool, DbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM reference_documents WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            tracing::debug!(id = %id, "Deleted reference document");
        }

        Ok(deleted)
    }

    /// List reference documents with pagination and filters
    pub async fn list(&self, query: ListDocumentsQuery) -> Result<PaginatedDocuments, DbError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(DEFAULT_PAGE_SIZE).min(100);
        let offset = (page - 1) * page_size;

        // Build dynamic query
        let mut conditions = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(ref rt) = query.retriever_type {
            params.push(rt.clone());
            conditions.push(format!("retriever_type = ${}", params.len()));
        }

        if let Some(ref du) = query.domain_url {
            params.push(du.clone());
            conditions.push(format!("domain_url = ${}", params.len()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        // Get total count
        let count_query = format!(
            "SELECT COUNT(*) as count FROM reference_documents {}",
            where_clause
        );

        let total_count: i64 = {
            let mut q = sqlx::query_scalar(&count_query);
            for param in &params {
                q = q.bind(param);
            }
            q.fetch_one(&self.pool).await?
        };

        // Get documents
        let select_query = format!(
            r#"
            SELECT * FROM reference_documents 
            {}
            ORDER BY created_at DESC
            LIMIT {} OFFSET {}
            "#,
            where_clause, page_size, offset
        );

        let rows: Vec<ReferenceDocumentRow> = {
            let mut q = sqlx::query_as(&select_query);
            for param in &params {
                q = q.bind(param);
            }
            q.fetch_all(&self.pool).await?
        };

        let documents: Vec<ReferenceDocument> = rows
            .into_iter()
            .filter_map(|row| row.into_domain().ok())
            .collect();

        let total_pages = ((total_count as f64) / (page_size as f64)).ceil() as u32;

        Ok(PaginatedDocuments {
            documents,
            page,
            page_size,
            total_count,
            total_pages,
        })
    }
}
