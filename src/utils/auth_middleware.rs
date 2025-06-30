use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts as RequestParts, StatusCode},
};
use axum_extra::extract::TypedHeader;
use headers::{authorization::Bearer, Authorization};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

// Make sure this path is correct and the Claims struct is public.
use crate::routes::auth::Claims;

#[derive(Error, Debug)]
pub enum AuthMiddlewareError {
    #[error("Missing or invalid Authorization header")]
    MissingAuthHeader,
    #[error("Missing secret key")]
    MissingSecretKey,
    #[error("Invalid token")]
    InvalidToken,
}

impl IntoResponse for AuthMiddlewareError {
    fn into_response(self) -> Response {
        match self {
            AuthMiddlewareError::MissingAuthHeader | AuthMiddlewareError::InvalidToken =>
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response(),
            AuthMiddlewareError::MissingSecretKey =>
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response(),
        }
    }
}

pub struct AuthUser(pub Claims);

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthMiddlewareError;

    async fn from_request_parts(
        parts: &mut RequestParts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let TypedHeader(auth_header) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AuthMiddlewareError::MissingAuthHeader)?;

        let token = auth_header.token();

        // Get secret key from extensions
        let secret_key = parts
            .extensions
            .get::<Arc<Vec<u8>>>()
            .ok_or(AuthMiddlewareError::MissingSecretKey)?;

        // Decode and validate token
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret_key.as_slice()),
            &Validation::default(),
        )
        .map_err(|_| AuthMiddlewareError::InvalidToken)?;

        Ok(AuthUser(token_data.claims))
    }
}
