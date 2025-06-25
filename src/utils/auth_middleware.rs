use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts as RequestParts, StatusCode},
};
use axum_extra::extract::TypedHeader;
use headers::{authorization::Bearer, Authorization};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;

// Make sure this path is correct and the Claims struct is public.
use crate::routes::auth::Claims;
pub struct AuthUser(pub Claims);

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut RequestParts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let TypedHeader(auth_header) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    (
                        StatusCode::UNAUTHORIZED,
                        "Missing or invalid Authorization header".into(),
                    )
                })?;

        let token = auth_header.token();

        // Get secret key from extensions
        let secret_key = parts
            .extensions
            .get::<Arc<Vec<u8>>>()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Missing secret key".into(),
            ))?;

        // Decode and validate token
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret_key.as_slice()),
            &Validation::default(),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".into()))?;

        Ok(AuthUser(token_data.claims))
    }
}
