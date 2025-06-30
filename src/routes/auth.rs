use axum::{
    extract::{Json, Extension},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Error};
use crate::utils::auth::{hash_password, verify_password};
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use std::sync::Arc;
use crate::utils::auth_middleware::AuthUser;
use thiserror::Error;

#[derive(Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Hashing error")]
    Hashing,
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Username already exists")]
    Conflict,
    #[error("Internal server error")]
    Internal,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::Database(_) | AuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            AuthError::Hashing => (StatusCode::INTERNAL_SERVER_ERROR, "Password hashing failed").into_response(),
            AuthError::Jwt(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed").into_response(),
            AuthError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            AuthError::Conflict => (StatusCode::CONFLICT, "Username already exists").into_response(),
        }
    }
}

// POST /register
pub async fn register_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<AuthPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let hashed = hash_password(&payload.password);

    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        payload.username,
        hashed,
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok(StatusCode::CREATED.into_response()),
        Err(e) => {
            if let Error::Database(db_err) = &e {
                if db_err.code() == Some("23505".into()) {
                    return Err(AuthError::Conflict);
                }
            }
            Err(AuthError::Database(e))
        }
    }
}


// create_jwt: creates json web tokens for user authorization
fn create_jwt(userid: &str, secret_key: &[u8]) -> Result<String, AuthError> {
    let expiry = Utc::now() + Duration::seconds(300);
    let claims = Claims {
        sub: userid.to_owned(),
        exp: expiry.timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key)).map_err(AuthError::Jwt)
}

// POST /login
pub async fn login_handler(
    Extension(pool): Extension<PgPool>,
    Extension(secret_key): Extension<Arc<Vec<u8>>>,
    Json(payload): Json<AuthPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let record = sqlx::query!(
        "SELECT password FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
    .await?;

    if let Some(row) = record {
        if let Some(ref hash) = row.password {
            if verify_password(&payload.password, hash) {
                let token = create_jwt(&payload.username, secret_key.as_slice())?;
                return Ok(Json(TokenResponse { token }).into_response());
            }
        }
        Err(AuthError::Unauthorized)
    } else {
        Err(AuthError::Unauthorized)
    }
}

// GET /me
pub async fn me_handler(AuthUser(user): AuthUser) -> impl IntoResponse {
    format!("Hello, {}!", user.sub)
}
