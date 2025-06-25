use axum::{
    extract::{Json, Extension},
    http::StatusCode,
    response::{IntoResponse},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::utils::auth::{hash_password, verify_password};
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use std::sync::Arc;
use crate::utils::auth_middleware::AuthUser;

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


// POST /register
pub async fn register_handler(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    let hashed = hash_password(&payload.password);

    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        payload.username,
        hashed,
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// create_jwt: creates json web tokens for user authorization
fn create_jwt(userid: &str, secret_key: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let expiry = Utc::now() + Duration::seconds(300);
    let claims = Claims {
        sub: userid.to_owned(),
        exp: expiry.timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key))
}

// POST /login
pub async fn login_handler(
    Extension(pool): Extension<PgPool>,
    Extension(secret_key): Extension<Arc<Vec<u8>>>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    let record = sqlx::query!(
        "SELECT password FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
    .await;

    match record {
        Ok(Some(row)) => {
            if let Some(ref hash) = row.password {
                if verify_password(&payload.password, hash) {
                    let token = create_jwt(&payload.username, secret_key.as_slice())
                        .unwrap_or_default();
                    return Json(TokenResponse { token }).into_response();
                }
            }
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

// GET /me
pub async fn me_handler(AuthUser(user): AuthUser) -> impl IntoResponse {
    format!("Hello, {}!", user.sub)
}
