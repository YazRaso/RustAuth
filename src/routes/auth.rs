use axum::{
    extract::{Json, Extension},
    http::StatusCode,
    response::{IntoResponse},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::utils::auth::{hash_password, verify_password};

#[derive(Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
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

// POST /login
pub async fn login_handler(
    Extension(pool): Extension<PgPool>,
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
            // row.password is Option<String>, unwrap safely
            if let Some(ref hash) = row.password {
                if verify_password(&payload.password, hash) {
                    return Json(TokenResponse {
                        token: "fake.jwt.token".into(),
                    })
                    .into_response();
                }
            }
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}
// GET /me
pub async fn me_handler() -> &'static str {
    "User info"
}
