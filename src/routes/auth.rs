use axum::{
    extract::{Json, Extension},
    http::StatusCode,
    response::{IntoResponse},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use crate::utils::auth::{hash_password, verify_password};
use rand::{RngCore, rngs::OsRng};
use jsonwebtoken::{encode, Header, EncodingKey};
#[derive(Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Serialize)]
struct Claims {
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
fn create_jwt(userid: str) -> Result<String, jsonwebtoken::errors::Error> {
    seconds_to_expiry = 300
    let secret_key = generate_secret_key() 
    let claims = Claims {
    sub: userid.to_owned(),
    exp: seconds_to_expiry
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key))
}

fn generate_secret_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
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
                        token: create_jwt(record).into(),
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
