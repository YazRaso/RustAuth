use axum::{Json, extract::Extension};
use serde::{Deserialize, Serialize};
use axum::http::StatusCode;

#[derive(Deserialize)]
pub struct AuthPayload {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

// POST /register
pub async fn register_handler(Json(payload): Json<AuthPayload>) -> StatusCode {
    println!("Register user: {}", payload.email);
    StatusCode::CREATED
}

// POST /login
pub async fn login_handler(Json(payload): Json<AuthPayload>) -> Json<TokenResponse> {
    println!("Login user: {}", payload.email);
    // TEMP: Return dummy token
    Json(TokenResponse {
        token: "fake.jwt.token".into(),
    })
}

// GET /me
pub async fn me_handler() -> &'static str {
    "User info"
}
