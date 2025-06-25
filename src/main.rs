use axum::{
    routing::{get, post},
    Router,
    Extension,
};
use std::{sync::Arc, env, net::SocketAddr};
use tokio::net::TcpListener;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
pub mod utils;
mod routes;
use routes::auth::{register_handler, login_handler, me_handler};

#[tokio::main]
async fn main() {
    // Load Database
    dotenv().ok();
    let jwt_secret = env::var("PRIVATE_KEY").expect("Private key must be set");
    let secret_key = Arc::new(jwt_secret.into_bytes());
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Connect Database
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    // Create routes
    let app = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/me", get(me_handler))
        // Make database and secret key available
        .layer(Extension(pool.clone()))
        .layer(Extension(secret_key.clone()));

    // Open socket amd listen
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();

    // Print auth service is running
    println!("🚀 Auth service running at http://{}", addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
