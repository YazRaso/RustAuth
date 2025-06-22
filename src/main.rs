use axum::{
    routing::{get, post},
    Router,
    Extension,
};
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
pub mod utils;
mod routes;
use routes::auth::{register_handler, login_handler, me_handler};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    let app = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/me", get(me_handler))
        .layer(Extension(pool.clone())); // Make pool available to routes

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("🚀 Auth service running at http://{}", addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
