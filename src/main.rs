use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;

mod routes;
use routes::auth::{register_handler, login_handler, me_handler};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok(); // Load .env

    let app = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/me", get(me_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🚀 Auth service running at http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
