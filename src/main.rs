use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
mod routes;
use routes::auth::{register_handler, login_handler, me_handler};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let app = Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/me", get(me_handler));


    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
    println!("🚀 Auth service running at http://{}", addr);
}
