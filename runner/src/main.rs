//! SealedCodeBounty verifier runner — thin binary over the library crate.
//!
//! Trust boundary (BUILD_PLAN_v2.md §4.3): this process is meant to run
//! inside a Nitro Enclave. It is the only place where the master flag secret,
//! the buyer's environment, and the hunter's plaintext exploit coexist. Its
//! only egress is short JSON responses whose security-critical fields are
//! enclave signatures over canonical 207-byte verdict messages.

use scb_runner::{config::Config, routes, state::AppState};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    let state = Arc::new(AppState::new(cfg.clone()));
    let app = routes::router(state.clone());

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], cfg.port));
    tracing::info!(%addr, "scb-runner listening");
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            // Spawning requires an entered Tokio runtime, including at boot.
            AppState::spawn_sweeper(state);
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    Ok(())
}
