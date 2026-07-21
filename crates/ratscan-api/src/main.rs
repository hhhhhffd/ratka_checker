//! Dedicated RatScan API binary.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ratscan_api::run().await
}
