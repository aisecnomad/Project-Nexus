use rmcp::{model::ServerInfo, ServerHandler, ServiceExt};

#[derive(Clone, Default)]
struct Arithmetic;

impl ServerHandler for Arithmetic {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = Arithmetic.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
